"""Live recall: of the npm packages OpenSSF/OSV reported as malicious since the monitor started,
how many did we flag, how fast, and why did we miss the others."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

import httpx

from gatekeeper.confirm import parse_ts
from gatekeeper.confirm.osv import first_public
from gatekeeper.confirm.tracker import flag_lead_minutes, publish_to_flag_minutes
from gatekeeper.npm.packument import is_placeholder_version, packument_url

MODIFIED_CSV = "https://osv-vulnerabilities.storage.googleapis.com/npm/modified_id.csv"
ENTRY_URL = "https://osv-vulnerabilities.storage.googleapis.com/npm/{id}.json"


def recent_mal_ids(csv_text: str, since: datetime) -> list[str]:
    """MAL ids modified at or after `since`. The file is sorted newest first, so reading stops at the first older line."""
    ids = []
    for line in csv_text.splitlines():
        ts, _, vid = line.strip().partition(",")
        when = parse_ts(ts)
        if when is None:
            continue
        if when < since:
            break
        if vid.startswith("MAL-"):
            ids.append(vid)
    return ids


def fetch_recent(client: httpx.Client, since: datetime) -> list[dict]:
    """MAL entries that became public (OSV import) at or after `since`. Withdrawn entries are dropped."""
    out = []
    with client.stream("GET", MODIFIED_CSV) as resp:  # the full file is large; only its head is needed
        resp.raise_for_status()
        head = []
        for line in resp.iter_lines():
            head.append(line)
            when = parse_ts(line.partition(",")[0])
            if when is not None and when < since:
                break
    for vid in recent_mal_ids("\n".join(head), since):
        r = client.get(ENTRY_URL.format(id=vid))
        if r.status_code != 200:
            continue
        vuln = r.json()
        public = parse_ts(first_public(vuln) or vuln.get("published"))
        if not vuln.get("withdrawn") and public is not None and public >= since:
            out.append(vuln)
    return out


def fetch_times(names: list[str], workers: int = 16) -> dict[str, dict]:
    """npm `time` objects (they keep the publish times of removed versions). Missing names map to {}."""
    from concurrent.futures import ThreadPoolExecutor

    with httpx.Client(timeout=20, follow_redirects=True) as client:
        def one(name: str) -> dict:
            try:
                r = client.get(packument_url(name))  # the abbreviated format has no `time`
                return (r.json().get("time") or {}) if r.status_code == 200 else {}
            except (httpx.HTTPError, ValueError):
                return {}

        with ThreadPoolExecutor(workers) as ex:
            return dict(zip(names, ex.map(one, names)))


def _real_publish_times(versions: list[str], times: dict) -> list[datetime]:
    real = [v for v in versions if not is_placeholder_version(v)]
    real = real or [v for v in times if v not in ("created", "modified", "unpublished") and not is_placeholder_version(v)]
    return [t for t in (parse_ts(times.get(v)) if isinstance(times.get(v), str) else None for v in real) if t]


@dataclass
class Outcome:
    id: str
    name: str
    status: str  # flagged | missed | not_seen | before_monitor
    versions: list[str]
    first_public: str | None
    published_at: str | None = None
    flagged_at: str | None = None
    publish_to_flag_min: float | None = None
    lead_over_osv_min: float | None = None
    detail: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _targets(vuln: dict) -> list[tuple[str, list[str]]]:
    out = []
    for a in vuln.get("affected") or []:
        pkg = a.get("package") or {}
        if str(pkg.get("ecosystem", "")).lower() == "npm" and pkg.get("name"):
            out.append((pkg["name"], list(a.get("versions") or [])))
    return out


def _seen_detail(r: dict) -> str:
    meta, content = r.get("meta_score") or 0, r.get("content_score") or 0
    if not r.get("scanned"):
        return f"metadata only, score {meta}: archive not downloaded"
    return f"archive scanned, score {meta + content} (metadata {meta}, code {content}); not sent to a model"


def classify(vuln: dict, seen: dict[str, list[dict]], flags: dict[str, str], start: datetime,
             queued: dict[str, str] | None = None, npm_times: dict[str, dict] | None = None,
             read_later: set[str] | None = None) -> list[Outcome]:
    """One outcome per affected package.
    seen: name -> event rows {version, published_at, seen_at, scanned, flagged, content_score, meta_score, error}
    flags: "name@version" -> flagged_at, detections only (a model said malicious or suspicious).
    queued: every key that reached the models, to tell "judged benign" apart from "never queued".
    npm_times: name -> npm `time`, to date versions the monitor never saw.
    read_later: keys the sweep read after the fact; if that was after the public report, it detected nothing.
    Versions npm itself published (`0.0.0-stage`, `0.0.1-security`, written when it takes a package down)
    are ignored: seeing only those means the malware itself came out before we looked."""
    queued = queued or {}
    npm_times = npm_times or {}
    public = first_public(vuln) or vuln.get("published")
    out = []
    for name, versions in _targets(vuln):
        rows = [r for r in seen.get(name, []) if (not versions or r["version"] in versions)
                and not is_placeholder_version(r["version"])]
        keys = [f"{name}@{v}" for v in versions] if versions else [k for k in flags if k.rpartition("@")[0] == name]
        keys = [k for k in keys if not is_placeholder_version(k.rpartition("@")[2])]
        hit = sorted((flags[k], k) for k in keys if k in flags
                     and not (k in (read_later or ()) and (flag_lead_minutes(flags[k], public) or 0) <= 0))
        o = Outcome(vuln["id"], name, "", versions, public)
        if rows:
            o.published_at = min((r.get("published_at") for r in rows if r.get("published_at")), default=None)
        if hit:
            o.status = "flagged"
            o.flagged_at = hit[0][0]
            version = hit[0][1].rpartition("@")[2]
            pub = next((r.get("published_at") for r in rows if r["version"] == version), None) or o.published_at
            o.publish_to_flag_min = publish_to_flag_minutes(pub, o.flagged_at)
            o.lead_over_osv_min = flag_lead_minutes(o.flagged_at, public)
        elif rows:
            o.status = "missed"
            r = rows[0]
            q = [k for k in queued if (k in keys if versions else k.rpartition("@")[0] == name)]
            o.detail = "queued, but every model said benign" if q else ("error: " + str(r["error"])[:80]) if r.get("error") else \
                _seen_detail(r)
        else:
            # never in our feed window: published before the monitor started, or a coverage gap
            pubs = _real_publish_times(versions, npm_times.get(name) or {})
            if pubs:
                o.status = "before_monitor" if max(pubs) < start else "not_seen"
                o.published_at = max(pubs).isoformat()
                o.detail = f"npm published {o.published_at[:16]}"
            else:  # removed without a trace on npm: OSV's own (often backdated) date is all there is
                pub = parse_ts(vuln.get("published"))
                o.status = "before_monitor" if pub is not None and pub < start else "not_seen"
                o.detail = f"osv published {vuln.get('published')}"
        out.append(o)
    return out


def published_since(outcomes: list[Outcome], when: datetime) -> list[Outcome]:
    """The malware that came out at or after `when`: the only part a change to the pipeline can be judged on."""
    return [o for o in outcomes if (ts := parse_ts(o.published_at)) is not None and ts >= when]


def summarize(outcomes: list[Outcome]) -> dict:
    by = {s: [o for o in outcomes if o.status == s] for s in ("flagged", "missed", "not_seen", "before_monitor")}
    in_scope = len(by["flagged"]) + len(by["missed"]) + len(by["not_seen"])
    leads = sorted(o.lead_over_osv_min for o in by["flagged"] if o.lead_over_osv_min is not None)
    p2f = sorted(o.publish_to_flag_min for o in by["flagged"] if o.publish_to_flag_min is not None)

    def median(xs):
        return None if not xs else (xs[len(xs) // 2] if len(xs) % 2 else (xs[len(xs) // 2 - 1] + xs[len(xs) // 2]) / 2)

    return {
        "in_scope": in_scope,
        "flagged": len(by["flagged"]),
        "missed": len(by["missed"]),
        "not_seen": len(by["not_seen"]),
        "before_monitor": len(by["before_monitor"]),
        "recall": round(len(by["flagged"]) / in_scope, 3) if in_scope else None,
        "flagged_before_osv": sum(1 for x in leads if x > 0),
        "median_lead_over_osv_min": median([x for x in leads if x > 0]),
        "median_publish_to_flag_min": median(p2f),
    }
