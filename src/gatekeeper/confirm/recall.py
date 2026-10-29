"""Live recall: of the npm packages OpenSSF/OSV reported as malicious since the monitor started,
how many did we flag, how fast, and why did we miss the others."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

import httpx

from gatekeeper.confirm import parse_ts
from gatekeeper.confirm.osv import first_public
from gatekeeper.confirm.tracker import flag_lead_minutes, publish_to_flag_minutes

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


def classify(vuln: dict, seen: dict[str, list[dict]], flags: dict[str, str], start: datetime) -> list[Outcome]:
    """One outcome per affected package.
    seen: name -> event rows {version, published_at, seen_at, scanned, flagged, content_score, meta_score, error}
    flags: "name@version" -> flagged_at (every flag, from any stage)."""
    public = first_public(vuln) or vuln.get("published")
    out = []
    for name, versions in _targets(vuln):
        rows = [r for r in seen.get(name, []) if not versions or r["version"] in versions]
        keys = [f"{name}@{v}" for v in versions] if versions else [k for k in flags if k.rpartition("@")[0] == name]
        hit = sorted((flags[k], k) for k in keys if k in flags)
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
            o.detail = ("error: " + str(r["error"])[:80]) if r.get("error") else \
                f"scanned={bool(r.get('scanned'))} meta={r.get('meta_score')} content={r.get('content_score')}"
        else:
            # never in our feed window: published before the monitor started, or a coverage gap
            pub = parse_ts(vuln.get("published"))
            o.status = "before_monitor" if pub is not None and pub < start else "not_seen"
            o.detail = f"osv published {vuln.get('published')}"
        out.append(o)
    return out


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
