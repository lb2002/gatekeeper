"""Realistic negatives from the past npm feed: versions published a week ago, scanned exactly like the
live monitor would have scanned them, then labelled with a week of hindsight from OSV.

    uv run modal run modal_app/history.py::collect

Versions whose package has an OSV MAL-* entry are labelled malicious; all others are presumed benign
(npm malware is rare and mostly reported within days). Archives are read in memory, never run.
"""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import modal

app = modal.App("gatekeeper-history")
image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("httpx>=0.27", "pydantic>=2.7")
    .add_local_python_source("gatekeeper")
)
data_volume = modal.Volume.from_name("gatekeeper-data", create_if_missing=True)
DATA = Path("/data")
CHANGES_PER_DAY = 360_000  # measured on the live monitor (~250 changes a minute)


def _osv_malicious_names(client, names: list[str]) -> set[str]:
    bad: set[str] = set()
    for i in range(0, len(names), 1000):
        chunk = names[i : i + 1000]
        resp = client.post("https://api.osv.dev/v1/querybatch",
                           json={"queries": [{"package": {"name": n, "ecosystem": "npm"}} for n in chunk]})
        resp.raise_for_status()
        for name, res in zip(chunk, resp.json().get("results", [])):
            if any(str(v.get("id", "")).startswith("MAL-") for v in res.get("vulns") or []):
                bad.add(name)
    return bad


@app.function(image=image, volumes={str(DATA): data_volume}, timeout=3 * 3600, cpu=2.0, memory=4096)
def collect(start: str = "2026-10-19", end: str = "2026-10-26", chunks: int = 80, chunk_size: int = 1000,
            max_samples: int = 15000, budget_s: int = 2 * 3600) -> dict:
    from gatekeeper.monitor import process_version
    from gatekeeper.npm import feed, packument
    from gatekeeper.popular import load_popular

    started = time.monotonic()
    t0 = datetime.fromisoformat(start).replace(tzinfo=timezone.utc)
    t1 = datetime.fromisoformat(end).replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    popular = load_popular(DATA / "popular.txt")
    client = feed.make_client()
    head = feed.current_seq(client)
    # sequence range that roughly covers [start, end]; versions are filtered by their real publish time
    lo = head - int((now - t0).total_seconds() / 86400 * CHANGES_PER_DAY)
    hi = head - int((now - t1).total_seconds() / 86400 * CHANGES_PER_DAY)
    step = max(chunk_size, (hi - lo) // chunks)
    names: dict[str, None] = {}
    for seq in range(lo, hi, step):
        batch, _ = feed.fetch_changes(client, seq, limit=chunk_size)
        for ch in batch:
            if not ch.deleted:
                names.setdefault(ch.name)
    seen: set[str] = set()

    def one(name: str) -> list[dict]:
        if time.monotonic() - started > budget_s:
            return []
        try:
            doc = packument.fetch_packument(client, name) or {}
        except Exception:
            return []
        out = []
        ordered = packument.versions_by_time(doc)
        for ver, ts in ordered:
            if not (t0 <= ts < t1) or f"{name}@{ver}" in seen:
                continue
            seen.add(f"{name}@{ver}")
            info = packument.version_info(doc, ver, ordered)
            rec = process_version(client, info, popular, ts + timedelta(minutes=5))  # as the monitor saw it then
            if rec.scanned and rec.bundle:
                out.append({k: getattr(rec, k) for k in ("name", "version", "published_at", "content_score", "rules",
                                                           "bundle", "excerpts", "flagged")})
        return out[:3]  # at most 3 versions per package, so busy monorepos do not dominate

    rows: list[dict] = []
    with ThreadPoolExecutor(max_workers=24) as pool:
        for recs in pool.map(one, list(names)):
            rows.extend(recs)
            if len(rows) >= max_samples:
                break
    rows = rows[:max_samples]
    bad = _osv_malicious_names(client, sorted({r["name"] for r in rows}))
    for r in rows:
        r["label"] = "malicious" if r["name"] in bad else "benign"
        r["kind"] = "live_history"
        r["split"] = "train"
        r["cluster"] = r["name"]
    out = DATA / "datasets" / "live_history.jsonl"
    out.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    data_volume.commit()
    stats = {"seq_range": [lo, hi], "names": len(names), "rows": len(rows), "osv_malicious": sum(r["label"] == "malicious" for r in rows),
             "rule_flagged": sum(bool(r["flagged"]) for r in rows), "seconds": round(time.monotonic() - started)}
    print(json.dumps(stats))
    return stats
