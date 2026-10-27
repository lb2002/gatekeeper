"""Gatekeeper live monitor on Modal.

Deploy:  uv run modal deploy modal_app/app.py
Test:    uv run modal run modal_app/app.py::poll_once

Package archives are only ever downloaded and read (in memory) inside these containers.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import modal

app = modal.App("gatekeeper")

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("httpx>=0.27", "pydantic>=2.7", "typer>=0.12", "rich>=13.7")
    .add_local_python_source("gatekeeper")
)
volume = modal.Volume.from_name("gatekeeper-data", create_if_missing=True)
state = modal.Dict.from_name("gatekeeper-state", create_if_missing=True)

DATA = Path("/data")
RUN_BUDGET_S = 95  # stay well inside the 2-minute schedule
MAX_CHANGES_PER_RUN = 4000


def _append_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _run_poll() -> dict:
    from gatekeeper.monitor import process_names
    from gatekeeper.npm import feed
    from gatekeeper.popular import load_popular

    started = time.monotonic()
    now = datetime.now(timezone.utc)
    popular = load_popular(DATA / "popular.txt")
    stats = {"changes": 0, "versions": 0, "scanned": 0, "flagged": 0, "errors": 0}
    with feed.make_client() as client:
        head = feed.current_seq(client)
        since = state.get("seq", None)
        if since is None:
            since = max(0, head - 1000)  # first run: start shortly before the head
        names: dict[str, None] = {}
        while since < head and len(names) < MAX_CHANGES_PER_RUN and time.monotonic() - started < RUN_BUDGET_S / 3:
            batch, nxt = feed.fetch_changes(client, since, limit=1000)
            if not batch or nxt <= since:
                break
            for ch in batch:
                if not ch.deleted:
                    names.setdefault(ch.name)
            since = nxt
        stats["changes"] = len(names)
        seen_keys = set(state.get("seen_recent", []))
        last = state.get("last_run", None)
        window = timedelta(minutes=30)
        if last and last.get("at"):
            window = min(timedelta(hours=6), now - datetime.fromisoformat(last["at"]) + timedelta(minutes=10))
        records = process_names(client, list(names), popular, seen_keys, now=now, window=window)

    run_id = f"{now:%H%M%S}-{uuid.uuid4().hex[:6]}"
    day = f"{now:%Y-%m-%d}"
    rows = [r.to_json() for r in records]
    _append_jsonl(DATA / "events" / day / f"{run_id}.jsonl", rows)
    flagged = [r for r in rows if r["flagged"]]
    if flagged:
        _append_jsonl(DATA / "flagged" / day / f"{run_id}.jsonl", flagged)
    volume.commit()

    stats["versions"] = len(records)
    stats["scanned"] = sum(r.scanned for r in records)
    stats["flagged"] = len(flagged)
    stats["errors"] = sum(1 for r in records if r.error)
    # remember recently seen versions (bounded) and the feed position
    recent = (list(seen_keys) + [r.key for r in records])[-20000:]
    state["seen_recent"] = recent
    state["seq"] = since
    state["last_run"] = {"at": now.isoformat(), "head": head, "seq": since, **stats}
    stats["lag_changes"] = head - since
    stats["seconds"] = round(time.monotonic() - started, 1)
    return stats


@app.function(image=image, volumes={str(DATA): volume}, schedule=modal.Period(minutes=2), timeout=115, cpu=0.5, memory=1024)
def poll() -> dict:
    stats = _run_poll()
    print(json.dumps(stats))
    return stats


@app.function(image=image, volumes={str(DATA): volume}, timeout=115, cpu=0.5, memory=1024)
def poll_once() -> dict:
    """Manual single run for testing (same code path as the cron)."""
    stats = _run_poll()
    print(json.dumps(stats))
    return stats


@app.local_entrypoint()
def main() -> None:
    print(poll_once.remote())
