"""Gatekeeper live monitor on Modal.

Deploy:  uv run modal deploy modal_app/app.py
Test:    uv run modal run modal_app/app.py::poll_once

Package archives are only ever downloaded and read (in memory) inside these containers.

No `from __future__ import annotations` here: FastAPI must resolve the request models defined
inside `api()` at runtime.
"""

import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import modal

app = modal.App("gatekeeper")

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("httpx>=0.27", "pydantic>=2.7", "typer>=0.12", "rich>=13.7", "fastapi[standard]>=0.115")
    .add_local_python_source("gatekeeper")
)
volume = modal.Volume.from_name("gatekeeper-data", create_if_missing=True)
state = modal.Dict.from_name("gatekeeper-state", create_if_missing=True)
queue = modal.Dict.from_name("gatekeeper-queue", create_if_missing=True)  # key "name@version" -> item
worker_secret = modal.Secret.from_name("gatekeeper-worker")  # GK_WORKER_TOKEN
QUEUE_FIELDS = ("name", "version", "published_at", "seen_at", "meta_score", "meta_reasons", "content_score", "rules", "priority", "bundle", "bundle_sha256", "excerpts")

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
        stats["queued"] = _enqueue(flagged)
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


QUEUE_TTL = timedelta(days=7)


def _enqueue(rows: list[dict]) -> int:
    added = 0
    for r in rows:
        key = f"{r['name']}@{r['version']}"
        if key in queue:
            continue
        item = {k: r.get(k) for k in QUEUE_FIELDS}
        item.update(status="pending", leased_until=0.0, verdicts={})
        queue[key] = item
        added += 1
    return added


@app.function(image=image, volumes={str(DATA): volume}, timeout=300, cpu=0.25, memory=512)
def backfill_queue() -> dict:
    """Load flagged records from the volume into the queue (recovery and first deployment)."""
    volume.reload()
    added = total = 0
    for path in sorted((DATA / "flagged").glob("*/*.jsonl")):
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        total += len(rows)
        added += _enqueue(rows)
    print(json.dumps({"flagged_records": total, "added": added}))
    return {"flagged_records": total, "added": added}


@app.function(image=image, volumes={str(DATA): volume}, schedule=modal.Period(hours=1), timeout=900, cpu=0.25, memory=512)
def confirm() -> dict:
    """Hourly: check every queued flag against OSV, GitHub malware advisories and npm takedowns."""
    from gatekeeper.confirm.batch import confirm_many
    from gatekeeper.npm import feed

    now = datetime.now(timezone.utc)
    items = dict(queue.items())
    stale = [k for k, it in items.items() if datetime.fromisoformat(it["seen_at"]) < now - QUEUE_TTL]
    for k in stale:
        queue.pop(k, None)
        items.pop(k, None)
    pending = {k: it for k, it in items.items() if not (it.get("confirmation") or {}).get("confirmed")}
    since = (now - QUEUE_TTL).isoformat()
    with feed.make_client() as client:
        results, gh_error = confirm_many(client, [(it["name"], it["version"]) for it in pending.values()], since, now=now)
    newly = 0
    rows = []
    for (key, item), conf in zip(pending.items(), results):
        row = conf.as_dict() | {"key": key, "flagged_at": item["seen_at"], "published_at": item["published_at"]}
        rows.append(row)
        if conf.confirmed:
            newly += 1
        item["confirmation"] = {k: row[k] for k in ("confirmed", "earliest_public", "osv_ids", "ghsa_ids", "npm_takedown_at", "checked_at")}
        queue[key] = item
    _append_jsonl(DATA / "confirmations" / f"{now:%Y-%m-%d}.jsonl", rows)
    volume.commit()
    stats = {"checked": len(results), "newly_confirmed": newly, "expired": len(stale), "github_error": gh_error}
    state["last_confirm"] = {"at": now.isoformat(), **stats}
    print(json.dumps(stats))
    return stats


SPARK_DAILY_CAP_USD = 10.0
SPARK_TOTAL_CAP_USD = 130.0
SPARK_PER_RUN = 20
SPARK_SECRET = modal.Secret.from_name("meta-api", required_keys=["MODEL_API_KEY"])


def _spark_candidates(items: dict, now: datetime) -> list[str]:
    """Second opinions on local malicious/suspicious verdicts first, then high-priority items the
    laptop has not reached for 30 minutes."""
    first, second = [], []
    for key, it in items.items():
        verdicts = it.get("verdicts", {})
        if "spark" in verdicts:
            continue
        local = (verdicts.get("glimmer-local") or {}).get("verdict")
        if local in ("malicious", "suspicious"):
            first.append((it["priority"], key))
        elif not verdicts and datetime.fromisoformat(it["seen_at"]) < now - timedelta(minutes=30):
            second.append((it["priority"], key))
    return [k for _, k in sorted(first, reverse=True)] + [k for _, k in sorted(second, reverse=True)]


@app.function(image=image, volumes={str(DATA): volume}, secrets=[SPARK_SECRET], schedule=modal.Period(minutes=5), timeout=280, cpu=0.25, memory=512)
def spark() -> dict:
    """Classify queued bundles with Muse Spark (Meta Model API) under hard spending caps.
    Disabled until state['spark_enabled'] is True."""
    from gatekeeper.evidence.bundle import RenderedBundle
    from gatekeeper.models.backends import classify_spark

    if not state.get("spark_enabled", False):
        return {"enabled": False}
    now = datetime.now(timezone.utc)
    day = f"{now:%Y-%m-%d}"
    spend = state.get("spark_spend", {"total": 0.0, "days": {}})
    done = 0
    for key in _spark_candidates(dict(queue.items()), now)[:SPARK_PER_RUN]:
        if spend["total"] >= SPARK_TOTAL_CAP_USD or spend["days"].get(day, 0.0) >= SPARK_DAILY_CAP_USD:
            break
        item = queue.get(key, None)
        if item is None:
            continue
        try:
            result = classify_spark(RenderedBundle.from_record(item))
        except Exception as exc:  # API errors (restriction, rate limit) must not crash the cron
            print(f"spark error on {key}: {type(exc).__name__}: {exc}"[:300])
            break
        spend["total"] += result.cost_usd
        spend["days"][day] = spend["days"].get(day, 0.0) + result.cost_usd
        v = result.verdict
        row = {
            "key": key, "backend": "spark", "model": result.model,
            "verdict": v.model_dump(mode="json") if v else None, "errors": result.errors,
            "latency_s": result.latency_s, "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens, "cost_usd": result.cost_usd, "received_at": now.isoformat(),
        }
        _append_jsonl(DATA / "verdicts" / day / "spark.jsonl", [row])
        item.setdefault("verdicts", {})["spark"] = {
            "verdict": v.verdict.value if v else None, "confidence": v.confidence if v else None,
            "at": now.isoformat(), "errors": result.errors[:3], "full": row["verdict"],
        }
        queue[key] = item
        done += 1
    state["spark_spend"] = spend
    volume.commit()
    stats = {"enabled": True, "classified": done, "spend_today": round(spend["days"].get(day, 0.0), 4), "spend_total": round(spend["total"], 4)}
    print(json.dumps(stats))
    return stats


@app.function(image=image, timeout=60)
def set_spark(enabled: bool) -> dict:
    state["spark_enabled"] = bool(enabled)
    return {"spark_enabled": state["spark_enabled"], "spend": state.get("spark_spend", None)}


LEASE_S = 15 * 60

from pydantic import BaseModel  # noqa: E402  (request models must live at module level for FastAPI)


class VerdictIn(BaseModel):
    key: str
    backend: str
    model: str
    verdict: dict | None = None
    errors: list[str] = []
    latency_s: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


class ReviewIn(BaseModel):
    key: str
    decision: str  # malicious | benign | unsure
    note: str = ""


@app.function(image=image, volumes={str(DATA): volume}, secrets=[worker_secret], cpu=0.25, memory=512)
@modal.concurrent(max_inputs=20)
@modal.asgi_app()
def api():
    """Worker API: laptop workers lease flagged bundles and post verdicts back (bearer token)."""
    import os

    from fastapi import Depends, FastAPI, Header, HTTPException

    web = FastAPI(title="gatekeeper")
    token = os.environ["GK_WORKER_TOKEN"]

    def auth(authorization: str = Header(default="")) -> None:
        if authorization != f"Bearer {token}":
            raise HTTPException(status_code=401, detail="unauthorized")

    @web.get("/status", dependencies=[Depends(auth)])
    def status() -> dict:
        counts: dict[str, int] = {}
        confirmed = 0
        for item in queue.values():
            counts[item["status"]] = counts.get(item["status"], 0) + 1
            confirmed += bool((item.get("confirmation") or {}).get("confirmed"))
        return {
            "last_run": state.get("last_run", None),
            "last_confirm": state.get("last_confirm", None),
            "queue": counts,
            "confirmed": confirmed,
            "spark_enabled": state.get("spark_enabled", False),
            "spark_spend": state.get("spark_spend", None),
        }

    @web.get("/work", dependencies=[Depends(auth)])
    def work(backend: str = "glimmer-local") -> dict:
        now = time.time()
        best_key, best = None, None
        for key, item in queue.items():
            if backend in item.get("verdicts", {}):
                continue
            if item["status"] == "leased" and item.get("leased_until", 0) > now:
                continue
            if best is None or item["priority"] > best["priority"]:
                best_key, best = key, item
        if best is None:
            return {"key": None}
        best["status"] = "leased"
        best["leased_until"] = now + LEASE_S
        queue[best_key] = best
        return {"key": best_key, **{k: best[k] for k in QUEUE_FIELDS}}

    @web.get("/items", dependencies=[Depends(auth)])
    def items(limit: int = 50) -> list[dict]:
        rows = []
        for key, it in queue.items():
            rows.append({
                "key": key,
                "priority": it["priority"],
                "published_at": it.get("published_at"),
                "seen_at": it.get("seen_at"),
                "rules": it.get("rules"),
                "meta_reasons": it.get("meta_reasons"),
                "verdicts": it.get("verdicts", {}),
                "confirmation": it.get("confirmation"),
                "review": it.get("review"),
            })
        rows.sort(key=lambda r: r["priority"], reverse=True)
        return rows[:limit]

    @web.get("/item", dependencies=[Depends(auth)])
    def item(key: str) -> dict:
        it = queue.get(key, None)
        if it is None:
            raise HTTPException(status_code=404, detail="unknown key")
        return {"key": key, **it}

    @web.post("/review", dependencies=[Depends(auth)])
    def review(r: ReviewIn) -> dict:
        now = datetime.now(timezone.utc)
        it = queue.get(r.key, None)
        if it is None:
            raise HTTPException(status_code=404, detail="unknown key")
        it["review"] = {"decision": r.decision, "note": r.note, "at": now.isoformat()}
        queue[r.key] = it
        _append_jsonl(DATA / "reviews" / f"{now:%Y-%m-%d}.jsonl", [{"key": r.key, **it["review"]}])
        volume.commit()
        return {"ok": True}

    @web.post("/verdict", dependencies=[Depends(auth)])
    def verdict(v: VerdictIn) -> dict:
        now = datetime.now(timezone.utc)
        row = v.model_dump() | {"received_at": now.isoformat()}
        _append_jsonl(DATA / "verdicts" / f"{now:%Y-%m-%d}" / f"{v.backend}.jsonl", [row])
        volume.commit()
        item = queue.get(v.key, None)
        if item is not None:
            item.setdefault("verdicts", {})[v.backend] = {
                "verdict": (v.verdict or {}).get("verdict"),
                "confidence": (v.verdict or {}).get("confidence"),
                "at": now.isoformat(),
                "errors": v.errors[:3],
                "full": v.verdict,
            }
            item["status"] = "done" if v.verdict else "pending"
            item["leased_until"] = 0.0
            queue[v.key] = item
        return {"ok": True}

    return web


@app.local_entrypoint()
def main() -> None:
    print(poll_once.remote())
