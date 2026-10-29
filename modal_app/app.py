"""Gatekeeper live monitor on Modal.

Deploy:  uv run modal deploy modal_app/app.py
Test:    uv run modal run modal_app/app.py::poll_once

Package archives are only ever downloaded and read (in memory) inside these containers.

No `from __future__ import annotations` here: FastAPI must resolve the request models defined
inside `api()` at runtime.
"""

import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import modal

app = modal.App("gatekeeper")

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("httpx>=0.27", "pydantic>=2.7", "typer>=0.12", "rich>=13.7", "fastapi[standard]>=0.115", "scikit-learn==1.5.2")
    .add_local_python_source("gatekeeper")
)
lg_image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("torch==2.5.1", "transformers==4.46.3", "peft==0.13.2", "accelerate==1.1.1", "httpx>=0.27", "pydantic>=2.7")
    .env({"HF_HOME": "/models/hf"})
    .add_local_python_source("gatekeeper")
)
volume = modal.Volume.from_name("gatekeeper-data", create_if_missing=True)
model_volume = modal.Volume.from_name("gatekeeper-models", create_if_missing=True)
state = modal.Dict.from_name("gatekeeper-state", create_if_missing=True)
queue = modal.Dict.from_name("gatekeeper-queue", create_if_missing=True)  # key "name@version" -> item
worker_secret = modal.Secret.from_name("gatekeeper-worker")  # GK_WORKER_TOKEN
NTFY_SECRET = modal.Secret.from_name("ntfy", required_keys=["NTFY_TOPIC"])  # reviewer push notifications
QUEUE_FIELDS = ("name", "version", "published_at", "seen_at", "meta_score", "meta_reasons", "content_score", "rules", "priority", "bundle", "bundle_sha256", "excerpts", "fast_risk", "lg_risk", "low_priority")

DATA = Path("/data")
# Time budget of one poll run (the function is killed at 115 s): every network step has a short timeout
# and a latest start time, and whatever does not fit is picked up by the next run two minutes later.
FEED_BUDGET_S = 25  # reading the change feed
PROCESS_BUDGET_S = 65  # after this, unfinished names are deferred to the next run
LEDGER_START_BY_S = 55  # the ledger flush (OTS + 2 GitHub writes) can take up to ~55 s
HTTP_TIMEOUT_S = 15
MAX_CHANGES_PER_RUN = 4000
MAX_PENDING = 8000
LIVE_SAMPLE_CAP = 40_000
MAX_WINDOW = timedelta(hours=24)
SEEN_MAX = 60000


def _append_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


_FAST: dict = {}


def _fast_scorer():
    """The fast first-stage classifier trained by modal_app/fastclf.py, or None if not trained yet."""
    import pickle
    import threading

    from gatekeeper.fastclf import clean_text

    path = DATA / "models" / "fastclf.pkl"
    if not path.exists():
        return None
    if _FAST.get("mtime") != path.stat().st_mtime:
        _FAST.update(pickle.loads(path.read_bytes()), mtime=path.stat().st_mtime, lock=threading.Lock())
    model, threshold, lock = _FAST["model"], _FAST["threshold"], _FAST["lock"]

    def score(name: str, version: str, text: str, rules: list[str]) -> tuple[float, bool]:
        with lock:
            risk = float(model.predict_proba([clean_text(text, name, version, rules)])[0, 1])
        return round(risk, 4), risk >= threshold

    return score


def _run_poll() -> dict:
    import httpx

    from gatekeeper.monitor import FLAG_CONTENT_THRESHOLD, FLAG_TOTAL_THRESHOLD, process_names
    from gatekeeper.npm import feed
    from gatekeeper.popular import load_popular

    started = time.monotonic()
    now = datetime.now(timezone.utc)
    popular = load_popular(DATA / "popular.txt")
    stats = {"changes": 0, "versions": 0, "scanned": 0, "flagged": 0, "errors": 0}
    with feed.make_client(timeout=HTTP_TIMEOUT_S) as client:
        head = feed.current_seq(client)
        since = state.get("seq", None)
        if since is None:
            since = max(0, head - 1000)  # first run: start shortly before the head
        pending = state.get("pending_names", [])
        names: dict[str, None] = {}
        # read less of the feed while a backlog is pending, so the backlog cannot grow without bound
        while since < head and len(names) + len(pending) < MAX_CHANGES_PER_RUN and time.monotonic() - started < FEED_BUDGET_S:
            try:
                batch, nxt = feed.fetch_changes(client, since, limit=1000, deadline=started + FEED_BUDGET_S)
            except (httpx.HTTPError, TimeoutError) as exc:  # keep what was read; the next run continues from `since`
                stats["feed_error"] = type(exc).__name__
                break
            if not batch or nxt <= since:
                break
            for ch in batch:
                if not ch.deleted:
                    names.setdefault(ch.name)
            since = nxt
        stats["changes"] = len(names)
        seen_list = state.get("seen_recent", [])
        seen_keys = set(seen_list)
        # Every change after the last run that reached the head with no backlog is unprocessed, so
        # the window must reach back to then (plus slack for publish-to-feed delay). Basing it on
        # the last run alone would skip versions whenever the feed lags or names are deferred.
        caught_up = state.get("caught_up_at", None) or (state.get("last_run") or {}).get("at")
        window = timedelta(minutes=30)
        if caught_up:
            window = now - datetime.fromisoformat(caught_up) + timedelta(minutes=10)
        if window > MAX_WINDOW:
            print(f"WARNING: monitor fell {window} behind; versions older than {MAX_WINDOW} are not scanned")
            window = MAX_WINDOW
        stats["window_min"] = round(window.total_seconds() / 60)
        todo = list(dict.fromkeys(pending + list(names)))
        records, deferred = process_names(
            client, todo, popular, seen_keys, now=now, window=window, deadline=started + PROCESS_BUDGET_S,
            fast=_fast_scorer(),
        )
        stats["deferred"] = len(deferred)

    run_id = f"{now:%H%M%S}-{uuid.uuid4().hex[:6]}"
    day = f"{now:%Y-%m-%d}"
    rows = [r.to_json() for r in records]
    # scanned but not flagged: bundles wait for the batched Llama Guard pass
    candidates = [r for r in rows if r["scanned"] and not r["flagged"] and r.get("bundle")]
    if candidates and state.get("lg_enabled", False):
        _append_jsonl(DATA / "lg_pending" / f"{day}-{run_id}.jsonl", candidates)
    # live npm sample (capped): everyday packages as realistic negatives for training and for an
    # honest live false-positive measurement; anything later flagged or confirmed is excluded then
    collected = state.get("live_samples", 0)
    if candidates and collected < LIVE_SAMPLE_CAP:
        keep = [{k: r[k] for k in ("name", "version", "published_at", "seen_at", "content_score", "rules", "bundle")}
                for r in candidates[: LIVE_SAMPLE_CAP - collected]]
        _append_jsonl(DATA / "live_samples" / f"{day}.jsonl", keep)
        state["live_samples"] = collected + len(keep)
    events = [r if r["flagged"] else {k: v for k, v in r.items() if k not in ("bundle", "excerpts")} for r in rows]
    # evidence text of every scanned version (no archives): when OSV later reports a package we did
    # not flag, its bundle is here, so misses can be studied and become fresh training/test data
    kept = [{k: r.get(k) for k in ("name", "version", "published_at", "seen_at", "meta_score", "content_score", "rules",
                                  "fast_risk", "flagged", "bundle")} for r in rows if r.get("bundle")]
    if kept:
        _append_jsonl(DATA / "bundles" / day / f"{run_id}.jsonl", kept)
    _append_jsonl(DATA / "events" / day / f"{run_id}.jsonl", events)
    flagged = [r for r in rows if r["flagged"]]
    if flagged:
        _append_jsonl(DATA / "flagged" / day / f"{run_id}.jsonl", flagged)
        stats["queued"] = _enqueue(flagged)
    volume.commit()

    stats["versions"] = len(records)
    stats["scanned"] = sum(r.scanned for r in records)
    stats["flagged"] = len(flagged)
    stats["fast_flagged"] = sum(1 for r in records if r.flagged and r.content_score < FLAG_CONTENT_THRESHOLD and r.meta_score + r.content_score < FLAG_TOTAL_THRESHOLD)
    stats["errors"] = sum(1 for r in records if r.error)
    # remember recently seen versions (bounded) and the feed position
    recent = (seen_list + [r.key for r in records if r.key not in seen_keys])[-SEEN_MAX:]  # oldest dropped first
    state["seen_recent"] = recent
    if len(deferred) > MAX_PENDING:
        print(f"WARNING: backlog of {len(deferred)} names truncated to {MAX_PENDING}; the rest are not scanned")
    state["pending_names"] = deferred[:MAX_PENDING]
    if since >= head and not deferred:
        state["caught_up_at"] = now.isoformat()
    state["seq"] = since
    state["last_run"] = {"at": now.isoformat(), "head": head, "seq": since, **stats}
    daily = state.get("daily", {})
    d = daily.setdefault(day, {"versions": 0, "scanned": 0, "flagged": 0})
    for k in ("versions", "scanned", "flagged"):
        d[k] += stats[k]
    state["daily"] = daily
    # pending commitments stay in state, so a skipped flush only delays them to the next run
    stats["ledger_committed"] = _flush_ledger() if time.monotonic() - started < LEDGER_START_BY_S else 0
    stats["lag_changes"] = head - since
    stats["seconds"] = round(time.monotonic() - started, 1)
    return stats


LEDGER_SECRET = modal.Secret.from_name("github-ledger", required_keys=["GITHUB_TOKEN"])


@app.function(image=image, volumes={str(DATA): volume}, secrets=[LEDGER_SECRET], schedule=modal.Period(minutes=2), timeout=115, cpu=1.0, memory=2048)
def poll() -> dict:
    import httpx

    # A run that never cleared `poll_started` was killed (timeout, OOM): count it as a failure.
    if state.get("poll_started"):
        _poll_failed("previous run did not finish (timeout or crash)")
    state["poll_started"] = datetime.now(timezone.utc).isoformat()
    try:
        stats = _run_poll()
    except (httpx.TransportError, httpx.HTTPStatusError) as exc:  # npm hiccup: skip, the next run catches up
        state["poll_started"] = None
        _poll_failed(f"network: {type(exc).__name__}: {exc}"[:200])
        return {"skipped": type(exc).__name__}
    except Exception as exc:
        state["poll_started"] = None
        _poll_failed(f"{type(exc).__name__}: {exc}"[:200])
        raise
    state["poll_started"] = None
    if state.get("poll_fail_streak", 0) >= POLL_ALERT_AFTER:
        _notify("Gatekeeper: monitor recovered", f"poll works again after {state['poll_fail_streak']} failed runs.", tags="white_check_mark")
    state["poll_fail_streak"] = 0
    print(json.dumps(stats))
    return stats


POLL_ALERT_AFTER = 3  # failed runs in a row (6 minutes) before a push


def _poll_failed(reason: str) -> None:
    streak = state.get("poll_fail_streak", 0) + 1
    state["poll_fail_streak"] = streak
    state["poll_last_error"] = {"at": datetime.now(timezone.utc).isoformat(), "reason": reason}
    print(f"poll failure #{streak}: {reason}")
    if streak == POLL_ALERT_AFTER or (streak > POLL_ALERT_AFTER and streak % 30 == 0):  # then once an hour
        _notify("Gatekeeper: monitor failing", f"{streak} poll runs in a row failed. Last: {reason}")


def _watchdog() -> None:
    """Called by the 5-minute crons: alert if poll has not finished a run for 10 minutes, whatever the
    cause (also when Modal never started it). At most one push per hour."""
    last = (state.get("last_run") or {}).get("at")
    now = datetime.now(timezone.utc)
    if not last or now - datetime.fromisoformat(last) < timedelta(minutes=10):
        return
    alerted = state.get("watchdog_alert_at")
    if alerted and now - datetime.fromisoformat(alerted) < timedelta(hours=1):
        return
    state["watchdog_alert_at"] = now.isoformat()
    err = (state.get("poll_last_error") or {}).get("reason", "unknown")
    _notify("Gatekeeper: monitor stalled", f"No successful poll since {last[:16]} UTC. Last error: {err}")


@app.function(image=image, volumes={str(DATA): volume}, secrets=[LEDGER_SECRET], timeout=600, cpu=1.0, memory=2048)
def poll_once() -> dict:
    """Manual single run for testing (same code path as the cron)."""
    stats = _run_poll()
    print(json.dumps(stats))
    return stats


QUEUE_TTL = timedelta(days=7)


def _enqueue(rows: list[dict]) -> int:
    from gatekeeper.ledger import canonical_line, commitment, new_salt

    added = 0
    pending = state.get("ledger_pending", [])
    for r in rows:
        key = f"{r['name']}@{r['version']}"
        if key in queue:
            continue
        item = {k: r.get(k) for k in QUEUE_FIELDS}
        item.update(status="pending", leased_until=0.0, verdicts={})
        # public commitment now, salt revealed only after independent confirmation
        line = canonical_line(r["name"], r["version"], r["seen_at"], "flagged")
        salt = new_salt()
        item["ledger"] = {"line": line, "salt": salt, "digest": commitment(salt, line), "revealed": False}
        _append_jsonl(DATA / "ledger" / "salts.jsonl", [{"key": key, **item["ledger"]}])  # private, outlives the queue TTL
        pending.append(f"{r['seen_at']} {item['ledger']['digest']}")
        queue[key] = item
        added += 1
    state["ledger_pending"] = pending
    return added


def _record_catches() -> None:
    """Confirmed detections, kept beyond the queue TTL: the public numbers are built from these."""
    from gatekeeper.confirm.tracker import flag_lead_minutes, publish_to_flag_minutes

    catches = state.get("catches", {})
    for key, it in queue.items():
        conf = it.get("confirmation") or {}
        if not conf.get("confirmed"):
            continue
        verdicts = {b: v.get("verdict") for b, v in (it.get("verdicts") or {}).items()}
        catches[key] = {
            "name": it["name"], "version": it["version"], "published_at": it.get("published_at"),
            "flagged_at": it["seen_at"], "earliest_public": conf.get("earliest_public"),
            "osv_ids": conf.get("osv_ids"), "ghsa_ids": conf.get("ghsa_ids"), "npm_takedown_at": conf.get("npm_takedown_at"),
            "publish_to_flag_min": publish_to_flag_minutes(it.get("published_at"), it["seen_at"]),
            "lead_over_public_min": flag_lead_minutes(it["seen_at"], conf.get("earliest_public")),
            "model_verdicts": verdicts, "review": (it.get("review") or {}).get("decision"),
            "ledger_digest": (it.get("ledger") or {}).get("digest"),
        }
    state["catches"] = catches


def _reveal_confirmed() -> int:
    """Publish the salt of every independently confirmed flag, so anyone can check its commitment."""
    from gatekeeper.ledger import append_file

    token = os.environ.get("GITHUB_TOKEN")
    todo = [(k, it) for k, it in queue.items()
            if (it.get("confirmation") or {}).get("confirmed") and it.get("ledger") and not it["ledger"].get("revealed")]
    if not todo or not token:
        return 0
    lines = []
    for key, it in todo:
        conf = it["confirmation"]
        lines.append(json.dumps({"line": it["ledger"]["line"], "salt": it["ledger"]["salt"], "digest": it["ledger"]["digest"],
                                 "osv_ids": conf.get("osv_ids"), "ghsa_ids": conf.get("ghsa_ids"),
                                 "earliest_public": conf.get("earliest_public")}, sort_keys=True) + "\n")
    try:
        append_file(token, f"revealed/{datetime.now(timezone.utc):%Y-%m}.jsonl", "".join(lines),
                    f"reveal {len(lines)} confirmed detection(s)")
    except Exception as exc:
        print(f"ledger reveal error: {type(exc).__name__}: {exc}"[:300])
        return 0
    for key, it in todo:
        fresh = queue.get(key, None) or it
        fresh["ledger"]["revealed"] = True
        queue[key] = fresh
    return len(lines)


def _flush_ledger() -> int:
    """Publish pending commitments as one new batch file plus its OpenTimestamps proof.

    Each batch is a new file that is never rewritten; the .ots proof (Bitcoin-anchored by public
    calendars) dates it independently of git. On failure the batch waits for the next run."""
    from gatekeeper.ledger import ots_stamp, put_new_file

    pending = state.get("ledger_pending", [])
    token = os.environ.get("GITHUB_TOKEN")
    if not pending or not token:
        return 0
    now = datetime.now(timezone.utc)
    path = f"commitments/{now:%Y-%m-%d}/{now:%H%M%S}-{uuid.uuid4().hex[:6]}.txt"
    data = "".join(line + "\n" for line in pending).encode()
    try:
        proof = ots_stamp(data)
        put_new_file(token, path, data, f"{len(pending)} commitment(s)")
        put_new_file(token, path + ".ots", proof, "OpenTimestamps proof")
    except Exception as exc:  # the ledger must never stop the monitor
        print(f"ledger error: {type(exc).__name__}: {exc}"[:300])
        return 0
    state["ledger_pending"] = state.get("ledger_pending", [])[len(pending):]
    return len(pending)


@app.function(image=image, timeout=120)
def prune_queue(before: str) -> dict:
    """Drop unjudged, unreviewed queue items first seen before `before` (ISO), e.g. flags produced
    by an older, noisier rule set."""
    cutoff = datetime.fromisoformat(before)
    removed = 0
    for key, it in list(queue.items()):
        if it.get("review") or it.get("verdicts"):
            continue
        if datetime.fromisoformat(it["seen_at"]) < cutoff:
            queue.pop(key, None)
            removed += 1
    return {"removed": removed, "remaining": len(queue)}


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


@app.function(image=image, volumes={str(DATA): volume}, secrets=[LEDGER_SECRET, NTFY_SECRET], schedule=modal.Period(hours=1), timeout=900, cpu=0.25, memory=512)
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
        results, gh_error = confirm_many(client, [(it["name"], it["version"]) for it in pending.values()], since, now=now,
                                         github_token=os.environ.get("GITHUB_TOKEN"))
    newly = 0
    rows = []
    for (key, item), conf in zip(pending.items(), results):
        row = conf.as_dict() | {"key": key, "flagged_at": item["seen_at"], "published_at": item["published_at"]}
        rows.append(row)
        if conf.confirmed:
            newly += 1
            _notify(f"Gatekeeper: confirmed {key}", f"Public records: {', '.join(conf.osv_ids + conf.ghsa_ids) or conf.npm_takedown_at}\n"
                    f"We flagged it at {item['seen_at'][:16]} UTC.", click=f"https://osv.dev/list?q={item['name']}", tags="white_check_mark")
        item["confirmation"] = {k: row[k] for k in ("confirmed", "earliest_public", "osv_ids", "ghsa_ids", "npm_takedown_at", "checked_at")}
        queue[key] = item
    _append_jsonl(DATA / "confirmations" / f"{now:%Y-%m-%d}.jsonl", rows)
    _record_catches()
    revealed = _reveal_confirmed()
    volume.commit()
    live_recall.spawn()  # separate container: reads all event logs and the OSV feed
    stats = {"checked": len(results), "newly_confirmed": newly, "expired": len(stale), "github_error": gh_error,
             "ledger_revealed": revealed}
    state["last_confirm"] = {"at": now.isoformat(), **stats}
    print(json.dumps(stats))
    return stats


SPARK_DAILY_CAP_USD = 10.0
SPARK_TOTAL_CAP_USD = 130.0
SPARK_PER_RUN = 20
SPARK_SECRET = modal.Secret.from_name("meta-api", required_keys=["MODEL_API_KEY"])
# Muse Spark Open on Fireworks serverless (paid from Fireworks credits): judges every flag, ~$0.007 per package
FIREWORKS_DAILY_CAP_USD = 5.0
FIREWORKS_TOTAL_CAP_USD = 80.0  # of $100 promo credits; the rest stays for fine-tuning tests
FIREWORKS_PER_RUN = 60
FIREWORKS_SECRET = modal.Secret.from_name("fireworks-api", required_keys=["FIREWORKS_API_KEY"])
# Baseten serves the same Spark Open weights from the hackathon credits ($100): it takes over when
# Fireworks reached its daily cap, so every flag still gets a Spark Open verdict
BASETEN_DAILY_CAP_USD = 8.0
BASETEN_TOTAL_CAP_USD = 85.0  # of $100; the rest stays for the time-split evaluation baseline
BASETEN_SECRET = modal.Secret.from_name("baseten-api", required_keys=["BASETEN_API_KEY"])
# classic token, public_repo only: opens the automatic OpenSSF reports as lb2002
REPORTER_SECRET = modal.Secret.from_name("github-reporter", required_keys=["GITHUB_REPORT_TOKEN"])
# one model on two hosts: they count as a single opinion
SPARK_OPEN_BACKENDS = ("spark-open-fireworks", "spark-open-baseten")
FIRST_OPINION_BACKENDS = ("glimmer-local", *SPARK_OPEN_BACKENDS)
# The cloud crons are killed at 280 s: no call starts after budget_s (140 s), and none runs longer than
# this, so a run always ends with time to spare for saving state.
CLOUD_CALL_TIMEOUT_S = 75


def _spark_candidates(items: dict, now: datetime) -> list[str]:
    """Second opinions on first-opinion malicious/suspicious verdicts first, then high-priority
    items no model has judged for 30 minutes."""
    first, second = [], []
    for key, it in items.items():
        verdicts = it.get("verdicts", {})
        if "spark" in verdicts:
            continue
        if any((verdicts.get(b) or {}).get("verdict") in ("malicious", "suspicious") for b in FIRST_OPINION_BACKENDS):
            first.append((it["priority"], key))
        elif not verdicts and datetime.fromisoformat(it["seen_at"]) < now - timedelta(minutes=30):
            second.append((it["priority"], key))
    return [k for _, k in sorted(first, reverse=True)] + [k for _, k in sorted(second, reverse=True)]


def _fireworks_candidates(items: dict) -> list[str]:
    """Every queued item without a Spark Open verdict (from either host), newest first."""
    todo = [(not it.get("low_priority"), it["seen_at"], key) for key, it in items.items()
            if not any(b in it.get("verdicts", {}) for b in SPARK_OPEN_BACKENDS)]
    return [k for *_, k in sorted(todo, reverse=True)]


NOTIFY_BACKENDS = ("glimmer-local", "spark", *SPARK_OPEN_BACKENDS)


def _notify(title: str, body: str, click: str = "", tags: str = "warning") -> None:
    """Push to the reviewer's phone via ntfy (secret topic). Never raises."""
    topic = os.environ.get("NTFY_TOPIC")
    if not topic:
        return
    import httpx

    headers = {"Title": title.encode("ascii", "replace").decode(), "Tags": tags, "Priority": "high"}
    if click:
        headers["Click"] = click
    try:
        httpx.post(f"https://ntfy.sh/{topic}", content=body.encode(), headers=headers, timeout=10)
    except Exception as exc:
        print(f"ntfy error: {type(exc).__name__}"[:200])


def _maybe_notify_candidate(key: str, item: dict) -> dict:
    """Strong candidate: at least two Meta-model verdicts malicious/suspicious, one of them malicious."""
    if item.get("notified") or (item.get("confirmation") or {}).get("confirmed"):
        return item
    calls = {("spark-open" if b in SPARK_OPEN_BACKENDS else b): v for b, v in (item.get("verdicts") or {}).items()
             if b in NOTIFY_BACKENDS and v.get("verdict")}
    bad = {b: v for b, v in calls.items() if v["verdict"] in ("malicious", "suspicious")}
    if len(bad) < 2 or not any(v["verdict"] == "malicious" for v in bad.values()):
        return item
    now = datetime.now(timezone.utc)
    item["notified"] = now.isoformat()
    # one push per package name per 12 h: campaigns publish many versions within minutes
    pushed = state.get("notified_names", {})
    last = pushed.get(item["name"])
    if last and now - datetime.fromisoformat(last) < timedelta(hours=12):
        item["notify_suppressed"] = True
        return item
    pushed = {n: t for n, t in pushed.items() if now - datetime.fromisoformat(t) < timedelta(hours=12)}
    pushed[item["name"]] = now.isoformat()
    state["notified_names"] = pushed
    summary = ", ".join(f"{b} {v['verdict']} {v.get('confidence')}" for b, v in bad.items())
    _notify(f"Gatekeeper: candidate {key}", f"{summary}\nFurther versions of this package stay silent for 12 h.\n"
            f"Review: uv run gk packet {key}", click=f"https://www.npmjs.com/package/{item['name']}")
    return item


def _cloud_one(backend: str, key: str, item: dict, spend: dict, now: datetime) -> dict:
    """Classify one queued item with a cloud model, book the cost and store the verdict. Raises on API errors."""
    from gatekeeper.evidence.bundle import RenderedBundle
    from gatekeeper.models.backends import classify_spark, classify_spark_open_baseten, classify_spark_open_fireworks

    classify = {"spark": classify_spark, "spark-open-fireworks": classify_spark_open_fireworks,
                "spark-open-baseten": classify_spark_open_baseten}[backend]
    day = f"{now:%Y-%m-%d}"
    result = classify(RenderedBundle.from_record(item), timeout=CLOUD_CALL_TIMEOUT_S)
    spend["total"] += result.cost_usd
    spend["days"][day] = spend["days"].get(day, 0.0) + result.cost_usd
    v = result.verdict
    row = {
        "key": key, "backend": backend, "model": result.model,
        "verdict": v.model_dump(mode="json") if v else None, "errors": result.errors,
        "latency_s": result.latency_s, "input_tokens": result.input_tokens, "cached_tokens": result.cached_tokens,
        "output_tokens": result.output_tokens, "cost_usd": result.cost_usd, "received_at": now.isoformat(),
    }
    if not v:
        row["raw"] = result.raw[:4000]
    _append_jsonl(DATA / "verdicts" / day / f"{backend}.jsonl", [row])
    # re-read just before writing so verdicts stored meanwhile by other crons or the laptop survive
    fresh = queue.get(key, None) or item
    fresh.setdefault("verdicts", {})[backend] = {
        "verdict": v.verdict.value if v else None, "confidence": v.confidence if v else None,
        "at": now.isoformat(), "errors": result.errors[:3], "full": row["verdict"],
    }
    queue[key] = _maybe_notify_candidate(key, fresh)
    return row


def _run_cloud(
    backend: str, keys: list[str], spend_key: str, daily_cap: float, total_cap: float,
    workers: int = 1, budget_s: float = 240,
) -> dict:
    import threading
    from concurrent.futures import ThreadPoolExecutor

    started = time.monotonic()
    now = datetime.now(timezone.utc)
    day = f"{now:%Y-%m-%d}"
    spend = state.get(spend_key, {"total": 0.0, "days": {}})
    lock = threading.Lock()
    counts = {"done": 0, "errors": 0, "consecutive_errors": 0}

    def one(key: str) -> None:
        with lock:
            stop = (
                spend["total"] >= total_cap or spend["days"].get(day, 0.0) >= daily_cap
                or counts["consecutive_errors"] >= 3 or time.monotonic() - started > budget_s
            )
        item = None if stop else queue.get(key, None)
        if item is None:
            return
        try:
            row = _cloud_one(backend, key, item, {"total": 0.0, "days": {}}, now)
        except Exception as exc:  # API errors (timeouts, rate limits) skip the item; 3 in a row stop the run
            print(f"{backend} error on {key}: {type(exc).__name__}: {exc}"[:300])
            with lock:
                counts["errors"] += 1
                counts["consecutive_errors"] += 1
            return
        with lock:
            spend["total"] += row["cost_usd"]
            spend["days"][day] = spend["days"].get(day, 0.0) + row["cost_usd"]
            counts["done"] += 1
            counts["consecutive_errors"] = 0
            state[spend_key] = spend  # save as we go, so a timeout cannot lose booked spend

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(one, keys))
    state[spend_key] = spend
    volume.commit()
    stats = {"backend": backend, "classified": counts["done"], "errors": counts["errors"],
             "spend_today": round(spend["days"].get(day, 0.0), 4), "spend_total": round(spend["total"], 4)}
    print(json.dumps(stats))
    return stats


@app.function(image=image, volumes={str(DATA): volume}, secrets=[SPARK_SECRET, NTFY_SECRET, REPORTER_SECRET], schedule=modal.Period(minutes=5), timeout=280, cpu=0.25, memory=512)
def spark() -> dict:
    """Second opinions from Muse Spark (Meta Model API) under hard spending caps, after the automatic
    reporting pass. Spark is disabled until state['spark_enabled'] is True."""
    _watchdog()
    items = dict(queue.items())
    reported = _autoreport(items, budget_s=50)
    if not state.get("spark_enabled", False):
        return {"enabled": False, **reported}
    keys = _spark_candidates(items, datetime.now(timezone.utc))[:SPARK_PER_RUN]
    return _run_cloud("spark", keys, "spark_spend", SPARK_DAILY_CAP_USD, SPARK_TOTAL_CAP_USD, workers=4, budget_s=110) | reported


def _autoreport(items: dict, budget_s: float) -> dict:
    """Report packages that pass every check in gatekeeper.report.auto to OpenSSF, without a human.
    Off unless state['autoreport_enabled']; mode 'dry' does everything except the GitHub writes.
    Never raises: a failure here must not stop the Spark cron (and fails closed: nothing is sent)."""
    if not state.get("autoreport_enabled", False):
        return {"autoreport": "off"}
    try:
        return _autoreport_run(items, budget_s)
    except Exception as exc:
        print(f"autoreport failed: {type(exc).__name__}: {exc}"[:300])
        return {"autoreport": "error"}


# Results that cannot change on a later run. Anything else (network errors, the daily limit) is
# not stored, so the item is evaluated again on the next run.
AUTOREPORT_FINAL = (
    "no longer on the registry", "version no longer on the registry", "popular package", "package older than 7 days",
    "too many versions", "archive integrity mismatch", "archive unreadable", "install-time code does not meet the static check",
    "already in OSV", "a pull request already exists", "package already reported",
)
JUDGE_NAMES = {"spark": "Muse Spark", "spark-open": "Muse Spark Open", "glimmer-local": "Muse Glimmer"}


def _github():
    import httpx

    return httpx.Client(base_url="https://api.github.com", timeout=20, headers={
        "Authorization": f"Bearer {os.environ['GITHUB_REPORT_TOKEN']}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})


def _autoreport_run(items: dict, budget_s: float) -> dict:
    from gatekeeper.report import auto

    started = time.monotonic()
    live = state.get("autoreport_mode", "dry") == "live" and bool(os.environ.get("GITHUB_REPORT_TOKEN"))
    if live and _autoreport_breaker():
        return {"autoreport": "stopped"}
    reports = state.get("autoreports", {})
    by_name: dict[str, list] = {}
    for key, it in items.items():
        prev = it.get("autoreport")
        if prev and not (live and prev.get("result") == "dry-run"):
            continue
        if it.get("low_priority") or (it.get("review") or {}).get("decision") not in (None, "malicious"):
            continue
        ok, judges = auto.models_agree(it.get("verdicts"))
        if ok:  # otherwise re-checked next run, when more verdicts may have arrived
            by_name.setdefault(it["name"], []).append((key, it, judges))
    done = []
    for name, entries in by_name.items():
        if time.monotonic() - started > budget_s:
            break
        if name in reports:  # reported or pending: later versions are never added automatically
            marks = {key: {"result": "skipped", "reason": "package already reported"} for key, _, _ in entries}
        else:
            try:
                marks = _autoreport_package(name, entries, live)
            except Exception as exc:  # network trouble: everything is evaluated again next run
                print(f"autoreport error on {name}: {type(exc).__name__}: {exc}"[:300])
                continue
        for key, result in marks.items():
            if result["result"] == "skipped" and result["reason"] not in AUTOREPORT_FINAL:
                continue
            fresh = queue.get(key, None)
            if fresh is not None:
                fresh["autoreport"] = {"at": datetime.now(timezone.utc).isoformat(), **result}
                queue[key] = fresh
            done.append({"key": key, **result})
    volume.commit()
    return {"autoreport": "live" if live else "dry", "autoreport_done": done}


def _autoreport_breaker() -> bool:
    """Stop all automatic reporting as soon as OpenSSF closes one of our reports without merging it.
    Checked every 30 minutes; a GitHub error raises, which skips reporting for this run."""
    from gatekeeper.report import auto

    now = datetime.now(timezone.utc)
    last = state.get("autoreport_breaker_at")
    if last and now - datetime.fromisoformat(last) < timedelta(minutes=30):
        return False
    urls = [r["pr"] for r in state.get("autoreports", {}).values() if r.get("pr")] + state.get("reports_watch", [])
    with _github() as gh:
        for url in urls:
            r = gh.get(f"/repos/{auto.UPSTREAM}/pulls/{url.rsplit('/', 1)[-1]}")
            r.raise_for_status()
            pr = r.json()
            if pr["state"] == "closed" and not pr.get("merged_at"):
                state["autoreport_enabled"] = False
                _notify("Gatekeeper: automatic reporting stopped",
                        f"OpenSSF closed {url} without merging it. Nothing is reported automatically until you have "
                        "looked at it and switched it on again.", click=url, tags="no_entry")
                return True
    state["autoreport_breaker_at"] = now.isoformat()
    return False


def _autoreport_package(name: str, entries: list, live: bool) -> dict:
    """Decide and (in live mode) submit one report for all qualifying versions of `name`.
    Returns {queue key: result}. Raises on network errors (the caller retries next run)."""
    import base64
    import hashlib
    import tarfile

    from gatekeeper.confirm import osv as osv_api
    from gatekeeper.npm import feed, packument
    from gatekeeper.npm.tarball import ArchiveTooLarge, read_tarball
    from gatekeeper.popular import load_popular
    from gatekeeper.report import auto

    now = datetime.now(timezone.utc)
    day = f"{now:%Y-%m-%d}"

    def skip(reason: str, keys=None) -> dict:
        return {k: {"result": "skipped", "reason": reason} for k in (keys or [k for k, _, _ in entries])}

    marks: dict = {}
    evidence = []
    with feed.make_client(timeout=HTTP_TIMEOUT_S) as client:
        doc = packument.fetch_packument(client, name)
        if not doc:
            return skip("no longer on the registry")
        ok, why = auto.package_is_new(doc, load_popular(DATA / "popular.txt"), now)
        if not ok:
            return skip(why)
        if any(v.get("id", "").startswith("MAL-") for v in osv_api.query(client, name)):
            return skip("already in OSV")
        for key, it, _ in entries:
            version = it["version"]
            if version not in (doc.get("versions") or {}):
                marks |= skip("version no longer on the registry", [key])
                continue
            info = packument.version_info(doc, version)
            resp = client.get(info.tarball_url)
            resp.raise_for_status()
            if not (info.integrity or "").startswith("sha512-") or \
                    base64.b64encode(hashlib.sha512(resp.content).digest()).decode() != info.integrity[7:]:
                marks |= skip("archive integrity mismatch", [key])
                continue
            try:
                pkg = read_tarball(resp.content)
            except (ArchiveTooLarge, tarfile.TarError, EOFError, OSError):
                marks |= skip("archive unreadable", [key])
                continue
            ev = auto.install_evidence(pkg, version)
            if ev is None:
                marks |= skip("install-time code does not meet the static check", [key])
                continue
            evidence.append((key, it, ev))
    if not evidence:
        return marks
    ev_keys = [k for k, _, _ in evidence]
    counts = state.get("autoreport_days", {})
    if counts.get(day, 0) >= auto.DAILY_LIMIT:
        return marks | skip("daily limit reached", ev_keys)
    judge_ids = sorted({j for _, it, _ in evidence for j in auto.judge_verdicts(it.get("verdicts"))})
    judges = ", ".join(JUDGE_NAMES.get(j, j) for j in judge_ids)
    published = {it["version"]: it.get("published_at") or "" for _, it, _ in evidence}
    osv_doc = auto.build_osv(name, [ev for _, _, ev in evidence], published, judges, now)
    if not live:
        _append_jsonl(DATA / "autoreport" / "dry" / f"{day}.jsonl", [{"name": name, "versions": list(published), "osv": osv_doc}])
        return marks | {k: {"result": "dry-run", "reason": judges} for k in ev_keys}

    # last look at the live queue: a newer dissenting verdict or a human review wins
    for key in ev_keys:
        fresh = queue.get(key, None) or {}
        if (fresh.get("review") or {}).get("decision") not in (None, "malicious") or not auto.models_agree(fresh.get("verdicts"))[0]:
            return marks
    with _github() as gh:
        found = auto.existing_pr(gh, name)
        if found:
            return marks | {k: {"result": "skipped", "reason": "a pull request already exists", "pr": found} for k in ev_keys}
        reports = state.get("autoreports", {})
        reports[name] = {"pending": now.isoformat(), "versions": list(published)}  # blocks any retry from submitting twice
        state["autoreports"] = reports
        try:
            res = auto.submit(gh, osv_doc, name)
        except Exception:
            _notify(f"Gatekeeper: automatic report for {name} failed",
                    "It stopped partway and will not be retried. Check https://github.com/lb2002/malicious-packages/branches")
            raise
    try:  # bookkeeping must never trigger a second submission
        reports = state.get("autoreports", {})
        reports[name] = {**res, "versions": list(published), "at": now.isoformat()}
        state["autoreports"] = reports
        counts[day] = counts.get(day, 0) + 1
        state["autoreport_days"] = counts
        _append_jsonl(DATA / "autoreport" / f"{day}.jsonl", [{"name": name, "pr": res["pr"], "osv": osv_doc}])
    except Exception as exc:
        print(f"autoreport bookkeeping error for {name}: {type(exc).__name__}: {exc}"[:300])
    _notify(f"Gatekeeper: reported {name} to OpenSSF", f"{res['pr']}\nVersions: {', '.join(published)}\nJudges: {judges}\n"
            "No action needed. To retract, close the PR.", click=res["pr"], tags="rotating_light")
    return marks | {k: {"result": "reported", "pr": res["pr"]} for k in ev_keys}


@app.function(image=image, volumes={str(DATA): volume}, secrets=[FIREWORKS_SECRET, BASETEN_SECRET, NTFY_SECRET], schedule=modal.Period(minutes=5), timeout=280, cpu=0.25, memory=512)
def spark_open() -> dict:
    """Muse Spark Open judges every flag under hard spending caps: on Fireworks while it is under its
    caps, otherwise on Baseten. Each host is off until state['fireworks_enabled'] / ['baseten_enabled']."""
    _watchdog()
    host = _spark_open_host()
    if host is None:
        return {"enabled": False}
    backend, spend_key, daily_cap, total_cap = host
    keys = _fireworks_candidates(dict(queue.items()))[:FIREWORKS_PER_RUN]
    return _run_cloud(backend, keys, spend_key, daily_cap, total_cap, workers=8, budget_s=140)


def _spark_open_host() -> tuple[str, str, float, float] | None:
    day = f"{datetime.now(timezone.utc):%Y-%m-%d}"
    hosts = [("fireworks_enabled", "spark-open-fireworks", "fireworks_spend", FIREWORKS_DAILY_CAP_USD, FIREWORKS_TOTAL_CAP_USD),
             ("baseten_enabled", "spark-open-baseten", "baseten_spend", BASETEN_DAILY_CAP_USD, BASETEN_TOTAL_CAP_USD)]
    for flag, backend, spend_key, daily_cap, total_cap in hosts:
        spend = state.get(spend_key, {"total": 0.0, "days": {}})
        if state.get(flag, False) and spend["total"] < total_cap and spend["days"].get(day, 0.0) < daily_cap:
            return backend, spend_key, daily_cap, total_cap
    return None


LG_MAX_PER_RUN = 3000
# v2: trained with real npm releases as negatives (v1 flagged 37% of live npm). Validation threshold
# 0.10; 0.30 keeps live false positives at ~1.2% on held-out later days (55% time-split recall).
LG_ADAPTER = "llamaguard1b-gatekeeper-v2"
LG_MIN_THRESHOLD = 0.3
LG_KILL_RATE = 0.04  # a run is "hot" if it flags more than 4% of the distinct packages it scores
LG_STRONG = 0.9  # in a hot run, weaker hits are queued as low priority


@app.function(image=lg_image, gpu="L4", volumes={str(DATA): volume, "/models": model_volume},
              secrets=[modal.Secret.from_name("huggingface"), NTFY_SECRET], schedule=modal.Period(minutes=15), timeout=900,
              cpu=2.0, memory=16384)
def llamaguard() -> dict:
    """Batched pass of the fine-tuned Llama Guard 3 1B over every scanned version the rules and the
    classifier let through, plus a score for each queued flag. Its flags enter the normal queue,
    where the Muse models judge them with cited lines and a human reviews them."""
    from gatekeeper.models.llamaguard import BACKEND, LlamaGuardScorer, prepare

    if not state.get("lg_enabled", False):
        return {"enabled": False}
    volume.reload()
    now = datetime.now(timezone.utc)
    files = sorted((DATA / "lg_pending").glob("*.jsonl")) if (DATA / "lg_pending").exists() else []
    candidates: list[dict] = []
    used: list[Path] = []
    for path in files:
        if len(candidates) >= LG_MAX_PER_RUN:
            break
        candidates += [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        used.append(path)
    queued = [(k, it) for k, it in queue.items() if it.get("lg_risk") is None and it.get("bundle")]
    if not candidates and not queued:
        return {"scored": 0}
    scorer = LlamaGuardScorer(DATA / "models" / LG_ADAPTER)
    scorer.threshold = max(scorer.threshold, LG_MIN_THRESHOLD)
    texts = [prepare(r["bundle"], r["name"], r["version"], r.get("rules") or []) for r in candidates]
    texts += [prepare(it["bundle"], it["name"], it["version"], it.get("rules") or []) for _, it in queued]
    risks = scorer.risk(texts)
    cand_risks, queue_risks = risks[: len(candidates)], risks[len(candidates):]

    new_flags = []
    for r, risk in zip(candidates, cand_risks):
        if risk >= scorer.threshold:
            r["flagged"], r["lg_risk"] = True, round(risk, 4)
            new_flags.append(r)
    # Unusual flag rate (broken model, or a flood meant to bury real hits): nothing is dropped and the
    # model is never switched off automatically. Weaker hits of a hot run are queued as low priority,
    # so the cloud judges see everything else first (their daily caps bound the cost), and the
    # reviewer gets one push per hot streak to decide.
    names_scored = {r["name"] for r in candidates}
    names_flagged = {r["name"] for r in new_flags}
    hot = len(names_scored) >= 50 and len(names_flagged) > LG_KILL_RATE * len(names_scored)
    hot_runs = state.get("lg_hot_runs", 0) + 1 if hot else 0
    state["lg_hot_runs"] = hot_runs
    if hot:
        for r in new_flags:
            if r["lg_risk"] < LG_STRONG:
                r["low_priority"] = True
                r["priority"] = min(r.get("priority") or 0, 0)
    if hot_runs == 1:
        _notify("Gatekeeper: unusual Llama Guard rate",
                f"It flagged {len(names_flagged)} of {len(names_scored)} scanned packages (expected about 1%). "
                "Weaker hits are queued as low priority. Switch it off with set_lg if this continues.", tags="warning")
    added = _enqueue(new_flags) if new_flags else 0
    for r in new_flags:  # record the score as a verdict on the new queue items
        key = f"{r['name']}@{r['version']}"
        it = queue.get(key, None)
        if it is not None:
            it.setdefault("verdicts", {})[BACKEND] = {"verdict": "malicious", "confidence": r["lg_risk"], "at": now.isoformat(), "full": None}
            queue[key] = it
    for (key, _), risk in zip(queued, queue_risks):
        fresh = queue.get(key, None)
        if fresh is None:
            continue
        # Llama Guard may only raise concern: a low score is kept as a number, never as a "benign"
        # verdict that would make a flag look judged and drop it from Spark or the review list.
        fresh["lg_risk"] = round(risk, 4)
        if risk >= scorer.threshold:
            fresh.setdefault("verdicts", {})[BACKEND] = {"verdict": "malicious", "confidence": round(risk, 4), "at": now.isoformat(), "full": None}
        queue[key] = fresh
    if new_flags:
        _append_jsonl(DATA / "flagged" / f"{now:%Y-%m-%d}" / f"llamaguard-{now:%H%M%S}.jsonl", new_flags)
    for path in used:
        path.unlink()
    daily = state.get("daily", {})
    d = daily.setdefault(f"{now:%Y-%m-%d}", {"versions": 0, "scanned": 0, "flagged": 0})
    d["lg_scored"] = d.get("lg_scored", 0) + len(candidates)
    d["lg_flagged"] = d.get("lg_flagged", 0) + len(new_flags)
    d["flagged"] += added
    state["daily"] = daily
    volume.commit()
    stats = {"scored": len(candidates), "flagged": len(new_flags), "hot_runs": hot_runs,
             "queued": added, "queue_scored": len(queued),
             "threshold": round(scorer.threshold, 4)}
    print(json.dumps(stats))
    return stats


@app.function(image=image, volumes={str(DATA): volume}, secrets=[SPARK_SECRET, FIREWORKS_SECRET, BASETEN_SECRET], timeout=180, cpu=0.25, memory=512)
def cloud_probe(backend: str = "spark", key: str = "") -> dict:
    """One call on one queued item (the top candidate unless a key is given), to check the key,
    the schema mode and the cost accounting before a cron is switched on."""
    now = datetime.now(timezone.utc)
    items = dict(queue.items())
    candidates = _spark_candidates(items, now) if backend == "spark" else _fireworks_candidates(items)
    key = key or next(iter(candidates), "")
    item = queue.get(key, None) if key else None
    if item is None:
        return {"error": f"no queued item {key!r}"}
    spend_key = {"spark": "spark_spend", "spark-open-fireworks": "fireworks_spend", "spark-open-baseten": "baseten_spend"}[backend]
    spend = state.get(spend_key, {"total": 0.0, "days": {}})
    try:
        row = _cloud_one(backend, key, item, spend, now)
    except Exception as exc:
        body = getattr(getattr(exc, "response", None), "text", "")
        return {"error": f"{type(exc).__name__}: {exc}"[:300], "body": body[:500]}
    state[spend_key] = spend
    volume.commit()
    v = row["verdict"] or {}
    return {
        "key": key, "verdict": v.get("verdict"), "confidence": v.get("confidence"), "summary": v.get("summary"),
        "errors": row["errors"], "latency_s": round(row["latency_s"], 1), "input_tokens": row["input_tokens"],
        "cached_tokens": row["cached_tokens"], "output_tokens": row["output_tokens"],
        "cost_usd": round(row["cost_usd"], 5), "spend_total": round(spend["total"], 5),
        "raw": row.get("raw", "")[:1500],
    }


@app.function(image=image, secrets=[SPARK_SECRET], timeout=120)
def spark_params_probe(extra: dict) -> dict:
    """Tiny request (a few tokens) to see how the API treats request parameters."""
    import httpx

    payload = {"model": "muse-spark-1.3", "messages": [{"role": "user", "content": 'Reply with the JSON {"ok": true} only.'}]} | extra
    r = httpx.post("https://api.meta.ai/v1/chat/completions", json=payload, timeout=90,
                   headers={"Authorization": f"Bearer {os.environ['MODEL_API_KEY']}"})
    if r.status_code != 200:
        return {"status": r.status_code, "body": r.text[:500]}
    d = r.json()
    c = d["choices"][0]
    return {"finish": c.get("finish_reason"), "content": (c["message"].get("content") or "")[:200], "usage": d.get("usage")}


@app.function(image=image, timeout=60)
def set_spark(enabled: bool) -> dict:
    state["spark_enabled"] = bool(enabled)
    return {"spark_enabled": state["spark_enabled"], "spend": state.get("spark_spend", None)}


@app.function(image=image, timeout=120, cpu=0.25, memory=1024)
def inspect_package(name: str, version: str, show_up_to: int = 20_000) -> dict:
    """Facts for a human review and a report: tarball and per-file SHA-256, the manifest, and the
    full text of install-time files. Read in memory inside this container; nothing is executed."""
    import hashlib

    from gatekeeper.npm import feed, packument
    from gatekeeper.npm.tarball import read_tarball
    from gatekeeper.triage.content import install_time_files

    with feed.make_client() as client:
        doc = packument.fetch_packument(client, name) or {}
        info = packument.version_info(doc, version)
        data = client.get(info.tarball_url).content if info.tarball_url else b""
    pkg = read_tarball(data)
    install = install_time_files(pkg)
    return {
        "name": name, "version": version, "published_at": info.published_at.isoformat() if info.published_at else None,
        "publisher": info.publisher, "maintainers": info.maintainers, "tarball_url": info.tarball_url,
        "tarball_sha256": hashlib.sha256(data).hexdigest(), "integrity": info.integrity,
        "files": {p: {"size": pkg.sizes[p], "sha256": hashlib.sha256(b).hexdigest()} for p, b in pkg.files.items()},
        "install_time_files": install,
        "text": {p: (pkg.text(p) or "")[:show_up_to] for p in install + [info_main for info_main in ("index.js",) if info_main in pkg.files]},
        "still_on_registry": version in (doc.get("versions") or {}),
    }


@app.function(image=image, timeout=60)
def set_lg(enabled: bool) -> dict:
    state["lg_enabled"] = bool(enabled)
    return {"lg_enabled": state["lg_enabled"]}


@app.function(image=image, timeout=60)
def set_fireworks(enabled: bool) -> dict:
    state["fireworks_enabled"] = bool(enabled)
    return {"fireworks_enabled": state["fireworks_enabled"], "spend": state.get("fireworks_spend", None)}


@app.function(image=image, timeout=60)
def set_autoreport(enabled: bool, mode: str = "dry") -> dict:
    """mode 'dry' records what would be reported; 'live' opens OpenSSF pull requests."""
    assert mode in ("dry", "live")
    state["autoreport_enabled"] = bool(enabled)
    state["autoreport_mode"] = mode
    return {"autoreport_enabled": state["autoreport_enabled"], "autoreport_mode": mode,
            "reports": state.get("autoreports", {}), "per_day": state.get("autoreport_days", {})}


@app.function(image=image, timeout=60)
def set_baseten(enabled: bool) -> dict:
    state["baseten_enabled"] = bool(enabled)
    return {"baseten_enabled": state["baseten_enabled"], "spend": state.get("baseten_spend", None)}



@app.function(image=image, volumes={str(DATA): volume}, timeout=900, cpu=1.0, memory=2048)
def rebuild_public_stats() -> dict:
    """Recount the daily totals from the per-run event logs and refresh the confirmed-catch record."""
    volume.reload()
    daily: dict[str, dict] = {}
    for day_dir in sorted((DATA / "events").iterdir()):
        d = {"versions": 0, "scanned": 0, "flagged": 0}
        for path in day_dir.glob("*.jsonl"):
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                r = json.loads(line)
                d["versions"] += 1
                d["scanned"] += bool(r.get("scanned"))
                d["flagged"] += bool(r.get("flagged"))
        daily[day_dir.name] = d
    state["daily"] = daily
    _record_catches()
    return {"daily": daily, "catches": len(state.get("catches", {}))}


@app.function(image=image, volumes={str(DATA): volume}, timeout=900, cpu=1.0, memory=2048)
def live_recall() -> dict:
    """Of the npm packages OSV reported as malicious since the monitor started: how many we flagged
    (any stage), how fast, and what the misses looked like. Spawned by `confirm` every hour."""
    from gatekeeper.confirm import recall
    from gatekeeper.npm import feed

    volume.reload()
    start = datetime.fromisoformat(min(state.get("daily", {"2026-10-27": 0})) + "T00:00:00+00:00")
    with feed.make_client(timeout=30) as client:
        vulns = recall.fetch_recent(client, start)
    names = {name for v in vulns for name, _ in recall._targets(v)}
    seen: dict[str, list[dict]] = {}
    for path in sorted((DATA / "events").glob("*/*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip() and any(n in line for n in names):  # cheap prefilter before parsing
                r = json.loads(line)
                if r.get("name") in names:
                    seen.setdefault(r["name"], []).append({k: r.get(k) for k in (
                        "version", "published_at", "seen_at", "scanned", "flagged", "meta_score", "content_score", "error")})
    flags: dict[str, str] = {}
    salts = DATA / "ledger" / "salts.jsonl"
    if salts.exists():
        for line in salts.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                flags.setdefault(row["key"], json.loads(row["line"])["flagged_at"])
    for key, it in queue.items():
        flags.setdefault(key, it["seen_at"])
    outcomes = [o for v in vulns for o in recall.classify(v, seen, flags, start)]
    result = {"at": datetime.now(timezone.utc).isoformat(), "since": start.isoformat(), **recall.summarize(outcomes),
              "outcomes": [o.as_dict() for o in sorted(outcomes, key=lambda o: o.first_public or "")]}
    state["recall"] = result
    out = DATA / "recall" / f"{datetime.now(timezone.utc):%Y-%m-%d}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=1), encoding="utf-8")
    volume.commit()
    return result


REPO_URL = "https://github.com/lb2002/gatekeeper"
LEDGER_URL = "https://github.com/lb2002/gatekeeper-ledger"


def _median(xs: list[float]) -> float | None:
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    mid = len(xs) // 2
    return xs[mid] if len(xs) % 2 else (xs[mid - 1] + xs[mid]) / 2


def _public_stats() -> dict:
    daily = state.get("daily", {})
    catches = sorted(state.get("catches", {}).values(), key=lambda c: c["flagged_at"])
    packages = sorted({c["name"] for c in catches})
    first = [min((c for c in catches if c["name"] == n), key=lambda c: c["flagged_at"]) for n in packages]
    totals = {k: sum(d.get(k, 0) for d in daily.values()) for k in ("versions", "scanned", "flagged")}
    return {
        "since": min(daily) if daily else None,
        "updated_at": (state.get("last_run") or {}).get("at"),
        "totals": totals,
        "daily": [{"day": d, **daily[d]} for d in sorted(daily)],
        "confirmed_packages": len(packages),
        "confirmed_versions": len(catches),
        "median_publish_to_flag_min": _median([c["publish_to_flag_min"] for c in first]),
        "flagged_before_public_report": sum(1 for c in first if (c.get("lead_over_public_min") or 0) > 0),
        "median_lead_over_public_min": _median([c["lead_over_public_min"] for c in first if (c.get("lead_over_public_min") or 0) > 0]),
        "live_recall": {k: v for k, v in (state.get("recall") or {}).items() if k != "outcomes"},
        "catches": catches,
        "repo": REPO_URL,
        "ledger": LEDGER_URL,
    }


def _fmt_minutes(m: float | None) -> str:
    if m is None:
        return "-"
    return f"{m:.1f} min" if abs(m) < 120 else f"{m / 60:.1f} h"


def _public_html(st: dict) -> str:
    from html import escape

    rows = "".join(
        f"<tr><td><code>{escape(c['name'])}@{escape(c['version'])}</code></td><td>{escape((c['published_at'] or '')[:16])}</td>"
        f"<td>{_fmt_minutes(c['publish_to_flag_min'])}</td><td>{_fmt_minutes(c['lead_over_public_min'])}</td>"
        f"<td>{' '.join(escape(i) for i in (c.get('osv_ids') or []) + (c.get('ghsa_ids') or []))}</td></tr>"
        for c in st["catches"]
    ) or '<tr><td colspan="5">none yet</td></tr>'
    days = "".join(
        f"<tr><td>{escape(d['day'])}</td><td>{d['versions']:,}</td><td>{d['scanned']:,}</td><td>{d['flagged']:,}</td></tr>"
        for d in reversed(st["daily"])
    )
    t = st["totals"]
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gatekeeper live</title><style>
:root{{--bg:#fbfbf9;--fg:#1d1d1b;--muted:#6b6b66;--line:#e3e3dd;--accent:#b4232c}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151514;--fg:#ececea;--muted:#9a9a94;--line:#2c2c2a;--accent:#ef6b6b}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:880px;margin:0 auto;padding:24px 16px}}
h1{{font-size:22px;margin:0}} .sub{{color:var(--muted);margin:4px 0 24px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:28px}}
.kpi{{border:1px solid var(--line);border-radius:8px;padding:12px}} .kpi b{{display:block;font-size:24px}} .kpi span{{color:var(--muted);font-size:13px}}
table{{border-collapse:collapse;width:100%;margin:8px 0 28px;font-size:14px}} th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}}
th{{color:var(--muted);font-weight:500}} .wrap{{overflow-x:auto}} a{{color:var(--accent)}} code{{font-size:13px}}
</style></head><body>
<h1>Gatekeeper: live npm malware monitor</h1>
<p class="sub">Every new npm release, checked statically by rules, a fast classifier and Meta models (Muse Spark, Muse Glimmer). Running since {escape(st['since'] or '-')}; last run {escape((st['updated_at'] or '-')[:16])} UTC.</p>
<div class="kpis">
<div class="kpi"><b>{t['versions']:,}</b><span>versions checked</span></div>
<div class="kpi"><b>{t['scanned']:,}</b><span>archives scanned</span></div>
<div class="kpi"><b>{t['flagged']:,}</b><span>flagged for model review</span></div>
<div class="kpi"><b>{st['confirmed_packages']}</b><span>independently confirmed malicious packages</span></div>
<div class="kpi"><b>{_fmt_minutes(st['median_publish_to_flag_min'])}</b><span>median publish to flag</span></div>
<div class="kpi"><b>{st['flagged_before_public_report']}</b><span>flagged before the public report (median lead {_fmt_minutes(st['median_lead_over_public_min'])})</span></div>
</div>
<h2>Confirmed catches</h2>
<p class="sub">Only detections confirmed by OSV / OpenSSF, GitHub advisories or an npm takedown are named. Flag times are committed as salted hashes to the <a href="{st['ledger']}">public ledger</a> when they happen.</p>
<div class="wrap"><table><tr><th>package</th><th>published (UTC)</th><th>publish to flag</th><th>lead over public report</th><th>public records</th></tr>{rows}</table></div>
<h2>Daily volume</h2>
<div class="wrap"><table><tr><th>day (UTC)</th><th>versions</th><th>scanned</th><th>flagged</th></tr>{days}</table></div>
<p class="sub">Open source: <a href="{st['repo']}">{st['repo']}</a> · JSON: <a href="stats.json">stats.json</a></p>
</body></html>"""


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


@app.function(image=image, volumes={str(DATA): volume}, secrets=[worker_secret, NTFY_SECRET], cpu=0.25, memory=512)
@modal.concurrent(max_inputs=20)
@modal.asgi_app()
def api():
    """Worker API: laptop workers lease flagged bundles and post verdicts back (bearer token)."""
    import os

    from fastapi import Depends, FastAPI, Header, HTTPException
    from fastapi.responses import HTMLResponse

    web = FastAPI(title="gatekeeper")
    token = os.environ["GK_WORKER_TOKEN"]

    def auth(authorization: str = Header(default="")) -> None:
        if authorization != f"Bearer {token}":
            raise HTTPException(status_code=401, detail="unauthorized")

    @web.get("/stats.json")
    def public_stats() -> dict:
        """Public, no auth: daily counts and independently confirmed catches only. Unconfirmed
        flags are never named here (they appear only as salted hashes in the ledger)."""
        return _public_stats()

    @web.get("/", response_class=HTMLResponse)
    def public_page() -> str:
        return _public_html(_public_stats())

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
            "fireworks_enabled": state.get("fireworks_enabled", False),
            "fireworks_spend": state.get("fireworks_spend", None),
        }

    @web.get("/work", dependencies=[Depends(auth)])
    def work(backend: str = "glimmer-local") -> dict:
        now = time.time()
        best_key, best = None, None
        items = dict(queue.items())
        judged = {it.get("bundle_sha256"): it["verdicts"][backend] for it in items.values() if backend in it.get("verdicts", {})}
        for key, item in items.items():
            if backend in item.get("verdicts", {}):
                continue
            same = judged.get(item.get("bundle_sha256"))
            if same is not None:  # identical evidence already judged: reuse instead of recomputing
                item.setdefault("verdicts", {})[backend] = {**same, "reused": True}
                item["status"] = "done"
                queue[key] = item
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
            queue[v.key] = _maybe_notify_candidate(v.key, item)
        return {"ok": True}

    return web


@app.local_entrypoint()
def main() -> None:
    print(poll_once.remote())
