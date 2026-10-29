"""One monitoring step: registry changes -> metadata triage -> in-memory archive scan -> flagged bundles.

Runs inside a Modal container. Archives are read in memory only and never executed.
"""

from __future__ import annotations

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, field
from typing import Callable
from datetime import datetime, timedelta, timezone

import httpx

from gatekeeper.evidence.bundle import build_bundle
from gatekeeper.npm import packument
from gatekeeper.npm.tarball import ArchiveTooLarge, read_tarball
from gatekeeper.triage.content import score_content
from gatekeeper.triage.meta import score_metadata

RECENT_WINDOW = timedelta(hours=6)  # versions considered "new" for a changed package
NEW_PACKAGE_WINDOW = timedelta(hours=72)
SCAN_META_THRESHOLD = 2
# Updates of small packages are scanned too: live recall showed malware pushed as an update of a
# young, little-used package (no install hook, so no metadata signal) went unscanned.
SMALL_PACKAGE_VERSIONS = 20
FLAG_CONTENT_THRESHOLD = 6
FLAG_TOTAL_THRESHOLD = 9


@dataclass
class Record:
    name: str
    version: str
    published_at: str | None
    seen_at: str
    meta_score: int
    meta_reasons: list[str]
    scanned: bool = False
    content_score: int = 0
    rules: list[str] = field(default_factory=list)
    flagged: bool = False
    priority: int = 0
    bundle: str | None = None
    bundle_sha256: str | None = None
    excerpts: list[dict] | None = None
    fast_risk: float | None = None
    error: str | None = None

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"

    def to_json(self) -> dict:
        return asdict(self)


def should_scan(info: packument.VersionInfo, meta_score: int, popular: set[str], now: datetime) -> bool:
    is_new_package = info.package_created_at is not None and now - info.package_created_at <= NEW_PACKAGE_WINDOW
    is_small = info.version_count is not None and info.version_count <= SMALL_PACKAGE_VERSIONS
    return is_new_package or is_small or meta_score >= SCAN_META_THRESHOLD or info.name in popular


# (name, version, bundle text, rules) -> (risk in [0, 1], flag?) from the fast first-stage classifier
FastScorer = Callable[[str, str, str, list[str]], tuple[float, bool]]


def process_version(
    client: httpx.Client, info: packument.VersionInfo, popular: set[str], now: datetime,
    fast: FastScorer | None = None,
    mal_index: dict[str, dict] | None = None,
) -> Record:
    meta = score_metadata(info, popular, now=now, mal_index=mal_index)
    rec = Record(
        name=info.name,
        version=info.version,
        published_at=info.published_at.isoformat() if info.published_at else None,
        seen_at=now.isoformat(),
        meta_score=meta.score,
        meta_reasons=meta.reasons,
    )
    if not info.tarball_url or not should_scan(info, meta.score, popular, now):
        return rec
    try:
        resp = client.get(info.tarball_url)
        resp.raise_for_status()
        pkg = read_tarball(resp.content)
    except (httpx.HTTPError, ArchiveTooLarge, OSError, EOFError) as exc:
        rec.error = f"archive: {type(exc).__name__}: {exc}"[:300]
        return rec
    except Exception as exc:  # malformed archives must never stop the monitor
        rec.error = f"archive: {type(exc).__name__}"[:300]
        return rec
    content = score_content(pkg)
    rec.scanned = True
    rec.content_score = content.score
    rec.rules = sorted(content.rules)
    rec.priority = meta.score + content.score
    rules_flag = content.score >= FLAG_CONTENT_THRESHOLD or rec.priority >= FLAG_TOTAL_THRESHOLD
    fast_flag = False
    if fast is not None:
        # scored on the bundle without metadata notes, the format the classifier was trained on
        plain = build_bundle(info.name, info.version, pkg, content).render()
        rec.fast_risk, fast_flag = fast(info.name, info.version, plain, rec.rules)
        rec.priority += round(10 * rec.fast_risk)  # ordering only; the flag decision is made above
    # Every scanned version keeps its bundle: flagged ones go to the queue, the rest to the batched
    # Llama Guard pass, which catches malware the rules and the classifier both miss.
    bundle = build_bundle(info.name, info.version, pkg, content, meta_reasons=meta.reasons)
    text = bundle.render()
    rec.flagged = rules_flag or fast_flag
    rec.bundle = text
    rec.bundle_sha256 = hashlib.sha256(text.encode()).hexdigest()
    rec.excerpts = [e.ref() for e in bundle.excerpts]
    return rec


def process_names(
    client: httpx.Client,
    names: list[str],
    popular: set[str],
    seen: set[str],
    now: datetime | None = None,
    workers: int = 16,
    window: timedelta = RECENT_WINDOW,
    deadline: float | None = None,
    fast: FastScorer | None = None,
    mal_index: dict[str, dict] | None = None,
) -> tuple[list[Record], list[str]]:
    """Score every version of the changed packages published within `window`, unless already seen.

    With a `deadline` (time.monotonic()), names not finished by then are returned as deferred
    instead of blocking, so a scheduled run never overruns its timeout."""
    now = now or datetime.now(timezone.utc)

    def one(name: str) -> list[Record] | None:
        if deadline is not None and time.monotonic() > deadline:
            return None
        try:
            doc = packument.fetch_packument(client, name)
        except Exception as exc:
            return [Record(name, "?", None, now.isoformat(), 0, [], error=f"packument: {type(exc).__name__}")]
        if not doc:
            return []
        out = []
        for info in packument.recent_versions(doc, window, now=now):
            if info.is_security_holder or f"{info.name}@{info.version}" in seen:
                continue
            out.append(process_version(client, info, popular, now, fast, mal_index))
        return out

    pool = ThreadPoolExecutor(max_workers=workers)
    futures = {pool.submit(one, n): n for n in names}
    remaining = None if deadline is None else max(0.0, deadline - time.monotonic()) + 5
    done, _ = wait(futures, timeout=remaining)
    pool.shutdown(wait=False, cancel_futures=True)  # stragglers are abandoned and retried next run
    records: list[Record] = []
    deferred: list[str] = []
    for fut, name in futures.items():
        if fut in done and fut.exception() is not None:
            exc = fut.exception()
            records.append(Record(name, "?", None, now.isoformat(), 0, [], error=f"process: {type(exc).__name__}"))
            continue
        rs = fut.result() if fut in done else None
        if rs is None:
            deferred.append(name)
        else:
            records.extend(rs)
    return records, deferred
