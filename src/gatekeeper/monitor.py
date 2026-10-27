"""One monitoring step: registry changes -> metadata triage -> in-memory archive scan -> flagged bundles.

Runs inside a Modal container. Archives are read in memory only and never executed.
"""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
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
    error: str | None = None

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"

    def to_json(self) -> dict:
        return asdict(self)


def should_scan(info: packument.VersionInfo, meta_score: int, popular: set[str], now: datetime) -> bool:
    is_new_package = info.package_created_at is not None and now - info.package_created_at <= NEW_PACKAGE_WINDOW
    return is_new_package or meta_score >= SCAN_META_THRESHOLD or info.name in popular


def process_version(
    client: httpx.Client, info: packument.VersionInfo, popular: set[str], now: datetime
) -> Record:
    meta = score_metadata(info, popular, now=now)
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
    if content.score >= FLAG_CONTENT_THRESHOLD or rec.priority >= FLAG_TOTAL_THRESHOLD:
        bundle = build_bundle(info.name, info.version, pkg, content, meta_reasons=meta.reasons)
        text = bundle.render()
        rec.flagged = True
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
) -> list[Record]:
    """Score every version of the changed packages published within `window`, unless already seen."""
    now = now or datetime.now(timezone.utc)

    def one(name: str) -> list[Record]:
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
            out.append(process_version(client, info, popular, now))
        return out

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return [r for rs in pool.map(one, names) for r in rs]
