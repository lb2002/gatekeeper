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
from gatekeeper.npm.tarball import MAX_COMPRESSED_BYTES, ArchiveTooLarge, read_tarball
from gatekeeper.triage.content import Hit, score_content
from gatekeeper.triage.campaign import shared_files
from gatekeeper.triage.meta import score_metadata
from gatekeeper.triage.phantom import public_peer, unreadable_imports, url_dependencies, young_additions

RECENT_WINDOW = timedelta(hours=6)  # versions considered "new" for a changed package
NEW_PACKAGE_WINDOW = timedelta(hours=72)
SCAN_META_THRESHOLD = 2
MAX_VERSIONS_PER_NAME = 6
# Updates of small packages are scanned too: live recall showed malware pushed as an update of a
# young, little-used package (no install hook, so no metadata signal) went unscanned.
SMALL_PACKAGE_VERSIONS = 20
FLAG_CONTENT_THRESHOLD = 6
FLAG_TOTAL_THRESHOLD = 9
# A package younger than this that runs code at install time always goes to a model: live recall's real
# misses were all new packages with a postinstall hook scoring 4-7, below the rules threshold. It is
# only ~100-150 versions a day (~70 packages), a third of which the rules flag anyway.
NEW_PACKAGE_HOURS = 72


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
    publisher: str | None = None

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


URL_DOWNLOAD_S = 20


def download_capped(client: httpx.Client, url: str, limit: int = MAX_COMPRESSED_BYTES, public_only: bool = False) -> bytes:
    """Stream an archive and stop as soon as it exceeds `limit`: large binary packages would otherwise
    tie up a worker for the whole download only to be rejected afterwards. `public_only` is for URLs a package
    author chose: no redirects, a public address at the other end, and a limit on the time as well as the size."""
    started = time.monotonic()
    with client.stream("GET", url, follow_redirects=not public_only) as resp:
        if public_only and not public_peer(resp):
            raise OSError("not a public address")
        resp.raise_for_status()
        if int(resp.headers.get("content-length") or 0) > limit:
            raise ArchiveTooLarge(f"compressed size {resp.headers['content-length']} > {limit}")
        buf = bytearray()
        for chunk in resp.iter_bytes(64 * 1024):
            buf += chunk
            if len(buf) > limit:
                raise ArchiveTooLarge(f"compressed size > {limit}")
            if public_only and time.monotonic() - started > URL_DOWNLOAD_S:
                raise OSError("too slow")
    return bytes(buf)


CAMPAIGN_TEXT_CAP = 2_000_000


def campaign_matches(pkg, campaign: dict[str, str] | None) -> list[tuple[str, str]]:
    """Known campaign endpoints anywhere in the package's text files (first 2 MB)."""
    if not campaign:
        return []
    from gatekeeper.triage.campaign import matches

    parts, size = [], 0
    for path in sorted(pkg.files):
        data = pkg.files[path]
        if size >= CAMPAIGN_TEXT_CAP:
            break
        parts.append(data[: CAMPAIGN_TEXT_CAP - size].decode("utf-8", errors="replace"))
        size += len(data)
    return matches("\n".join(parts), campaign)


def process_version(
    client: httpx.Client, info: packument.VersionInfo, popular: set[str], now: datetime,
    fast: FastScorer | None = None,
    mal_index: dict[str, dict] | None = None,
    scan: bool = True,
    campaign: dict[str, str] | None = None,
    publishers: dict[str, str] | None = None,
    known_files: dict[str, str] | None = None,
) -> Record:
    meta = score_metadata(info, popular, now=now, mal_index=mal_index)
    rec = Record(
        name=info.name,
        version=info.version,
        published_at=info.published_at.isoformat() if info.published_at else None,
        seen_at=now.isoformat(),
        meta_score=meta.score,
        meta_reasons=meta.reasons,
        publisher=info.publisher,
    )
    # an npm account that already published a package the models agree is malicious: always look closely
    known_account = (publishers or {}).get(info.publisher or "")
    if known_account:
        meta.reasons.append(f"+10 published by {info.publisher}, who also published {known_account}")
    # an update that pulls in a brand-new package: the shape of a hijacked release
    fresh = young_additions(client, info, now, popular)  # also past the per-name cap: the publisher chooses the order
    if fresh:
        dep, hours = fresh[0]
        meta.reasons.append(f"+10 this update adds {dep}, " + ("which is not on the public registry" if hours is None
                                                                else f"a package created {hours:.0f} hours ago"))
    # code from a URL, in a package small enough that nobody would notice: hs-framework is one log line around such a dependency
    small = info.version_count is not None and info.version_count <= SMALL_PACKAGE_VERSIONS and info.name not in popular
    remote = url_dependencies(info.dependencies) if small else []
    if remote:
        meta.reasons.append(f"+10 installs {remote[0][0]} from {remote[0][1][:80]}, outside the registry")
    # past the per-name cap only a strong metadata signal (e.g. a known-malicious dependency) earns a download
    if not scan and meta.score < FLAG_TOTAL_THRESHOLD and not known_account and not fresh and not remote:
        return rec
    if not info.tarball_url or not (should_scan(info, meta.score, popular, now) or known_account or fresh or remote):
        return rec
    try:
        pkg = read_tarball(download_capped(client, info.tarball_url))
    except (httpx.HTTPError, ArchiveTooLarge, OSError, EOFError) as exc:
        rec.error = f"archive: {type(exc).__name__}: {exc}"[:300]
        return rec
    except Exception as exc:  # malformed archives must never stop the monitor
        rec.error = f"archive: {type(exc).__name__}"[:300]
        return rec
    content = score_content(pkg)
    # code that loads a package nobody can read: the payload stays out of every scanner's sight
    hidden = unreadable_imports(client, pkg, info.name, popular, info.dependencies)
    for dep, (path, line, text) in hidden:
        content.hits.append(Hit("private_dependency", path, line, text))
        meta.reasons.append(f"+10 loads {dep}, which does not exist on the public registry")
    # a file identical to one in a reported package: a re-upload, however clean it looks
    copied = shared_files(pkg, known_files or {})
    if copied:
        meta.reasons.append(f"+10 {copied[0][0]} is identical to a file of {copied[0][1]}")
    # an exfiltration endpoint a malicious package used before (see triage/campaign.py)
    shared = campaign_matches(pkg, campaign)
    if shared:
        meta.reasons.append(f"+10 sends to {shared[0][0]}, the endpoint of {shared[0][1]}")
    rec.scanned = True
    rec.content_score = content.score
    rec.rules = sorted(content.rules | ({"known_campaign_endpoint"} if shared else set())
                       | ({"known_bad_publisher"} if known_account else set()) | ({"known_bad_file"} if copied else set())
                       | ({"fresh_dependency"} if fresh else set()) | ({"url_dependency"} if remote else set()))
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
    young = info.package_created_at is not None and now - info.package_created_at <= timedelta(hours=NEW_PACKAGE_HOURS)
    new_with_hook = young and bool(info.install_scripts or info.gypfile)
    rec.flagged = rules_flag or fast_flag or new_with_hook or any((shared, known_account, hidden, copied, fresh, remote))
    rec.priority += 10 * sum(map(bool, (shared, known_account, hidden, copied, fresh, remote)))
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
    campaign: dict[str, str] | None = None,
    publishers: dict[str, str] | None = None,
    known_files: dict[str, str] | None = None,
    before: datetime | None = None,
) -> tuple[list[Record], list[str]]:
    """Score every version of the changed packages published within `window`, unless already seen.

    With a `deadline` (time.monotonic()), names not finished by then are returned as deferred
    instead of blocking, so a scheduled run never overruns its timeout. `before` leaves out later versions."""
    now = now or datetime.now(timezone.utc)

    def one(name: str) -> tuple[list[Record], bool] | None:
        if deadline is not None and time.monotonic() > deadline:
            return None
        try:
            doc = packument.fetch_packument(client, name)
        except Exception as exc:
            return [Record(name, "?", None, now.isoformat(), 0, [], error=f"packument: {type(exc).__name__}")], False
        if not doc:
            return [], False
        todo = [v for v in packument.recent_versions(doc, window, now=now)
                if not v.is_npm_placeholder and f"{v.name}@{v.version}" not in seen
                and (before is None or (v.published_at is not None and v.published_at < before))]
        # Newest first, and only a few per name: a package that pushed 190 versions in a day (CI canaries,
        # spam) otherwise ties up a worker for minutes. Malware rarely comes as more than a handful.
        # Versions past the cap still get the metadata check (install hooks, dependencies), just no download.
        todo.sort(key=lambda v: v.published_at or now, reverse=True)
        out = []
        for i, info in enumerate(todo):
            if out and deadline is not None and time.monotonic() > deadline:
                return out, True  # unfinished: the name is deferred, `seen` skips what is done
            out.append(process_version(client, info, popular, now, fast, mal_index, scan=i < MAX_VERSIONS_PER_NAME,
                                       campaign=campaign, publishers=publishers, known_files=known_files))
        return out, False

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
        res = fut.result() if fut in done else None
        if res is None:
            deferred.append(name)
        else:
            records.extend(res[0])
            if res[1]:
                deferred.append(name)
    return records, deferred
