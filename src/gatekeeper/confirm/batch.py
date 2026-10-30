"""Check many flagged versions at once: OSV and npm takedown per package, GitHub advisories in bulk."""

from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone

import httpx

from gatekeeper.confirm import earliest, to_iso
from gatekeeper.confirm.ghsa import GhsaResult, recent_malware
from gatekeeper.confirm.osv import hits_in, query, report_commit_time
from gatekeeper.confirm.takedown import takedown_info, takedown_for
from gatekeeper.confirm.tracker import Confirmation


def confirm_many(
    client: httpx.Client,
    keys: list[tuple[str, str]],
    ghsa_since: str,
    now: datetime | None = None,
    github_token: str | None = None,
    workers: int = 16,
) -> tuple[list[Confirmation], str | None]:
    """`keys` are (name, version) pairs. Returns confirmations and a GitHub error, if any."""
    now = now or datetime.now(timezone.utc)
    ghsa_by_name, ghsa_error = recent_malware(client, ghsa_since)
    # OSV, the npm packument and the OpenSSF commit time depend on the package name only, and the queue holds
    # many versions of one name (CI snapshots, a campaign's re-uploads): each is fetched once per batch.
    cache: dict[tuple[str, str], Future] = {}
    lock = threading.Lock()

    def once(kind: str, name: str, fetch):
        with lock:
            fut = cache.get((kind, name))
            owner = fut is None
            if owner:
                fut = cache[(kind, name)] = Future()
        if owner:
            try:
                fut.set_result(fetch())
            except Exception as exc:
                fut.set_exception(exc)
        return fut.result()

    def one(key: tuple[str, str]) -> Confirmation:
        name, version = key
        c = Confirmation(name=name, version=version, checked_at=to_iso(now))
        try:
            vulns = once("osv", name, lambda: query(client, name))
            hits = hits_in(vulns, name, version)
            c.osv_ids = [h.id for h in hits]
            c.osv_first_public = earliest(h.first_public for h in hits)
            if hits and c.osv_first_public is None:
                c.osv_first_public = once("ossf", name, lambda: report_commit_time(client, name, github_token))
        except Exception as exc:
            c.errors.append(f"osv: {type(exc).__name__}")
        g = ghsa_by_name.get(name, GhsaResult())
        c.ghsa_ids, c.ghsa_published_at = g.ids, g.published_at
        try:
            t = takedown_for(once("npm", name, lambda: takedown_info(client, name)), version)
            c.npm_takedown_at, c.version_removed = t.takedown_at, t.version_removed
        except Exception as exc:
            c.errors.append(f"npm: {type(exc).__name__}")
        return c

    # Sequentially this took ~0.6 s per flag and ran into the hourly job's timeout at ~1,400 flags.
    with ThreadPoolExecutor(max_workers=workers) as ex:
        out = list(ex.map(one, keys))
    return out, ghsa_error
