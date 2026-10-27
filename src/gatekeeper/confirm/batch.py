"""Check many flagged versions at once: OSV and npm takedown per package, GitHub advisories in bulk."""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from gatekeeper.confirm import earliest, to_iso
from gatekeeper.confirm.ghsa import GhsaResult, recent_malware
from gatekeeper.confirm.osv import malicious_hits
from gatekeeper.confirm.takedown import check_takedown
from gatekeeper.confirm.tracker import Confirmation


def confirm_many(
    client: httpx.Client,
    keys: list[tuple[str, str]],
    ghsa_since: str,
    now: datetime | None = None,
) -> tuple[list[Confirmation], str | None]:
    """`keys` are (name, version) pairs. Returns confirmations and a GitHub error, if any."""
    now = now or datetime.now(timezone.utc)
    ghsa_by_name, ghsa_error = recent_malware(client, ghsa_since)
    out: list[Confirmation] = []
    for name, version in keys:
        c = Confirmation(name=name, version=version, checked_at=to_iso(now))
        try:
            hits = malicious_hits(client, name, version)
            c.osv_ids = [h.id for h in hits]
            c.osv_first_public = earliest(h.first_public for h in hits)
        except Exception as exc:
            c.errors.append(f"osv: {type(exc).__name__}")
        g = ghsa_by_name.get(name, GhsaResult())
        c.ghsa_ids, c.ghsa_published_at = g.ids, g.published_at
        try:
            t = check_takedown(client, name, version)
            c.npm_takedown_at, c.version_removed = t.takedown_at, t.version_removed
        except Exception as exc:
            c.errors.append(f"npm: {type(exc).__name__}")
        out.append(c)
    return out, ghsa_error
