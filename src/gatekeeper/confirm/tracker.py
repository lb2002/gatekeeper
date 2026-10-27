"""Combine OSV, GHSA and npm takedown signals into one Confirmation per flagged version."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import httpx

from gatekeeper.confirm import earliest, parse_ts, to_iso
from gatekeeper.confirm.ghsa import malware_advisories
from gatekeeper.confirm.osv import malicious_hits
from gatekeeper.confirm.takedown import check_takedown


@dataclass
class Confirmation:
    name: str
    version: str
    checked_at: str
    osv_ids: list[str] = field(default_factory=list)
    osv_first_public: str | None = None
    ghsa_ids: list[str] = field(default_factory=list)
    ghsa_published_at: str | None = None
    npm_takedown_at: str | None = None
    version_removed: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        # version_removed alone does not count: authors unpublish for all sorts of reasons.
        return bool(self.osv_ids or self.ghsa_ids or self.npm_takedown_at)

    @property
    def earliest_public(self) -> str | None:
        return earliest([self.osv_first_public, self.ghsa_published_at, self.npm_takedown_at])

    def as_dict(self) -> dict:
        return {**asdict(self), "confirmed": self.confirmed, "earliest_public": self.earliest_public}


def check(
    client: httpx.Client,
    name: str,
    version: str,
    github_token: str | None = None,
    now: datetime | None = None,
) -> Confirmation:
    """Query all three sources; a failing source is recorded in `errors` and never raises."""
    conf = Confirmation(name, version, to_iso(now or datetime.now(timezone.utc)))
    try:
        hits = malicious_hits(client, name, version)
        conf.osv_ids = [h.id for h in hits]
        conf.osv_first_public = earliest(h.first_public for h in hits)
    except Exception as exc:  # noqa: BLE001 - one source must not break the others
        conf.errors.append(f"osv: {exc!r}")
    try:
        ghsa = malware_advisories(client, name, github_token)
        conf.ghsa_ids, conf.ghsa_published_at = ghsa.ids, ghsa.published_at
        if ghsa.error:
            conf.errors.append(f"ghsa: {ghsa.error}")
    except Exception as exc:  # noqa: BLE001
        conf.errors.append(f"ghsa: {exc!r}")
    try:
        td = check_takedown(client, name, version)
        conf.npm_takedown_at, conf.version_removed = td.takedown_at, td.version_removed
    except Exception as exc:  # noqa: BLE001
        conf.errors.append(f"npm: {exc!r}")
    return conf


def _minutes(start: str | None, end: str | None) -> float | None:
    a, b = parse_ts(start), parse_ts(end)
    return None if a is None or b is None else (b - a).total_seconds() / 60


def publish_to_flag_minutes(published_at: str | None, flagged_at: str) -> float | None:
    """Minutes from npm publish to our flag (detection latency)."""
    return _minutes(published_at, flagged_at)


def flag_lead_minutes(flagged_at: str, earliest_public: str | None) -> float | None:
    """Minutes our flag preceded the earliest public report; positive = we were first."""
    return _minutes(flagged_at, earliest_public)
