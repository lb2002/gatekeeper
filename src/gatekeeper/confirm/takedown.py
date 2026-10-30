"""npm security takedowns: removed malware is replaced by a `0.0.1-security` placeholder."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from gatekeeper.confirm import earliest
from gatekeeper.npm.packument import SECURITY_HOLDER_VERSION, fetch_packument, packument_url


@dataclass(frozen=True)
class Takedown:
    takedown_at: str | None = None
    version_removed: bool = False


def from_packument(packument: dict | None, version: str) -> Takedown:
    """Placeholder publish time = takedown time; a version in `time` but not `versions` was removed."""
    if not packument:
        return Takedown()
    times = packument.get("time") or {}
    versions = packument.get("versions") or {}
    return Takedown(
        takedown_at=earliest([times.get(SECURITY_HOLDER_VERSION)]),
        version_removed=version in times and version not in versions,
    )


ABBREVIATED = {"Accept": "application/vnd.npm.install-v1+json"}


def takedown_info(client: httpx.Client, name: str) -> tuple[dict | None, dict | None]:
    """(versions from the abbreviated packument, full packument if npm's security holder is there). The
    abbreviated document is a fraction of the size but has no `time`, which only the takedown date needs.
    Depends on the name only, so a batch fetches it once per package."""
    resp = client.get(packument_url(name), headers=ABBREVIATED)
    if resp.status_code == 404:
        return None, None
    resp.raise_for_status()
    versions = resp.json().get("versions") or {}
    return versions, (fetch_packument(client, name) if SECURITY_HOLDER_VERSION in versions else None)


def takedown_for(info: tuple[dict | None, dict | None], version: str) -> Takedown:
    versions, full = info
    if versions is None:
        return Takedown()
    if full is not None:
        return from_packument(full, version)
    return Takedown(version_removed=version not in versions)


def check_takedown(client: httpx.Client, name: str, version: str) -> Takedown:
    return takedown_for(takedown_info(client, name), version)
