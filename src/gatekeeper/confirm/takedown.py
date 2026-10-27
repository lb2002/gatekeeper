"""npm security takedowns: removed malware is replaced by a `0.0.1-security` placeholder."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from gatekeeper.confirm import earliest
from gatekeeper.npm.packument import SECURITY_HOLDER_VERSION, fetch_packument


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


def check_takedown(client: httpx.Client, name: str, version: str) -> Takedown:
    return from_packument(fetch_packument(client, name), version)
