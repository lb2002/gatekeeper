"""Fetch npm packuments and turn them into the per-version facts that triage needs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx

REGISTRY_URL = "https://registry.npmjs.org"
INSTALL_HOOKS = ("preinstall", "install", "postinstall")
SECURITY_HOLDER_VERSION = "0.0.1-security"


@dataclass
class VersionInfo:
    name: str
    version: str
    published_at: datetime | None
    package_created_at: datetime | None
    install_scripts: dict[str, str] = field(default_factory=dict)
    gypfile: bool = False
    bin: dict[str, str] = field(default_factory=dict)
    has_repository: bool = False
    maintainers: list[str] = field(default_factory=list)
    publisher: str | None = None
    tarball_url: str | None = None
    integrity: str | None = None
    unpacked_size: int | None = None
    file_count: int | None = None
    dependencies: dict[str, str] = field(default_factory=dict)
    previous_version: str | None = None
    previous_install_scripts: dict[str, str] = field(default_factory=dict)
    previous_publisher: str | None = None
    previous_maintainers: list[str] = field(default_factory=list)

    @property
    def is_security_holder(self) -> bool:
        return self.version == SECURITY_HOLDER_VERSION

    @property
    def install_hook_added(self) -> bool:
        return bool(self.install_scripts) and not self.previous_install_scripts and self.previous_version is not None


def packument_url(name: str) -> str:
    # Scoped names keep the leading '@' but escape the slash.
    return f"{REGISTRY_URL}/{quote(name, safe='@')}"


def fetch_packument(client: httpx.Client, name: str) -> dict | None:
    resp = client.get(packument_url(name))
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _people(entries: object) -> list[str]:
    out: list[str] = []
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and entry.get("name"):
                out.append(str(entry["name"]))
            elif isinstance(entry, str):
                out.append(entry)
    return out


def _bin(manifest: dict) -> dict[str, str]:
    raw = manifest.get("bin")
    if isinstance(raw, str):
        return {manifest.get("name", "").split("/")[-1]: raw}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    return {}


def _hooks(manifest: dict) -> dict[str, str]:
    scripts = manifest.get("scripts") or {}
    if not isinstance(scripts, dict):
        return {}
    return {k: str(scripts[k]) for k in INSTALL_HOOKS if k in scripts}


def versions_by_time(packument: dict) -> list[tuple[str, datetime]]:
    times = packument.get("time") or {}
    versions = packument.get("versions") or {}
    out = []
    for ver in versions:
        ts = _parse_time(times.get(ver))
        if ts is not None:
            out.append((ver, ts))
    out.sort(key=lambda item: item[1])
    return out


def version_info(packument: dict, version: str) -> VersionInfo:
    name = packument.get("name", "")
    manifest = (packument.get("versions") or {}).get(version, {})
    times = packument.get("time") or {}
    ordered = versions_by_time(packument)
    previous = None
    for i, (ver, _) in enumerate(ordered):
        if ver == version and i > 0:
            previous = ordered[i - 1][0]
    prev_manifest = (packument.get("versions") or {}).get(previous, {}) if previous else {}
    dist = manifest.get("dist") or {}
    npm_user = manifest.get("_npmUser") or {}
    prev_user = prev_manifest.get("_npmUser") or {}
    return VersionInfo(
        name=name,
        version=version,
        published_at=_parse_time(times.get(version)),
        package_created_at=_parse_time(times.get("created")),
        install_scripts=_hooks(manifest),
        gypfile=bool(manifest.get("gypfile")),
        bin=_bin(manifest),
        has_repository=bool(manifest.get("repository")),
        maintainers=_people(manifest.get("maintainers")),
        publisher=npm_user.get("name") if isinstance(npm_user, dict) else None,
        tarball_url=dist.get("tarball"),
        integrity=dist.get("integrity"),
        unpacked_size=dist.get("unpackedSize"),
        file_count=dist.get("fileCount"),
        dependencies={str(k): str(v) for k, v in (manifest.get("dependencies") or {}).items()},
        previous_version=previous,
        previous_install_scripts=_hooks(prev_manifest),
        previous_publisher=prev_user.get("name") if isinstance(prev_user, dict) else None,
        previous_maintainers=_people(prev_manifest.get("maintainers")),
    )


def recent_versions(packument: dict, window: timedelta, now: datetime | None = None) -> list[VersionInfo]:
    """Versions published within `window` before `now` (the releases a change most likely refers to)."""
    now = now or datetime.now(timezone.utc)
    return [
        version_info(packument, ver)
        for ver, ts in versions_by_time(packument)
        if now - ts <= window
    ]
