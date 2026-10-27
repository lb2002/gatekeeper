"""OSV (api.osv.dev): MAL-* entries from the OpenSSF malicious-packages feed."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from gatekeeper.confirm import earliest

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAX_PAGES = 10


@dataclass(frozen=True)
class OsvHit:
    id: str
    first_public: str | None


def query(client: httpx.Client, name: str, version: str | None = None) -> list[dict]:
    """All OSV vulns for an npm package, following `next_page_token`."""
    body: dict = {"package": {"name": name, "ecosystem": "npm"}}
    if version:
        body["version"] = version
    vulns: list[dict] = []
    for _ in range(MAX_PAGES):
        resp = client.post(OSV_QUERY_URL, json=body)
        resp.raise_for_status()
        data = resp.json() or {}
        vulns.extend(data.get("vulns") or [])
        token = data.get("next_page_token")
        if not token:
            break
        body["page_token"] = token
    return vulns


def affects(vuln: dict, name: str, version: str) -> bool:
    """True if the entry lists `version`, or has no explicit versions for the package (all versions / ranges)."""
    affected = vuln.get("affected") or []
    if not affected:
        return True
    for entry in affected:
        pkg = entry.get("package") or {}
        if str(pkg.get("ecosystem", "")).lower() != "npm" or pkg.get("name") != name:
            continue
        versions = entry.get("versions")
        if not versions or version in versions:
            return True
    return False


def first_public(vuln: dict) -> str | None:
    """Earliest origin `import_time`; `published` is submitter-set (can be backdated) so it is only a fallback."""
    origins = (vuln.get("database_specific") or {}).get("malicious-packages-origins") or []
    imported = earliest(o.get("import_time") for o in origins if isinstance(o, dict))
    return imported or earliest([vuln.get("published")])


def malicious_hits(client: httpx.Client, name: str, version: str) -> list[OsvHit]:
    """MAL-* entries (not withdrawn) that affect this exact version."""
    return [
        OsvHit(v["id"], first_public(v))
        for v in query(client, name)
        if str(v.get("id", "")).startswith("MAL-") and not v.get("withdrawn") and affects(v, name, version)
    ]
