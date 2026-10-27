"""GitHub Advisory Database: reviewed malware advisories (only returned with type=malware).

Malware advisories almost always use the range ">= 0", so any malware advisory on the package
counts as confirming the flagged version; we deliberately do not evaluate version ranges.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx

from gatekeeper.confirm import earliest

GHSA_URL = "https://api.github.com/advisories"
MAX_PAGES = 5


@dataclass
class GhsaResult:
    ids: list[str] = field(default_factory=list)
    published_at: str | None = None
    error: str | None = None


def headers(token: str | None = None) -> dict[str, str]:
    out = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = token or os.environ.get("GITHUB_TOKEN")
    if token:
        out["Authorization"] = f"Bearer {token}"
    return out


def _names_package(advisory: dict, name: str) -> bool:
    for vuln in advisory.get("vulnerabilities") or []:
        pkg = vuln.get("package") or {}
        if str(pkg.get("ecosystem", "")).lower() == "npm" and pkg.get("name") == name:
            return True
    return False


def recent_malware(
    client: httpx.Client, since: str, token: str | None = None, max_pages: int = 10
) -> tuple[dict[str, GhsaResult], str | None]:
    """All npm malware advisories published after `since` (ISO), grouped by package name.

    One bulk listing per run instead of one request per flagged package keeps us far below the
    60 requests/hour that the unauthenticated GitHub API allows.
    """
    from gatekeeper.confirm import parse_ts

    cutoff = parse_ts(since)
    url: str | None = GHSA_URL
    params: dict | None = {"type": "malware", "ecosystem": "npm", "per_page": 100, "sort": "published", "direction": "desc"}
    by_name: dict[str, GhsaResult] = {}
    error = None
    for _ in range(max_pages):
        resp = client.get(url, params=params, headers=headers(token))
        if resp.status_code in (403, 429) or resp.status_code >= 400:
            error = f"github advisories HTTP {resp.status_code}"
            break
        page = [a for a in resp.json() or [] if isinstance(a, dict)]
        done = False
        for adv in page:
            published = parse_ts(adv.get("published_at"))
            if cutoff and published and published < cutoff:
                done = True
                continue
            if adv.get("withdrawn_at"):
                continue
            for vuln in adv.get("vulnerabilities") or []:
                pkg = vuln.get("package") or {}
                if str(pkg.get("ecosystem", "")).lower() != "npm" or not pkg.get("name"):
                    continue
                res = by_name.setdefault(pkg["name"], GhsaResult())
                if adv.get("ghsa_id") and adv["ghsa_id"] not in res.ids:
                    res.ids.append(adv["ghsa_id"])
                res.published_at = earliest([res.published_at, adv.get("published_at")])
        url = resp.links.get("next", {}).get("url")
        if done or not url:
            break
        params = None
    return by_name, error


def malware_advisories(client: httpx.Client, name: str, token: str | None = None) -> GhsaResult:
    """Malware advisories for an npm package. Rate limits and HTTP errors go to `error`, never raised."""
    url: str | None = GHSA_URL
    params: dict | None = {"type": "malware", "ecosystem": "npm", "affects": name, "per_page": 100}
    advisories: list[dict] = []
    error = None
    for _ in range(MAX_PAGES):
        resp = client.get(url, params=params, headers=headers(token))
        if resp.status_code in (403, 429):
            reset = resp.headers.get("x-ratelimit-reset") or resp.headers.get("retry-after")
            error = f"github rate limited ({resp.status_code})" + (f", reset {reset}" if reset else "")
            break
        if resp.status_code >= 400:
            error = f"github advisories HTTP {resp.status_code}"
            break
        advisories.extend(a for a in resp.json() or [] if isinstance(a, dict))
        url = resp.links.get("next", {}).get("url")
        if not url:
            break
        params = None  # the cursor URL already carries the full query
    hits = [a for a in advisories if not a.get("withdrawn_at") and _names_package(a, name)]
    return GhsaResult(
        ids=[a["ghsa_id"] for a in hits if a.get("ghsa_id")],
        published_at=earliest(a.get("published_at") for a in hits),
        error=error,
    )
