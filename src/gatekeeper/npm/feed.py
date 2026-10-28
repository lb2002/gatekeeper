"""Follow new npm registry changes through the replication `_changes` endpoint.

Since May 2025 the endpoint only returns `{seq, id}` per change (no documents, no continuous feed),
so we poll with `since=<seq>` and fetch each packument separately.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

REPLICATE_URL = "https://replicate.npmjs.com/registry"
USER_AGENT = "gatekeeper-monitor/0.1 (+https://github.com/lb2002)"


@dataclass(frozen=True)
class Change:
    seq: int
    name: str
    deleted: bool = False


def make_client(timeout: float = 30.0) -> httpx.Client:
    return httpx.Client(timeout=timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=True)


def current_seq(client: httpx.Client, retries: int = 3) -> int:
    for attempt in range(retries):
        try:
            resp = client.get(f"{REPLICATE_URL}/")
            resp.raise_for_status()
            return int(resp.json()["update_seq"])
        except (httpx.HTTPError, ValueError, KeyError):  # resets and 5xx happen a few times a day
            if attempt == retries - 1:
                raise
            time.sleep(1 + attempt)
    raise AssertionError("unreachable")


def fetch_changes(
    client: httpx.Client, since: int, limit: int = 1000, retries: int = 4, deadline: float | None = None
) -> tuple[list[Change], int]:
    """Return the changes after `since` and the sequence number to continue from.

    Large limits are known to time out (504), so we back off and shrink the page on errors.
    With a `deadline` (time.monotonic()), no retry starts after it; the caller continues next run.
    """
    page = limit
    for attempt in range(retries):
        if attempt and deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("feed retries ran past the run budget")
        try:
            resp = client.get(f"{REPLICATE_URL}/_changes", params={"since": since, "limit": page})
            resp.raise_for_status()
            data = resp.json()
            changes = [
                Change(seq=int(r["seq"]), name=r["id"], deleted=bool(r.get("deleted", False)))
                for r in data.get("results", [])
                if not r["id"].startswith("_design/")
            ]
            last_seq = int(data.get("last_seq", since)) if data.get("results") else since
            return changes, last_seq
        except (httpx.HTTPError, ValueError, KeyError):
            if attempt == retries - 1:
                raise
            page = max(100, page // 2)
            time.sleep(2**attempt)
    return [], since
