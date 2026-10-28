"""Public detection ledger: provable flag times without naming anyone early.

For every flag we publish only a commitment, sha256(salt || canonical line), where the line holds
the package, version, flag time and verdict. The secret per-flag salt stays private until the
detection is independently confirmed; publishing it then lets anyone recompute the hash and check
that the commit containing it is older than every public report. Unconfirmed flags are never named.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets

import httpx

LEDGER_REPO = "lb2002/gatekeeper-ledger"


def canonical_line(name: str, version: str, flagged_at: str, verdict: str | None) -> str:
    return json.dumps({"package": name, "version": version, "flagged_at": flagged_at, "verdict": verdict},
                      sort_keys=True, separators=(",", ":"))


def new_salt() -> str:
    return secrets.token_hex(16)


def commitment(salt: str, line: str) -> str:
    return hashlib.sha256(bytes.fromhex(salt) + line.encode()).hexdigest()


def verify(salt: str, line: str, digest: str) -> bool:
    return commitment(salt, line) == digest


def append_file(token: str, path: str, text: str, message: str, repo: str = LEDGER_REPO) -> str:
    """Append `text` to a file in the ledger repo through the GitHub contents API; returns the commit sha."""
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    with httpx.Client(timeout=30, headers=headers) as client:
        resp = client.get(url)
        sha, old = None, ""
        if resp.status_code == 200:
            body = resp.json()
            sha, old = body["sha"], base64.b64decode(body["content"]).decode()
        elif resp.status_code != 404:
            resp.raise_for_status()
        payload = {"message": message, "content": base64.b64encode((old + text).encode()).decode()}
        if sha:
            payload["sha"] = sha
        put = client.put(url, json=payload)
        put.raise_for_status()
        return put.json()["commit"]["sha"]
