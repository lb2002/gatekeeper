"""Public detection ledger: provable flag times without naming anyone early.

For every flag we publish only a commitment, sha256(salt || canonical line), where the line holds
the package, version, flag time and verdict. The secret per-flag salt stays private until the
detection is independently confirmed; publishing it then lets anyone recompute the hash and check
that it existed before every public report. Unconfirmed flags are never named.

Git commit dates are self-asserted, so each batch file is also timestamped with OpenTimestamps
(anchored in Bitcoin by public calendar servers): `ots verify <batch>.txt.ots` proves the batch
existed at that time independently of us and of GitHub.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets

import httpx

LEDGER_REPO = "lb2002/gatekeeper-ledger"
OTS_CALENDARS = (
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
)
# OpenTimestamps detached-proof header (magic, version 1) followed by the file hash op (0x08 = sha256)
OTS_HEADER = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94" + b"\x01" + b"\x08"


def ots_stamp(data: bytes, calendars: tuple[str, ...] = OTS_CALENDARS, timeout: float = 20) -> bytes:
    """A pending OpenTimestamps proof (.ots file) for `data`, from the first calendar that answers.
    `ots upgrade` later completes it with the Bitcoin attestation; `ots verify` checks it."""
    digest = hashlib.sha256(data).digest()
    errors = []
    for url in calendars:
        try:
            resp = httpx.post(f"{url}/digest", content=digest, timeout=timeout,
                              headers={"Accept": "application/vnd.opentimestamps.v1", "User-Agent": "gatekeeper-ledger"})
            resp.raise_for_status()
            return OTS_HEADER + digest + resp.content
        except httpx.HTTPError as exc:
            errors.append(f"{url}: {type(exc).__name__}")
    raise RuntimeError("no OpenTimestamps calendar answered: " + "; ".join(errors))


def canonical_line(name: str, version: str, flagged_at: str, verdict: str | None) -> str:
    return json.dumps({"package": name, "version": version, "flagged_at": flagged_at, "verdict": verdict},
                      sort_keys=True, separators=(",", ":"))


def new_salt() -> str:
    return secrets.token_hex(16)


def commitment(salt: str, line: str) -> str:
    return hashlib.sha256(bytes.fromhex(salt) + line.encode()).hexdigest()


def verify(salt: str, line: str, digest: str) -> bool:
    return commitment(salt, line) == digest


def put_new_file(token: str, path: str, content: bytes, message: str, repo: str = LEDGER_REPO) -> str:
    """Create a file in the ledger repo (fails if it exists, so nothing is ever rewritten)."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    resp = httpx.put(f"https://api.github.com/repos/{repo}/contents/{path}", headers=headers, timeout=30,
                     json={"message": message, "content": base64.b64encode(content).decode()})
    resp.raise_for_status()
    return resp.json()["commit"]["sha"]


def find_batch(digest: str, day: str, repo: str = LEDGER_REPO) -> str | None:
    """Path of the batch file under commitments/<day>/ that contains `digest`."""
    with httpx.Client(timeout=30) as client:
        resp = client.get(f"https://api.github.com/repos/{repo}/contents/commitments/{day}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        for entry in sorted(resp.json(), key=lambda e: e["name"]):
            if entry["name"].endswith(".txt"):
                raw = client.get(entry["download_url"])
                if raw.status_code == 200 and digest in raw.text:
                    return entry["path"]
    return None


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


def first_commit_with(digest: str, day: str, repo: str = LEDGER_REPO, token: str | None = None) -> str | None:
    """Commit time of the earliest ledger commit whose commitments/<day>.txt contains `digest`."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    path = f"commitments/{day}.txt"
    with httpx.Client(timeout=30, headers=headers) as client:
        commits: list[dict] = []
        for page in range(1, 31):  # a busy day has hundreds of ledger commits
            resp = client.get(f"https://api.github.com/repos/{repo}/commits", params={"path": path, "per_page": 100, "page": page})
            resp.raise_for_status()
            batch = resp.json()
            commits += batch
            if len(batch) < 100:
                break
        commits.sort(key=lambda c: c["commit"]["committer"]["date"])
        for c in commits:
            raw = client.get(f"https://raw.githubusercontent.com/{repo}/{c['sha']}/{path}")
            if raw.status_code == 200 and digest in raw.text:
                return c["commit"]["committer"]["date"]
    return None
