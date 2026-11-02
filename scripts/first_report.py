"""When was each confirmed version first reported anywhere we can see?

/stats.json measures the lead over OSV, GitHub and npm listings. An OSV listing can lag its pull request by days, because
the pull request has to be merged first, so this script also reads the pull requests of ossf/malicious-packages: the first
commit whose report names the version. That date is set by the reporter, so it can only make our lead look shorter.

Usage: python scripts/first_report.py <stats.json> [out.json]     (needs the GitHub CLI, logged in)
"""
from __future__ import annotations

import base64
import json
import statistics
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

REPO = "repos/ossf/malicious-packages"
OURS = ("lb2002",)


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def gh(path: str):
    for attempt in range(3):
        p = subprocess.run(["gh", "api", path], capture_output=True, text=True, encoding="utf-8")
        if p.returncode == 0:
            return json.loads(p.stdout)
        if "404" in p.stderr + p.stdout:
            return None
        time.sleep(4 * (attempt + 1))
    # GitHub answers 500 for the history of some paths; such a package falls back to its listing date
    print(f"could not read {path}: {p.stderr[:80]}", file=sys.stderr)
    return None


def lists_version(path: str, ref: str, version: str) -> bool:
    for entry in gh(f"{REPO}/contents/{path}?ref={ref}") or []:
        blob = gh(f"{REPO}/contents/{quote(entry['path'])}?ref={ref}")
        doc = json.loads(base64.b64decode(blob["content"])) if blob else {}
        if any(version in (a.get("versions") or []) for a in doc.get("affected", [])):
            return True
    return False


def first_commit(name: str, version: str) -> tuple[str, str] | None:
    """Earliest pull request commit by someone else whose report lists this exact version. The history of main only shows merge dates."""
    path = f"osv/malicious/npm/{quote(name)}"
    prs = {}
    for c in gh(f"{REPO}/commits?path={path}&per_page=100") or []:
        for pr in gh(f"{REPO}/commits/{c['sha']}/pulls") or []:
            if pr["user"]["login"] not in OURS and pr["user"]["type"] != "Bot":
                prs[pr["number"]] = pr
    for pr in sorted(prs.values(), key=lambda p: p["created_at"]):
        for c in gh(f"{REPO}/pulls/{pr['number']}/commits?per_page=100") or []:
            if lists_version(path, c["sha"], version):
                return c["commit"]["author"]["date"], pr["user"]["login"]
    return None


def main(stats_path: str, out: str | None = None) -> None:
    stats = json.loads(Path(stats_path).read_text(encoding="utf-8"))
    # a package counts with its first flagged version, as on the live page
    first_flag: dict[str, dict] = {}
    for c in stats["catches"]:
        if c["name"] not in first_flag or c["flagged_at"] < first_flag[c["name"]]["flagged_at"]:
            first_flag[c["name"]] = c
    rows = []
    for c in first_flag.values():
        hit = first_commit(c["name"], c["version"])
        first = min([ts(c["earliest_public"])] + ([ts(hit[0])] if hit else []))
        rows.append({"name": c["name"], "version": c["version"], "flagged_at": c["flagged_at"], "listed": c["earliest_public"], "first_report": first.isoformat(),
                     "reporter": hit[1] if hit else None, "lead_h": round((first - ts(c["flagged_at"])).total_seconds() / 3600, 2)})
    rows.sort(key=lambda r: r["lead_h"])
    for r in rows:
        print(f"{r['lead_h']:>7} h  {r['name']}@{r['version']}  {r['reporter'] or 'listing'}")
    print(f"{len(rows)} packages, {sum(r['lead_h'] > 0 for r in rows)} flagged before the first report; median lead {statistics.median(r['lead_h'] for r in rows)} h")
    if out:
        Path(out).write_text(json.dumps(rows, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main(*sys.argv[1:])
