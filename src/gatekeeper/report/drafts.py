"""Report drafts for a human-verified malicious npm version.

- OSV JSON for a pull request to github.com/ossf/malicious-packages
  (path osv/malicious/npm/<name>/MAL-0000-<name>.json; the real MAL id is assigned on merge).
- Plain text for npm's "Report malware" form on the package page.

Drafts are written locally and submitted by the reviewer; nothing is sent automatically.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

FINDER = {"name": "Linus Baumberger (Gatekeeper)", "contact": ["https://github.com/lb2002"], "type": "FINDER"}


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _verdict_lines(verdict: dict, paths: dict[str, str] | None = None) -> list[str]:
    """Evidence as `file lines a-b: why`. Excerpts keep the real line numbers of their file, so an
    excerpt id maps directly to a path in the published package."""
    lines = []
    for ev in verdict.get("evidence") or []:
        where = (paths or {}).get(ev.get("excerpt_id"), ev.get("excerpt_id"))
        lines.append(f"- {where} lines {ev.get('line_start')}-{ev.get('line_end')}: {ev.get('why')}")
    return lines


def excerpt_paths(item: dict) -> dict[str, str]:
    return {e["excerpt_id"]: e.get("path") or e["excerpt_id"] for e in item.get("excerpts") or []}


def osv_draft(item: dict, verdict: dict, note: str = "") -> dict:
    iocs = [i.get("value") for i in verdict.get("iocs") or [] if i.get("value")]
    details = [
        f"The package {item['name']} version {item['version']} contains malicious code "
        f"({verdict.get('category', 'other')}, triggered via {verdict.get('trigger', 'unknown')}).",
        "",
        verdict.get("summary", ""),
        "",
        "Evidence:",
        *_verdict_lines(verdict, excerpt_paths(item)),
    ]
    if iocs:
        details += ["", "Indicators: " + ", ".join(iocs)]
    if note:
        details += ["", note]
    now = _iso_now()
    return {
        "schema_version": "1.5.0",
        "published": now,
        "modified": now,
        "summary": f"Malicious code in {item['name']} (npm)",
        "details": "\n".join(details).strip(),
        "affected": [{"package": {"ecosystem": "npm", "name": item["name"]}, "versions": [item["version"]]}],
        "credits": [FINDER],
        "database_specific": {
            "malicious-packages-origins": [{"source": "gatekeeper", "import_time": now, "versions": [item["version"]]}]
        },
    }


def osv_path(name: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", name.lower()).strip("-")
    return f"osv/malicious/npm/{name}/MAL-0000-{slug}.json"


def npm_report_text(item: dict, verdict: dict, note: str = "") -> str:
    parts = [
        f"Package: {item['name']}",
        f"Affected version(s): {item['version']}",
        "",
        f"Behaviour: {verdict.get('summary', '')}",
        f"Trigger: {verdict.get('trigger', 'unknown')}",
        "",
        "Evidence (lines in the published package):",
        *_verdict_lines(verdict, excerpt_paths(item)),
    ]
    iocs = [i.get("value") for i in verdict.get("iocs") or [] if i.get("value")]
    if iocs:
        parts += ["", "Indicators: " + ", ".join(iocs)]
    if note:
        parts += ["", note]
    parts += ["", "Found by Gatekeeper (static analysis, no code executed) and verified manually."]
    return "\n".join(parts)


def write_drafts(item: dict, verdict: dict, out_dir, note: str = "") -> list[str]:
    from pathlib import Path

    folder = Path(out_dir) / f"{item['name'].replace('/', '__')}@{item['version']}"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "osv.json").write_text(json.dumps(osv_draft(item, verdict, note), indent=2), encoding="utf-8")
    (folder / "osv_path.txt").write_text(osv_path(item["name"]) + "\n", encoding="utf-8")
    (folder / "npm_report.txt").write_text(npm_report_text(item, verdict, note), encoding="utf-8")
    return [str(p) for p in folder.iterdir()]
