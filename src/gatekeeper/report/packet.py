"""Review packet: everything a human needs to confirm or reject a flag in a few minutes.

Built from the queue item (bundle, model verdicts, confirmation status) and an inspection of the
published archive (file hashes, full install-time sources; read in memory on Modal, never run).
"""

from __future__ import annotations

import re

from gatekeeper.report.drafts import excerpt_paths

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+!|~])")


def _inline(value: object) -> str:
    """Untrusted text (paths, model summaries, IOCs, npm user names) as one inert Markdown line:
    newlines flattened and every Markdown/HTML control character backslash-escaped."""
    return _MD_SPECIAL.sub(r"\\\1", " ".join(str(value).split()))


def _code_block(text: str) -> list[str]:
    """Fence longer than any backtick run inside, so package code cannot close the block."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + "text", text, fence]


RANK = {"malicious": 2, "suspicious": 1, "benign": 0}


def consensus(verdicts: dict) -> str:
    calls = [v.get("verdict") for v in verdicts.values() if v.get("verdict")]
    if not calls:
        return "no model verdict yet"
    bad = sum(c in ("malicious", "suspicious") for c in calls)
    return f"{bad} of {len(calls)} model verdicts malicious/suspicious"


def _iocs(verdicts: dict) -> list[str]:
    seen: dict[str, None] = {}
    for v in verdicts.values():
        for ioc in ((v.get("full") or {}).get("iocs") or []):
            if ioc.get("value"):
                seen.setdefault(f"{ioc.get('type', '?')}: {ioc['value']}")
    return list(seen)


def build_packet(item: dict, inspection: dict) -> str:
    verdicts = item.get("verdicts") or {}
    paths = excerpt_paths(item)
    conf = item.get("confirmation") or {}
    out = [
        f"# Review packet: {_inline(item['name'])}@{_inline(item['version'])}",
        "",
        f"**Models:** {consensus(verdicts)}. **Public reports:** "
        + (", ".join((conf.get("osv_ids") or []) + (conf.get("ghsa_ids") or [])) or "none yet")
        + (f" (npm takedown {conf['npm_takedown_at']})" if conf.get("npm_takedown_at") else ""),
        "",
        "## Timeline (UTC)",
        "",
        f"- published: {_inline(inspection.get('published_at') or item.get('published_at'))} by {_inline(inspection.get('publisher'))}",
        f"- flagged by Gatekeeper: {item.get('seen_at')}",
        f"- earliest public report: {conf.get('earliest_public') or 'none yet'}",
        f"- still on the registry: {inspection.get('still_on_registry')}",
        "",
        "## What each model said",
        "",
        "| model | verdict | confidence | summary |",
        "|---|---|---|---|",
    ]
    for backend, v in sorted(verdicts.items(), key=lambda kv: -RANK.get(kv[1].get("verdict"), -1)):
        summary = (v.get("full") or {}).get("summary") or ""
        if not v.get("verdict"):
            summary = "no usable verdict: " + "; ".join(v.get("errors") or ["unknown"])
        out.append(f"| {_inline(backend)} | {_inline(v.get('verdict'))} | {_inline(v.get('confidence'))} | {_inline(summary)} |")
    out += ["", "## Cited evidence (file and line in the published package)", ""]
    for backend, v in verdicts.items():
        for ev in ((v.get("full") or {}).get("evidence") or []):
            where = paths.get(ev.get("excerpt_id"), ev.get("excerpt_id"))
            out.append(f"- {_inline(backend)}: {_inline(where)} lines {_inline(ev.get('line_start'))}-{_inline(ev.get('line_end'))}: {_inline(ev.get('why'))}")
    iocs = _iocs(verdicts)
    out += ["", "## Indicators", ""] + ([f"- {_inline(i)}" for i in iocs] or ["- none extracted"])
    out += ["", "## Fingerprints", "", f"- tarball SHA-256 {_inline(inspection.get('tarball_sha256'))}"]
    for path, meta in sorted((inspection.get("files") or {}).items()):
        out.append(f"- {_inline(path)} ({_inline(meta['size'])} B) SHA-256 {_inline(meta['sha256'])}")
    out += ["", "## Install-time code (read statically, never executed)", ""]
    for path, text in (inspection.get("text") or {}).items():
        numbered = "\n".join(f"{i:>4}| {line}" for i, line in enumerate(text.splitlines(), start=1))
        out += [f"### {_inline(path)}", "", *_code_block(numbered), ""]
    out += [
        "## Checklist",
        "",
        "- [ ] The cited lines exist and do what the models say (compare with the code above or on npmjs.com, Code tab).",
        "- [ ] The behaviour is not the package's stated purpose and the user is not told about it.",
        "- [ ] Data leaves the machine, or code is fetched/executed, or credentials/secrets are read.",
        "- [ ] Self-described research/canary? Then report it as a probe, with neutral wording.",
        "- [ ] Every sentence in the report drafts matches the code.",
        "",
        "If any box stays empty, do not report; mark it 'unsure' and ask.",
        "",
    ]
    return "\n".join(out)
