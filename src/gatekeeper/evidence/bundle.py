"""Build the evidence bundle: a short, line-numbered, text-only view of a package.

The same bundle is sent to every model (Muse Spark, Muse Glimmer) and used in the evaluation, so
comparisons are fair. Every excerpt has an ID and numbered lines; models must cite them, and
`models.validate` rejects citations that do not exist.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from gatekeeper.npm.tarball import PackageFiles
from gatekeeper.triage.content import ContentScore

MAX_CHARS = 8000  # roughly 2k tokens
CONTEXT_LINES = 8
MAX_LINE_CHARS = 240
MINIFIED_LINE_CHARS = 1000
MANIFEST_KEYS = ("name", "version", "main", "bin", "scripts", "gypfile", "dependencies", "optionalDependencies", "repository", "files")


@dataclass
class Excerpt:
    excerpt_id: str
    path: str
    first_line: int
    lines: list[str]

    @property
    def last_line(self) -> int:
        return self.first_line + len(self.lines) - 1

    def render(self) -> str:
        body = "\n".join(f"{self.first_line + i:>4}| {line}" for i, line in enumerate(self.lines))
        return f"[{self.excerpt_id}] {self.path} (lines {self.first_line}-{self.last_line})\n{body}"


@dataclass
class Bundle:
    package: str
    version: str
    header: list[str] = field(default_factory=list)
    excerpts: list[Excerpt] = field(default_factory=list)

    def excerpt(self, excerpt_id: str) -> Excerpt | None:
        return next((e for e in self.excerpts if e.excerpt_id == excerpt_id), None)

    def render(self) -> str:
        parts = ["\n".join(self.header)] + [e.render() for e in self.excerpts]
        return "\n\n".join(p for p in parts if p)


def _clip(line: str) -> str:
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + f" …[+{len(line) - MAX_LINE_CHARS} chars]"


def _manifest_excerpt(pkg: PackageFiles) -> list[str]:
    raw = pkg.text("package.json")
    if raw is None:
        return ["(no package.json)"]
    try:
        manifest = json.loads(raw)
    except ValueError:
        return raw.splitlines()[:40]
    subset = {k: manifest[k] for k in MANIFEST_KEYS if k in manifest}
    return json.dumps(subset, indent=2, ensure_ascii=False).splitlines()


def _windows(hit_lines: list[int], total: int) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for ln in sorted(set(hit_lines)):
        start, end = max(1, ln - CONTEXT_LINES), min(total, ln + CONTEXT_LINES)
        if spans and start <= spans[-1][1] + 1:
            spans[-1] = (spans[-1][0], max(spans[-1][1], end))
        else:
            spans.append((start, end))
    return spans


def build_bundle(
    name: str,
    version: str,
    pkg: PackageFiles,
    content: ContentScore,
    meta_reasons: list[str] | None = None,
    diff_excerpts: list[tuple[str, list[str]]] | None = None,
    max_chars: int = MAX_CHARS,
) -> Bundle:
    b = Bundle(package=name, version=version)
    b.header.append(f"package: {name}@{version}")
    if meta_reasons:
        b.header.append("registry signals: " + "; ".join(meta_reasons))
    listing = sorted(pkg.sizes.items(), key=lambda kv: -kv[1])[:25]
    b.header.append("files (largest first): " + ", ".join(f"{p} ({n}B)" for p, n in listing))
    if content.hits:
        b.header.append("static rule hits: " + ", ".join(sorted(content.rules)))

    counter = 0
    used = len("\n".join(b.header))

    def add(path: str, first_line: int, lines: list[str]) -> bool:
        nonlocal counter, used
        counter += 1
        ex = Excerpt(f"E{counter}", path, first_line, [_clip(line) for line in lines])
        size = len(ex.render()) + 2
        if used + size > max_chars:
            counter -= 1
            return False
        b.excerpts.append(ex)
        used += size
        return True

    add("package.json (selected fields)", 1, _manifest_excerpt(pkg))

    for path, lines in diff_excerpts or []:
        add(f"{path} (diff vs previous version)", 1, lines)

    # Focus files (install hooks, main, bin, binding.gyp): around rule hits, else the start of the file.
    hits_by_path: dict[str, list[int]] = {}
    for h in content.hits:
        hits_by_path.setdefault(h.path, []).append(h.line)
    ordered = list(dict.fromkeys(content.focus_files + list(hits_by_path)))
    for path in ordered:
        text = pkg.text(path)
        if text is None:
            continue
        all_lines = text.splitlines()
        if any(len(line) > MINIFIED_LINE_CHARS for line in all_lines[:50]):
            longest = max(len(line) for line in all_lines) if all_lines else 0
            note = f"(minified or packed file: {len(all_lines)} lines, longest {longest} chars; start shown)"
            add(path, 1, [note, all_lines[0][:200] if all_lines else ""])
            continue
        spans = _windows(hits_by_path.get(path, []), len(all_lines)) or [(1, min(len(all_lines), 2 * CONTEXT_LINES + 1))]
        for start, end in spans:
            if not add(path, start, all_lines[start - 1 : end]):
                break
    return b
