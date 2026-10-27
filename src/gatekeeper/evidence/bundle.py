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
    path: str  # the real file path inside the package (never a display label)
    first_line: int
    lines: list[str]
    note: str = ""  # display-only remark, e.g. "minified, excerpt of line 3"
    kind: str = "code"  # "manifest" for the selected package.json fields, "diff", or "code"

    @property
    def last_line(self) -> int:
        return self.first_line + len(self.lines) - 1

    def render(self) -> str:
        body = "\n".join(f"{self.first_line + i:>4}| {line}" for i, line in enumerate(self.lines))
        note = f" ({self.note})" if self.note else ""
        return f"[{self.excerpt_id}] {self.path}{note} (lines {self.first_line}-{self.last_line})\n{body}"

    def ref(self) -> dict:
        return {"excerpt_id": self.excerpt_id, "path": self.path, "kind": self.kind,
                "first_line": self.first_line, "last_line": self.last_line}


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


@dataclass
class ExcerptRef:
    excerpt_id: str
    first_line: int
    last_line: int
    path: str = ""
    kind: str = "code"


@dataclass
class RenderedBundle:
    """A bundle restored from storage: the exact text the model sees plus excerpt line ranges for validation."""

    package: str
    version: str
    text: str
    refs: list[ExcerptRef]

    def render(self) -> str:
        return self.text

    def excerpt(self, excerpt_id: str) -> ExcerptRef | None:
        return next((r for r in self.refs if r.excerpt_id == excerpt_id), None)

    @classmethod
    def from_record(cls, rec: dict) -> "RenderedBundle":
        refs = [
            ExcerptRef(e["excerpt_id"], e["first_line"], e["last_line"], e.get("path", ""), e.get("kind", "code"))
            for e in rec.get("excerpts") or []
        ]
        return cls(rec["name"], rec["version"], rec["bundle"], refs)


MINIFIED_EXCERPT_CHARS = 600


def _clip(line: str, limit: int = MAX_LINE_CHARS) -> str:
    return line if len(line) <= limit else line[:limit] + f" …[+{len(line) - limit} chars]"


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

    def add(
        path: str, first_line: int, lines: list[str], clip: int = MAX_LINE_CHARS, note: str = "", kind: str = "code"
    ) -> bool:
        nonlocal counter, used
        counter += 1
        ex = Excerpt(f"E{counter}", path, first_line, [_clip(line, clip) for line in lines], note=note, kind=kind)
        size = len(ex.render()) + 2
        if used + size > max_chars:
            counter -= 1
            return False
        b.excerpts.append(ex)
        used += size
        return True

    add("package.json", 1, _manifest_excerpt(pkg), note="selected fields", kind="manifest")

    for path, lines in diff_excerpts or []:
        add(path, 1, lines, note="diff vs previous version", kind="diff")

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
            # Minified/packed: show the code around each rule hit (real line numbers), not just the start.
            longest = max(len(line) for line in all_lines) if all_lines else 0
            hit_lines = sorted(set(hits_by_path.get(path, [])))
            if not hit_lines:
                note = f"minified or packed file: {len(all_lines)} lines, longest {longest} chars; no rule hits; start shown"
                add(path, 1, [all_lines[0][:200] if all_lines else ""], note=note)
                continue
            hits_here = [h for h in content.hits if h.path == path]
            for ln in hit_lines[:4]:
                line = all_lines[ln - 1] if ln - 1 < len(all_lines) else ""
                snippets = []
                for h in hits_here:
                    if h.line != ln:
                        continue
                    snippets.append(line[max(0, h.col - 200): h.col + 300])
                shown = " … ".join(dict.fromkeys(s for s in snippets if s)) or line[:400]
                if not add(path, ln, [shown], clip=MINIFIED_EXCERPT_CHARS, note=f"minified, excerpt of line {ln}"):
                    break
            continue
        spans = _windows(hits_by_path.get(path, []), len(all_lines)) or [(1, min(len(all_lines), 2 * CONTEXT_LINES + 1))]
        for start, end in spans:
            if not add(path, start, all_lines[start - 1 : end]):
                break
    return b
