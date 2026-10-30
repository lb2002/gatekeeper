"""What this version adds compared with a reference: its previous version, or the package it was forked from.

Injected code is a few lines in a large library, so neither rules nor an excerpt budget reliably land on it (a family
of 100+ Baileys forks hides one covert call in 100 KB of socket code). A hijacked update looks the same. The difference
against the original is short, whatever the size of the package, and it is exactly what a reviewer would read.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from gatekeeper.npm.tarball import PackageFiles
from gatekeeper.triage.content import CODE_EXT

VERSIONS_TRIED = 4  # a fork rarely keeps the version number: sample the original's history for the closest release
MIN_SHARED_PATHS = 0.3  # of the new package's code files, or it is not a fork of this reference
MAX_RUN_ROWS = 25
MAX_ROW_CHARS = 300
_RISKY = re.compile(r"https?:|fetch\(|request\(|child_process|exec|spawn|eval|Function\(|Buffer\.from|atob|process\.env|require\(|import\(|fs\.|readFile|writeFile|\.send\(|sendMessage|Query|socket|token|password|secret|key", re.I)
_TOKEN = re.compile(r"[^a-z0-9]+")
_NON_NAME = {"lib", "js", "node", "npm", "core", "utils", "util", "api", "sdk", "cli", "app", "web", "main", "git", "github", "com", "https", "the", "dev", "test"}


@dataclass
class Reference:
    label: str
    pkg: PackageFiles


@dataclass
class Run:
    path: str
    first_line: int
    lines: list[str]
    new_file: bool = False


def _code_paths(pkg: PackageFiles) -> list[str]:
    return [p for p in pkg.files if p.endswith(CODE_EXT) and not p.endswith((".d.ts", ".min.js", ".map"))]


def _norm(line: str) -> str:
    return "".join(line.split())


def added_runs(new: PackageFiles, old: PackageFiles) -> list[Run]:
    """Runs of consecutive lines in `new` that `old` does not have in that file, riskiest and shortest first."""
    runs: list[Run] = []
    for path in _code_paths(new):
        data = new.files[path]
        before = old.files.get(path)
        if before == data:
            continue
        lines = (new.text(path) or "").split("\n")
        known = {_norm(x) for x in (old.text(path) or "").split("\n")} if before is not None else set()
        i = 0
        while i < len(lines):
            if not lines[i].strip() or _norm(lines[i]) in known:
                i += 1
                continue
            start = i
            while i < len(lines) and (not lines[i].strip() or _norm(lines[i]) not in known):
                i += 1
            chunk = [x[:MAX_ROW_CHARS] for x in lines[start: i]]
            while chunk and not chunk[-1].strip():
                chunk.pop()
            runs.append(Run(path, start + 1, chunk[:MAX_RUN_ROWS], new_file=before is None))
    return sorted(runs, key=lambda r: (not _RISKY.search("\n".join(r.lines)), r.new_file, len(r.lines)))


def shared_paths(new: PackageFiles, old: PackageFiles) -> float:
    code = _code_paths(new)
    return sum(p in old.files for p in code) / len(code) if code else 0.0


def fork_candidates(name: str, manifest: dict, popular: set[str]) -> list[str]:
    """Popular packages this one may be a copy of. Forks usually keep the original's repository and homepage
    links, and often its name inside their own."""
    by_base: dict[str, list[str]] = {}
    for p in popular:
        by_base.setdefault(p.split("/")[-1].lower(), []).append(p)
    words = [manifest.get("homepage"), _url(manifest.get("repository")), _url(manifest.get("bugs")), name]
    found: list[str] = []
    for text in words:
        if not isinstance(text, str):
            continue
        parts = [t for t in _TOKEN.split(text.lower().replace(".git", "")) if len(t) >= 5 and t not in _NON_NAME]
        for token in parts + [t.rstrip("0123456789") for t in parts]:
            for candidate in by_base.get(token, []):
                if candidate != name and candidate not in found:
                    found.append(candidate)
    return found[:3]


def _url(value: object) -> str | None:
    return value.get("url") if isinstance(value, dict) else value if isinstance(value, str) else None


def references_for(client, doc: dict, version: str, pkg: PackageFiles, popular: set[str], fetch) -> list[Reference]:
    """The previous version of a package and, when it looks like a copy, the original (the release closest to it).
    `fetch(url)` returns the PackageFiles of an archive; a failed fetch just means one reference fewer."""
    from gatekeeper.npm import packument

    out: list[Reference] = []
    if version in (doc.get("versions") or {}):
        info = packument.version_info(doc, version)
        if info.previous_version and not packument.is_placeholder_version(info.previous_version):
            try:
                prev = packument.version_info(doc, info.previous_version)
                out.append(Reference(f"the previous version {info.previous_version}", fetch(prev.tarball_url)))
            except Exception:
                pass
    try:
        manifest = json.loads(pkg.text("package.json") or "{}")
    except ValueError:
        manifest = {}
    if not isinstance(manifest, dict):
        return out
    for candidate in fork_candidates(doc.get("name") or "", manifest, popular):
        try:
            up = packument.fetch_packument(client, candidate) or {}
            tags = up.get("dist-tags") or {}
            versions = up.get("versions") or {}
            released = [v for v, _ in packument.versions_by_time(up)]
            spread = released[:: max(len(released) // VERSIONS_TRIED, 1)]
            tries = [v for v in dict.fromkeys([version, tags.get("latest"), *spread]) if v in versions][:VERSIONS_TRIED + 2]
            refs = []
            for v in tries:
                archive = fetch(packument.version_info(up, v).tarball_url)
                if shared_paths(pkg, archive) >= MIN_SHARED_PATHS:
                    refs.append((sum(len(r.lines) for r in added_runs(pkg, archive)), v, archive))
            if refs:
                _, v, archive = min(refs, key=lambda r: r[0])
                out.append(Reference(f"{candidate}@{v}, which it appears to be copied from", archive))
                break
        except Exception:
            continue
    return out
