"""A public package that loads a package nobody can read.

The fake-job-interview campaign (26 Tailwind plugins, MAL-2026-18065 ff.) ships no payload at all: a clean plugin
requires a private scoped package, and only the victim has the token, from the lure repository's .npmrc. No scanner,
and no model, can see into that dependency, but the gap itself is visible: the name 404s on the public registry.
A hit only sends the version to the models, so a stray monorepo leftover costs a few cents and nothing else.
"""

from __future__ import annotations

import json
import re

from gatekeeper.npm import packument
from gatekeeper.npm.tarball import PackageFiles
from gatekeeper.triage.content import CODE_EXT, focus_files

_SCOPED_IMPORT = re.compile(r"""(?:\brequire\(\s*|\bfrom\s+|\bimport\(\s*|\bimport\s+)['"`](@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*)""", re.I)
_SCOPED_NAME = re.compile(r"@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*\Z", re.I)
_TEST_DIR = re.compile(r"(?:^|/)(?:test|tests|__tests__|fixtures)/")
MAX_LOOKUPS = 12  # registry requests per version; names already known cost nothing
MAX_SCAN_BYTES = 400_000  # of each file
MAX_NAMES = 200
_KNOWN: dict[str, bool] = {}  # name -> readable on the public registry, for the life of the container


def _manifest_names(pkg: PackageFiles) -> dict[str, tuple[str, int, str]]:
    try:
        manifest = json.loads(pkg.text("package.json") or "{}")
    except ValueError:
        return {}
    if not isinstance(manifest, dict):
        return {}
    found = {}
    for field in ("dependencies", "optionalDependencies", "peerDependencies"):
        deps = manifest.get(field)
        if isinstance(deps, dict):
            for name in deps:
                if isinstance(name, str) and _SCOPED_NAME.match(name):
                    found.setdefault(name, ("package.json", 1, f"{field}: {name}"[:120]))
    return found


def scoped_imports(pkg: PackageFiles) -> dict[str, tuple[str, int, str]]:
    """Scoped packages the package loads or declares -> where (path, line, text). Code that runs first comes first,
    so filler imports in other files cannot push the real one past the lookup limit."""
    found = _manifest_names(pkg)
    focus = focus_files(pkg)
    paths = focus + [p for p in pkg.files if p not in focus and p.endswith(CODE_EXT) and not p.endswith(".d.ts")]
    for path in paths:
        if path not in focus and _TEST_DIR.search(path):
            continue
        text = pkg.files[path][:MAX_SCAN_BYTES].decode("utf-8", errors="replace")
        line, offset = 1, 0
        for m in _SCOPED_IMPORT.finditer(text):
            if m.group(1) in found:
                continue
            if len(found) >= MAX_NAMES:
                return found
            line += text.count("\n", offset, m.start())
            offset = m.start()
            found[m.group(1)] = (path, line, m.group(0)[:120])
    return found


def unreadable_imports(client, pkg: PackageFiles, own_name: str, popular: set[str]) -> list[tuple[str, tuple[str, int, str]]]:
    """Scoped packages it loads that do not exist for the public: (name, (path, line, text)). A failed lookup
    counts as readable and is not remembered: the monitor must not stop for a registry hiccup, and the next
    version of the package asks again."""
    out = []
    lookups = 0
    for name, where in scoped_imports(pkg).items():
        if name in popular or name == own_name:
            continue
        if name not in _KNOWN:
            if lookups >= MAX_LOOKUPS:
                continue
            lookups += 1
            try:
                status = client.head(packument.packument_url(name)).status_code
            except Exception:
                continue
            if status not in (200, 404):
                continue
            _KNOWN[name] = status == 200
        if not _KNOWN[name]:
            out.append((name, where))
    return out
