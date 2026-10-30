"""A public package that loads a package nobody can read.

The fake-job-interview campaign (26 Tailwind plugins, MAL-2026-18065 ff.) ships no payload at all: a clean plugin
requires a private scoped package, and only the victim has the token, from the lure repository's .npmrc. No scanner,
and no model, can see into that dependency, but the gap itself is visible: the name 404s on the public registry.
"""

from __future__ import annotations

import re

from gatekeeper.npm import packument
from gatekeeper.npm.tarball import PackageFiles
from gatekeeper.triage.content import CODE_EXT

_SCOPED_IMPORT = re.compile(r"""(?:\brequire\(\s*|\bfrom\s+|\bimport\(\s*|\bimport\s+)['"`](@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*)""", re.I)
MAX_CHECKS = 6  # registry lookups per version: a bundle may name dozens of optional integrations
MAX_FILE_BYTES = 400_000
_KNOWN: dict[str, bool] = {}  # name -> readable on the public registry, for the life of the container


def scoped_imports(pkg: PackageFiles) -> dict[str, tuple[str, int, str]]:
    """Scoped package names loaded by the code -> where the first load is (path, line, text)."""
    found: dict[str, tuple[str, int, str]] = {}
    for path, data in pkg.files.items():
        if not path.endswith(CODE_EXT) or path.endswith(".d.ts") or len(data) > MAX_FILE_BYTES or "/test" in path:
            continue
        text = pkg.text(path) or ""
        for m in _SCOPED_IMPORT.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            found.setdefault(m.group(1), (path, line, m.group(0)[:120]))
    return found


def _readable(client, name: str) -> bool:
    if name not in _KNOWN:
        resp = client.head(packument.packument_url(name))
        if resp.status_code not in (200, 404):  # rate limit or outage: says nothing about the package
            return True
        _KNOWN[name] = resp.status_code == 200
    return _KNOWN[name]


def unreadable_imports(client, pkg: PackageFiles, own_name: str, popular: set[str]) -> list[tuple[str, tuple[str, int, str]]]:
    """Scoped packages the code loads that do not exist for the public: (name, (path, line, text))."""
    own_scope = own_name.split("/")[0] if own_name.startswith("@") else None
    candidates = [(n, where) for n, where in scoped_imports(pkg).items()
                  if n not in popular and n != own_name and n.split("/")[0] != own_scope]
    out = []
    for name, where in candidates[:MAX_CHECKS]:
        try:
            if not _readable(client, name):
                out.append((name, where))
        except Exception:
            continue
    return out
