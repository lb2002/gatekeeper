"""Which files can really run at install time: follow the install hooks through relative requires and imports.

Models tend to attribute any bad-looking code to the install hook. Whether a file is reachable from the hook is a
question plain code can answer, so a claim that fails this check does not count as proven. The graph is static and
errs towards reachable only for what it can see: a computed require path is invisible to it, which is why a failed
check lowers trust in a verdict and never turns it into `benign`.
"""

from __future__ import annotations

import json
import posixpath
import re

from gatekeeper.npm.tarball import PackageFiles

_REQUIRE = re.compile(r"""(?:require|import)\s*\(\s*['"`](\.{1,2}/[^'"`]+)['"`]|from\s+['"`](\.{1,2}/[^'"`]+)['"`]|import\s+['"`](\.{1,2}/[^'"`]+)['"`]""")
_SCRIPT_ARG = re.compile(r"""(?:^|[\s;&|'"])((?:\./)?[\w@./-]+\.(?:c?js|mjs|ts|sh|ps1|py|bat|cmd))\b""")
_HOOKS = ("preinstall", "install", "postinstall", "prepare")
_SUFFIXES = ("", ".js", ".cjs", ".mjs", ".ts", ".json", "/index.js", "/index.cjs", "/index.mjs")


def _resolve(pkg: PackageFiles, base: str, target: str) -> str | None:
    path = posixpath.normpath(posixpath.join(posixpath.dirname(base), target))
    return next((path + s for s in _SUFFIXES if path + s in pkg.files), None)


def install_roots(pkg: PackageFiles) -> set[str]:
    """Files named by the package's install hooks, and binding.gyp."""
    try:
        scripts = (json.loads(pkg.text("package.json") or "{}") or {}).get("scripts") or {}
    except (ValueError, AttributeError):
        scripts = {}
    roots = {"binding.gyp"} & set(pkg.files)
    if isinstance(scripts, dict):
        for hook in _HOOKS:
            cmd = scripts.get(hook)
            if isinstance(cmd, str):
                for m in _SCRIPT_ARG.finditer(cmd):
                    path = posixpath.normpath(m.group(1))
                    if path in pkg.files:
                        roots.add(path)
    return roots


def reachable(pkg: PackageFiles, roots: set[str]) -> set[str]:
    """`roots` plus every file they load, directly or through other files."""
    seen: set[str] = set()
    todo = list(roots)
    while todo:
        path = todo.pop()
        if path in seen or path not in pkg.files:
            continue
        seen.add(path)
        for m in _REQUIRE.finditer(pkg.text(path) or ""):
            found = _resolve(pkg, path, m.group(1) or m.group(2) or m.group(3))
            if found and found not in seen:
                todo.append(found)
    return seen


def runs_at_install(pkg: PackageFiles) -> set[str]:
    return reachable(pkg, install_roots(pkg))
