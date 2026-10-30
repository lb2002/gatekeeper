"""A public package that loads a package nobody can read.

The fake-job-interview campaign (26 Tailwind plugins, MAL-2026-18065 ff.) ships no payload at all: a clean plugin
requires a private scoped package, and only the victim has the token, from the lure repository's .npmrc. No scanner,
and no model, can see into that dependency, but the gap itself is visible: the name 404s on the public registry.
A hit only sends the version to the models, so a stray monorepo leftover costs a few cents and nothing else.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta

from gatekeeper.npm import packument
from gatekeeper.npm.tarball import PackageFiles
from gatekeeper.triage.content import CODE_EXT, focus_files

_SCOPED_IMPORT = re.compile(r"""(?:\brequire\(\s*|\bfrom\s+|\bimport\(\s*|\bimport\s+)['"`](@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*)""", re.I)
_SCOPED_NAME = re.compile(r"@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*\Z", re.I)
_TEST_DIR = re.compile(r"(?:^|/)(?:test|tests|__tests__|fixtures)/")
_ALIAS = re.compile(r"npm:(@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*)", re.I)
MAX_LOOKUPS = 30  # registry requests per version; names already known cost nothing
MAX_LOOKUP_FAILURES = 3
MAX_NAMES = 400
YOUNG_DEPENDENCY = timedelta(days=7)
MAX_ADDED_LOOKUPS = 12  # registry requests per version; names already known cost nothing
MISSING = object()  # a dependency the registry does not have
_KNOWN: dict[str, bool] = {}  # name -> readable on the public registry, for the life of the container
_CREATED: dict = {}  # name -> creation time of the package, likewise


def _declared(deps: list[tuple[str, str]]) -> dict[str, tuple[str, int, str]]:
    """Scoped names among declared dependencies, aliases (`"x": "npm:@evil/y"`) resolved to their target."""
    found = {}
    for name, spec in deps:
        alias = _ALIAS.match(spec) if isinstance(spec, str) else None
        target = alias.group(1) if alias else name
        if isinstance(target, str) and _SCOPED_NAME.match(target):
            found.setdefault(target, ("package.json", 1, f"dependency: {target}"[:120]))
    return found


def _manifest_deps(pkg: PackageFiles) -> list[tuple[str, str]]:
    try:
        manifest = json.loads((pkg.text("package.json") or "{}").lstrip("\ufeff"))
    except ValueError:
        return []
    if not isinstance(manifest, dict):
        return []
    return [(n, s) for field in ("dependencies", "optionalDependencies", "peerDependencies")
            if isinstance(manifest.get(field), dict) for n, s in manifest[field].items()]


def scoped_imports(pkg: PackageFiles, registry_deps: list[tuple[str, str]] | None = None) -> dict[str, tuple[str, int, str]]:
    """Scoped packages the package declares or loads -> where (path, line, text). What npm will install comes first
    (the registry's list, then the archive's, which can differ), then code that runs first, then other files, test
    folders last: filler imports cannot push the real one past the lookup limit."""
    found = _declared(list(registry_deps or []) + _manifest_deps(pkg))
    focus = focus_files(pkg)
    others = sorted((p for p in pkg.files if p not in focus and p.endswith(CODE_EXT) and not p.endswith(".d.ts")),
                    key=lambda p: bool(_TEST_DIR.search(p)))
    for path in focus + others:
        _scan(pkg, path, found)
    return found


def _scan(pkg: PackageFiles, path: str, found: dict[str, tuple[str, int, str]]) -> None:
    text = pkg.text(path) or ""
    line, offset = 1, 0
    for m in _SCOPED_IMPORT.finditer(text):
        if m.group(1) in found:
            continue
        if len(found) >= MAX_NAMES:
            return
        line += text.count("\n", offset, m.start())
        offset = m.start()
        found[m.group(1)] = (path, line, m.group(0)[:120])


def _created(client, name: str) -> datetime | None:
    """When a package was created, `MISSING` if the registry does not have it, None if it gave no usable answer."""
    resp = client.get(packument.packument_url(name))
    if resp.status_code == 404:
        return MISSING
    if resp.status_code != 200:
        return None
    body = resp.json()
    created = (body.get("time") or {}).get("created") if isinstance(body, dict) else None
    return packument._parse_time(created) if isinstance(created, str) else None


def young_additions(client, info, now: datetime, popular: set[str]) -> list[tuple[str, float | None]]:
    """Dependencies this update adds that are only days old, or not on the registry at all: (name, age in hours or
    None). A hijacked release usually looks like this: a patch version of a trusted package pulling in something
    created that week. The registry metadata shows it without opening the archive, which most updates never get."""
    out: list[tuple[str, float | None]] = []
    lookups = 0
    for name in info.added_dependencies:
        if name in popular:
            continue
        if name not in _CREATED:
            if lookups >= MAX_ADDED_LOOKUPS:
                continue
            lookups += 1
            try:
                created = _created(client, name)
            except Exception:  # no answer is no evidence; the next version of the package asks again
                continue
            if created is None:
                continue
            _CREATED[name] = created
        created = _CREATED[name]
        if created is MISSING:
            out.append((name, None))
        elif now - created <= YOUNG_DEPENDENCY:
            out.append((name, (now - created).total_seconds() / 3600))
    return out


def _lookup(client, name: str) -> bool | None:
    """True if the public can read this package, None if the registry gave no answer. npm's security holding
    package counts as unreadable: that name exists only because npm removed what was there."""
    resp = client.get(packument.packument_url(name), headers={"Accept": "application/vnd.npm.install-v1+json"})
    if resp.status_code == 404:
        return False
    if resp.status_code != 200:
        return None
    versions = (resp.json() or {}).get("versions") or {}
    return bool(set(versions) - {packument.SECURITY_HOLDER_VERSION, packument.STAGE_PLACEHOLDER_VERSION})


def unreadable_imports(client, pkg: PackageFiles, own_name: str, popular: set[str],
                       registry_deps: list[tuple[str, str]] | None = None) -> list[tuple[str, tuple[str, int, str]]]:
    """Scoped packages it loads that do not exist for the public: (name, (path, line, text)). A failed lookup
    counts as readable and is not remembered: the monitor must not stop for a registry hiccup, the next version
    of the package asks again, and the offline guard still has its other checks. Names already known always count,
    whatever happens to the lookups."""
    candidates = {n: w for n, w in scoped_imports(pkg, registry_deps).items() if n not in popular and n != own_name}
    lookups = failures = 0
    for name in candidates:
        if name in _KNOWN:
            continue
        if lookups >= MAX_LOOKUPS or failures >= MAX_LOOKUP_FAILURES:
            break
        lookups += 1
        try:
            readable = _lookup(client, name)
        except Exception:
            failures += 1  # a few in a row mean no network: the others would only wait for the same timeout
            continue
        failures = 0
        if readable is not None:
            _KNOWN[name] = readable
    return [(n, w) for n, w in candidates.items() if _KNOWN.get(n) is False]
