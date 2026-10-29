"""Index of npm package names reported as malicious in OSV (OpenSSF malicious-packages), with the time
each became public. Used to flag new versions that depend on a known-malicious package: the wrapper
itself often contains no malicious code at all, so no content check can catch it."""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

from gatekeeper.confirm import earliest
from gatekeeper.confirm.osv import first_public

ALL_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
_ALIAS = re.compile(r"^npm:(@?[^@]+)(?:@(.*))?$")
# a tarball fetched from an arbitrary server bypasses the registry (and every check on it)
_REMOTE = re.compile(r"^https?://", re.IGNORECASE)
# npm holds these names (Node built-ins) as security placeholders: depending on them is a harmless mistake
NODE_BUILTINS = {"assert", "buffer", "child_process", "cluster", "crypto", "dgram", "dns", "events", "fs", "http",
                 "http2", "https", "net", "os", "path", "process", "querystring", "readline", "stream", "string_decoder",
                 "timers", "tls", "tty", "url", "util", "v8", "vm", "worker_threads", "zlib"}


def _all_versions(affected: dict) -> bool:
    """True if the entry covers every version (no version list, or a range introduced at 0 with no fix)."""
    if affected.get("versions"):
        return False
    for r in affected.get("ranges") or []:
        events = r.get("events") or []
        if any("fixed" in e or "last_affected" in e for e in events):
            return False
    return True


def build_index(zip_path: Path) -> dict[str, dict]:
    """name -> {"public": earliest public time, "all": every version malicious, "versions": listed versions},
    merged over all MAL entries for that name in OSV's npm all.zip."""
    index: dict[str, dict] = {}
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            if not member.startswith("MAL-"):
                continue
            vuln = json.loads(zf.read(member))
            if vuln.get("withdrawn"):
                continue
            public = first_public(vuln) or vuln.get("published") or ""
            for a in vuln.get("affected") or []:
                pkg = a.get("package") or {}
                name = pkg.get("name")
                if str(pkg.get("ecosystem", "")).lower() != "npm" or not name:
                    continue
                e = index.setdefault(name, {"public": public, "all": False, "versions": []})
                e["public"] = earliest([e["public"], public]) or public
                e["all"] = e["all"] or _all_versions(a)
                e["versions"] = sorted(set(e["versions"]) | set(a.get("versions") or []))  # never truncated
    return index


KNOWN_MALICIOUS = "known_malicious"  # flag on its own
TAKEN_DOWN = "taken_down"
REMOTE_URL = "remote_url"  # sometimes legitimate: only worth a scan
DepEntries = dict[str, str] | list[tuple[str, str]]


def dependency_targets(deps: DepEntries) -> list[tuple[str, str, str]]:
    """(declared name, package actually installed, version spec); npm aliases point elsewhere.
    Takes a name->spec dict or a list of (name, spec) pairs (one per manifest section, duplicates kept)."""
    out = []
    for name, spec in (deps.items() if isinstance(deps, dict) else deps):
        m = _ALIAS.match(str(spec).strip())
        out.append((name, m.group(1), m.group(2) or "") if m else (name, name, str(spec)))
    return out


def bad_dependencies(deps: DepEntries, index: dict[str, dict], before: str | None = None,
                     popular: set[str] = frozenset()) -> list[tuple[str, str]]:
    """(kind, reason) for dependencies that are known malicious (reported in OSV before `before`, if
    given), pinned to npm's security placeholder, or fetched from a URL. A package that was malicious only
    in some versions (a hijacked library) counts only when the spec pins one of those versions; a popular
    package only then. The kind, never the text (which holds attacker-chosen names), decides the weight."""
    out = []
    for declared, target, spec in dependency_targets(deps):
        shown = declared if declared == target else f"{declared} (alias of {target})"
        e = index.get(target)
        known = e is not None and (before is None or e["public"] < before)
        exact = spec.lstrip("=v ").strip()
        if known and ((e["all"] and target not in popular) or exact in e["versions"]):
            out.append((KNOWN_MALICIOUS, f"depends on {shown}, reported malicious {e['public'][:10]}"))
        elif spec.endswith("-security") and target not in NODE_BUILTINS:
            out.append((TAKEN_DOWN, f"depends on {shown} at {spec}, npm's placeholder for removed malware"))
        elif _REMOTE.match(spec):
            out.append((REMOTE_URL, f"depends on {shown} from a URL outside the registry ({spec[:80]})"))
    return out
