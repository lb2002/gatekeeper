"""`gk audit`: am I already affected? Reads a project's lockfile, nothing else, and checks every locked version.

The install guard protects the next install; after an incident the question is about what is already there. The
lockfile answers it without touching node_modules or running anything. Works offline from the local copy of OSV's list;
online it also asks OSV about the exact versions, because the list can be a day old.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import unquote

import httpx
import yaml

from gatekeeper.confirm.osv import OSV_QUERY_URL

_YamlLoader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
OSV_BATCH_URL = OSV_QUERY_URL + "batch"
OSV_BATCH_SIZE = 500
TRUSTED_HOSTS = ("registry.npmjs.org", "registry.yarnpkg.com")
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock")
# Projects do pin forks on code hosts, so that is a note; it would fail too many builds to be an error
CODE_HOSTS = ("github.com", "codeload.github.com", "raw.githubusercontent.com", "gitlab.com", "bitbucket.org")
MALICIOUS, UNTRUSTED_SOURCE, CODE_HOST_SOURCE, NO_INTEGRITY = "malicious", "untrusted_source", "code_host_source", "no_integrity"
SEVERE = {MALICIOUS, UNTRUSTED_SOURCE}


@dataclass
class Locked:
    name: str
    version: str
    resolved: str = ""
    integrity: bool = True
    install_script: bool = False


@dataclass
class Finding:
    kind: str
    name: str
    version: str
    detail: str


def _npm_name(path: str) -> str:
    return path.rsplit("node_modules/", 1)[-1]


def parse_npm(text: str) -> list[Locked]:
    """package-lock.json, v1 to v3."""
    doc = json.loads(text)
    out: list[Locked] = []
    for path, e in (doc.get("packages") or {}).items():
        if not path or not isinstance(e, dict) or not e.get("version") or e.get("link"):
            continue
        out.append(Locked(e.get("name") or _npm_name(path), e["version"], e.get("resolved") or "", bool(e.get("integrity")),
                          bool(e.get("hasInstallScript"))))
    if out:
        return out

    def walk(deps: dict) -> None:
        for name, e in (deps or {}).items():
            if isinstance(e, dict) and e.get("version"):
                out.append(Locked(name, e["version"], e.get("resolved") or "", bool(e.get("integrity"))))
                walk(e.get("dependencies") or {})

    walk(doc.get("dependencies") or {})
    return out


# `git@` only as an ssh address: `simple-git@^3.10.0` and `@npmcli/git@5.0.8` are package names
_ANY_SOURCE = re.compile(r"""(?:https?://|git\+|ssh://|(?<![\w-])git@[\w.-]+[:/])[^\s"',}#&]*""", re.I)
_YARN_ALIAS = re.compile(r"((?:@[^/@\s]+/)?[^/@\s]+)(?:@.*)?\Z")
_YARN_FIELD = re.compile(r'  ("?[\w-]+"?):? "?([^"]*)"?\s*\Z')
_YARN_LOCAL = ("link:", "file:", "workspace:", "portal:", "patch:")
_RANGE = re.compile(r"[\^~<>=*0-9]|latest\Z|next\Z")
_SEMVER_START = re.compile(r"[0-9]")


def _source_of(*fields: str) -> str:
    """Where lockfile fields say the code comes from: any URL in them, percent-encoded ones too (yarn berry hides them
    in `::__archiveUrl=` bindings), a foreign one first. Deny by default: anything that looks like a source counts."""
    urls = _ANY_SOURCE.findall(unquote("\n".join(fields)))
    foreign = [u for u in urls if host_of(u) not in TRUSTED_HOSTS]
    return (foreign or urls or [""])[0]


def host_of(source: str) -> str:
    """The host of a URL, git+ssh address or scp-like `git@host:path`, compared exactly, never as a substring."""
    m = re.match(r"(?:[a-z][a-z0-9+.-]*://)?(?:[^@/]*@)?([^/:#?]+)", source.strip(), re.I)
    return m.group(1).lower() if m else ""


def _yarn_key(key: str) -> tuple[str, str]:
    """(package a yarn.lock key installs, its spec). An alias is the local name of another package: in
    `"eslint-v7@npm:eslint@^7.7.0"` the code comes from `eslint`, and the name `eslint-v7` is only a label, which on
    npm may even belong to someone else."""
    key = key.strip().strip('"')
    at = key.find("@", 1)
    name, spec = key[:at], key[at + 1:]
    target = spec[4:] if spec.startswith("npm:") else ""
    if target and not _RANGE.match(target):
        alias = _YARN_ALIAS.match(target)
        if alias:
            return alias.group(1), spec
    return name, spec


def parse_yarn(text: str) -> list[Locked]:
    """yarn.lock, classic and berry, by structure: every unindented line ending in `:` starts an entry. An entry counts
    as local code only if all its keys are local and it names no remote source."""
    entries: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            entries.append((line.rstrip().rstrip(":"), []))
        elif entries:
            entries[-1][1].append(line)
    out = []
    for header, body in entries:
        if header.strip('"') == "__metadata":
            continue
        keys = [_yarn_key(k) for k in re.findall(r'"[^"]*"|[^,\s][^,]*', header)]
        fields = dict(m.groups() for m in map(_YARN_FIELD.match, body) if m)
        fields = {k.strip('"'): v for k, v in fields.items()}
        source = _source_of(header, fields.get("resolved", ""), fields.get("resolution", ""))
        if not keys or (not source and all(spec.startswith(_YARN_LOCAL) for _, spec in keys)):
            continue
        version = fields.get("version") or "?"
        # berry says outright what was resolved; it wins over a key that could be crafted
        named = re.match(r'((?:@[^/@\s]+/)?[^/@\s]+)@npm:', fields.get("resolution", ""))
        names = [named.group(1)] if named else list(dict.fromkeys(n for n, _ in keys))
        integrity = "integrity" in fields or "checksum" in fields
        out += [Locked(n, version, source, integrity) for n in names]
    return out


def parse_pnpm(text: str) -> list[Locked]:
    """pnpm-lock.yaml. One file can hold several YAML documents (pnpm's own tooling comes first), each with its section."""
    out = []
    for doc in yaml.load_all(text, Loader=_YamlLoader):
        packages = doc.get("packages") if isinstance(doc, dict) else None
        for key, entry in (packages or {}).items():
            key = str(key).lstrip("/").split("(")[0]
            name, _, version = key.rpartition("@")
            resolution = entry.get("resolution") if isinstance(entry, dict) else None
            resolution = resolution if isinstance(resolution, dict) else {}
            if not name:  # an entry nobody can name must not vanish from the report
                out.append(Locked(key[:80], "?", "unreadable lockfile entry"))
                continue
            source = _source_of(key, *(str(v) for k, v in resolution.items() if k != "integrity"))
            if not source and not _SEMVER_START.match(version):  # `pkg@github.com/x/y/abc`: the key names the source
                source = version
            out.append(Locked(name, version, source, bool(resolution.get("integrity"))))
    return out


def read_lockfile(path: Path) -> tuple[Path, list[Locked]]:
    """The lockfile at `path`, or the first one in that folder. Raises FileNotFoundError if there is none."""
    candidates = [path] if path.is_file() else [path / n for n in LOCKFILES]
    for file in candidates:
        if file.exists():
            text = file.read_text(encoding="utf-8")
            parse = parse_yarn if file.name == "yarn.lock" else parse_pnpm if file.suffix == ".yaml" else parse_npm
            return file, parse(text)
    raise FileNotFoundError(f"no lockfile in {path}")


def parse_text(text: str) -> list[Locked]:
    """A lockfile whose name is unknown (pasted into the web page), told apart by its content."""
    head = text.lstrip()[:200]
    if head.startswith("{"):
        return parse_npm(text)
    return parse_pnpm(text) if "lockfileVersion" in head else parse_yarn(text)


def check_index(locked: list[Locked], index: dict) -> list[Finding]:
    """What the offline list and the lockfile itself can tell: known malware, foreign sources, missing hashes."""
    out = []
    for p in locked:
        e = index.get(p.name)
        if p.version.endswith("-security"):
            out.append(Finding(MALICIOUS, p.name, p.version, "npm's placeholder for a package it removed as malware"))
        elif e and (e.get("all") or p.version in (e.get("versions") or [])):
            out.append(Finding(MALICIOUS, p.name, p.version, f"listed as malicious in OSV (reported {str(e.get('public'))[:10]})"))
        if p.resolved and not p.resolved.startswith(("file:", "workspace:")):
            host = host_of(p.resolved)
            if host in CODE_HOSTS:
                out.append(Finding(CODE_HOST_SOURCE, p.name, p.version, f"resolved from {host[:80]}, not the npm registry"))
            elif host not in TRUSTED_HOSTS:
                out.append(Finding(UNTRUSTED_SOURCE, p.name, p.version, f"resolved from {p.resolved[:80]}, not the npm registry"))
            if not p.integrity:
                out.append(Finding(NO_INTEGRITY, p.name, p.version, "no integrity hash in the lockfile"))
    return out


def check_osv(locked: list[Locked], timeout: float = 20) -> tuple[list[Finding], bool]:
    """Ask OSV about the exact versions. Sends package names and versions only. (findings, answered)."""
    unique = sorted({(p.name, p.version) for p in locked})
    out = []
    try:
        with httpx.Client(timeout=timeout) as client:
            for i in range(0, len(unique), OSV_BATCH_SIZE):
                chunk = unique[i: i + OSV_BATCH_SIZE]
                resp = client.post(OSV_BATCH_URL, json={"queries": [
                    {"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in chunk]})
                resp.raise_for_status()
                for (n, v), res in zip(chunk, resp.json().get("results") or []):
                    ids = [x.get("id", "") for x in (res or {}).get("vulns") or [] if str(x.get("id", "")).startswith("MAL-")]
                    if ids:
                        out.append(Finding(MALICIOUS, n, v, f"reported as malware: {ids[0]}"))
    except (httpx.HTTPError, ValueError):
        return out, False
    return out, True


def audit(locked: list[Locked], index: dict, online: bool = True) -> dict:
    findings = check_index(locked, index)
    answered = False
    if online:
        extra, answered = check_osv(locked)
        have = {(f.kind, f.name, f.version) for f in findings}
        findings += [f for f in extra if (f.kind, f.name, f.version) not in have]
    return {"packages": len({(p.name, p.version) for p in locked}), "install_scripts": sum(p.install_script for p in locked),
            "osv_online": answered, "findings": [asdict(f) for f in findings], "severe": any(f.kind in SEVERE for f in findings)}
