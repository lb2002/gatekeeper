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

import httpx

from gatekeeper.confirm.osv import OSV_QUERY_URL

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


_YARN_ALIAS = re.compile(r"(@?[A-Za-z][^@\s]*)@")
_YARN_VERSION = re.compile(r'\s+version:? "?([^"\s]+)"?\s*$')
_YARN_LOCAL = ("@link:", "@file:", "@workspace:", "@portal:", "@patch:")
_PNPM_SECTION = re.compile(r"^packages:\n(.*?)(?=^\S|\Z)", re.M | re.S)
_YARN_BERRY_SOURCE = re.compile(r'resolution: "[^"]*?@((?:https?:|git)[^"]*)"')
_PNPM_BLOCK = re.compile(r"^  '?/?([^\s':][^'\n]*?)'?:\s*\n((?:    [^\n]*\n)+)", re.M)
_PNPM_SOURCE = re.compile(r"(?:tarball|repo): ([^,}\s]+)")
_SEMVER_START = re.compile(r"[0-9]")


def _yarn_package(key: str) -> str:
    """The package a yarn.lock key installs. An alias is the local name of another package: in
    `"eslint-v7@npm:eslint@^7.7.0"` the code comes from `eslint`, and the name `eslint-v7` is only a label, which on
    npm may even belong to someone else."""
    key = key.strip().strip('"')
    at = key.find("@", 1)
    name, spec = key[:at], key[at + 1:]
    if spec.startswith("npm:"):
        alias = _YARN_ALIAS.match(spec[4:])
        if alias:
            return alias.group(1)
    return name


def parse_yarn(text: str) -> list[Locked]:
    """yarn.lock, classic and berry. Entries for local code (workspaces, links, patches) are not packages from npm."""
    out = []
    for block in re.split(r"\n\s*\n", text):
        lines = [line for line in block.splitlines() if line.strip() and not line.startswith("#")]
        if not lines or lines[0].startswith((" ", "__metadata")) or not lines[0].endswith(":"):
            continue
        header = lines[0][:-1]
        version = next((m.group(1) for m in map(_YARN_VERSION.match, lines[1:]) if m), None)
        if version is None or any(protocol in header for protocol in _YARN_LOCAL):
            continue
        body = "\n".join(lines[1:])
        resolved = re.search(r'resolved "?([^"\n]+)"?', body) or _YARN_BERRY_SOURCE.search(body)
        out.append(Locked(_yarn_package(header.split(",")[0]), version, resolved.group(1) if resolved else "",
                          "integrity " in body or "checksum: " in body))
    return out


def parse_pnpm(text: str) -> list[Locked]:
    """pnpm-lock.yaml. One file can hold several YAML documents (pnpm's own tooling comes first), each with its section."""
    out = []
    for section in _PNPM_SECTION.findall(text + "\n"):
        for m in _PNPM_BLOCK.finditer(section):
            name, _, version = m.group(1).split("(")[0].rpartition("@")
            if not name:
                continue
            source = _PNPM_SOURCE.search(m.group(2))
            resolved = source.group(1) if source else ""
            if not _SEMVER_START.match(version):  # `pkg@https://...` or `pkg@github.com/...`: the key names the source
                resolved = resolved or version
            out.append(Locked(name, version, resolved, "integrity:" in m.group(2)))
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
        host = re.match(r"https?://([^/]+)", p.resolved)
        if host and host.group(1).lower() not in TRUSTED_HOSTS:
            kind = CODE_HOST_SOURCE if host.group(1).lower() in CODE_HOSTS else UNTRUSTED_SOURCE
            out.append(Finding(kind, p.name, p.version, f"resolved from {host.group(1)[:80]}, not the npm registry"))
        elif p.resolved and not host and not p.resolved.startswith(("file:", "workspace:")):
            kind = CODE_HOST_SOURCE if any(h in p.resolved for h in CODE_HOSTS) else UNTRUSTED_SOURCE
            out.append(Finding(kind, p.name, p.version, f"resolved from {p.resolved[:80]}"))
        if host and not p.integrity:
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
