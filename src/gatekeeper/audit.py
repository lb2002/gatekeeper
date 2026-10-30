"""`gk audit`: am I already affected? Reads a project's lockfile, nothing else, and checks every locked version.

The install guard protects the next install; after an incident the question is about what is already there. The
lockfile answers it without touching node_modules or running anything. Works offline from the local copy of OSV's list;
online it also asks OSV about the exact versions, because the list can be a day old.

With `--since <git ref>` it also asks what a change brought in. Nobody has reported a package that came out this morning,
so those versions go to the hosted investigator, which reads them. That is the pull request check of the GitHub Action.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlsplit

import httpx
import yaml

from gatekeeper.confirm.osv import OSV_QUERY_URL
from gatekeeper.npm.packument import packument_url

_YamlLoader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
OSV_BATCH_URL = OSV_QUERY_URL + "batch"
OSV_BATCH_SIZE = 500
TRUSTED_HOSTS = ("registry.npmjs.org", "registry.yarnpkg.com")
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock")
# Projects do pin forks on code hosts, so that is a note; it would fail too many builds to be an error
CODE_HOSTS = ("github.com", "codeload.github.com", "raw.githubusercontent.com", "gitlab.com", "bitbucket.org")
MALICIOUS, UNTRUSTED_SOURCE, CODE_HOST_SOURCE, NO_INTEGRITY = "malicious", "untrusted_source", "code_host_source", "no_integrity"
MODEL_FLAGGED = "model_flagged"
SEVERE = {MALICIOUS, UNTRUSTED_SOURCE, MODEL_FLAGGED}
MAX_REVIEWED = 5
MAX_LOOKUPS = 60
REVIEW_WORKERS = 3


@dataclass
class Locked:
    name: str
    version: str
    resolved: str = ""
    integrity: bool = True
    install_script: bool = False
    checksum: str = ""


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
                          bool(e.get("hasInstallScript")), str(e.get("integrity") or "")))
    if out:
        return out

    def walk(deps: dict) -> None:
        for name, e in (deps or {}).items():
            if isinstance(e, dict) and e.get("version"):
                out.append(Locked(name, e["version"], e.get("resolved") or "", bool(e.get("integrity")), checksum=str(e.get("integrity") or "")))
                walk(e.get("dependencies") or {})

    walk(doc.get("dependencies") or {})
    return out


# `git@` only as an ssh address: `simple-git@^3.10.0` and `@npmcli/git@5.0.8` are package names
# bounded, and a scheme can only start at a token start: this runs on text anyone can post to the public demo
_ANY_SOURCE = re.compile(r"""(?:(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}://|(?<![a-z0-9+.-])git\+|(?<![\w-])git@[\w.-]{1,255}[:/]|(?<![\w-])(?:github|gitlab|bitbucket|gist):)[^\s"',}#&]{0,2000}""", re.I)
_YARN_ALIAS = re.compile(r"((?:@[^/@\s]+/)?[^/@\s]+)(?:@.*)?\Z")
_YARN_FIELD = re.compile(r'  ("?[\w-]+"?):? "?([^"]*)"?\s*\Z')
_YARN_LOCAL = ("link:", "file:", "workspace:", "portal:", "patch:")
_RANGE = re.compile(r"[\^~<>=*0-9]|latest\Z|next\Z")
_SEMVER_START = re.compile(r"[0-9]")


def _source_of(*fields: str) -> str:
    """Where lockfile fields say the code comes from: any URL in them, percent-encoded ones too (yarn berry hides them
    in `::__archiveUrl=` bindings), a foreign one first. Deny by default: anything that looks like a source counts."""
    urls = [u for u in _ANY_SOURCE.findall(unquote("\n".join(fields))) if not is_local(u)]
    foreign = [u for u in urls if not on_registry(u)]
    return (foreign or urls or [""])[0]


def is_local(source: str) -> bool:
    """Code in the project itself. `file://host/...` names a machine, so it is not."""
    return source.startswith(("file:", "workspace:")) and "://" not in source.replace("file:///", "")


def on_registry(source: str) -> bool:
    """A plain URL on the registry; a value without a scheme is never taken for one. Nor is anything npm's URL parser
    could read differently from ours: for it, `https://evil.example\\@registry.npmjs.org/` is a URL on evil.example."""
    try:
        parts = urlsplit(source)
    except ValueError:
        return False
    return (parts.scheme.lower() in ("http", "https") and parts.hostname in TRUSTED_HOSTS and "@" not in parts.netloc
            and not re.search(r"[\\\s\x00-\x1f]", source))


def names_another_file(p: Locked) -> bool:
    """A registry URL for another package or version than the entry claims. The host is right, so the host check passes
    it, and a reviewer sees an entry for a familiar name: this is how a lockfile gets poisoned."""
    if not on_registry(p.resolved):
        return False
    path = unquote(urlsplit(p.resolved).path)
    prefix = f"/{p.name}/-/{p.name.rsplit('/', 1)[-1]}-"
    if p.version == "?":
        return not re.fullmatch(re.escape(prefix) + r"\d[^/]*\.tgz", path)
    return path != f"{prefix}{p.version}.tgz"


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
        resolved = fields.get("resolved", "")
        if resolved and not is_local(resolved) and not on_registry(resolved) and (not source or on_registry(source)):
            source = resolved  # whatever its form: only a registry URL is left alone
        if not keys or (not source and all(spec.startswith(_YARN_LOCAL) for _, spec in keys)):
            continue
        version = fields.get("version") or "?"
        # berry says outright what was resolved; it wins over a key that could be crafted
        named = re.match(r'((?:@[^/@\s]+/)?[^/@\s]+)@npm:', fields.get("resolution", ""))
        names = [named.group(1)] if named else list(dict.fromkeys(n for n, _ in keys))
        integrity = "integrity" in fields or "checksum" in fields
        out += [Locked(n, version, source, integrity, checksum=fields.get("integrity") or fields.get("checksum", "")) for n in names]
    return out


def parse_pnpm(text: str) -> list[Locked]:
    """pnpm-lock.yaml. One file can hold several YAML documents (pnpm's own tooling comes first), each with its section.
    pnpm never writes aliases, and a few hundred bytes of them expand to gigabytes: anyone can post text here."""
    out = []
    try:
        if any(isinstance(event, yaml.AliasEvent) for event in yaml.parse(text, Loader=_YamlLoader)):
            raise ValueError("YAML aliases are not part of a pnpm lockfile")
        docs = list(yaml.load_all(text, Loader=_YamlLoader))
    except (yaml.YAMLError, RecursionError) as exc:
        raise ValueError("not a readable pnpm lockfile") from exc
    for doc in docs:
        packages = doc.get("packages") if isinstance(doc, dict) else None
        for key, entry in (packages or {}).items():
            key = str(key).lstrip("/").split("(")[0]
            name, _, version = key.rpartition("@")
            resolution = entry.get("resolution") if isinstance(entry, dict) else None
            resolution = resolution if isinstance(resolution, dict) else {}
            if not name:  # an entry nobody can name must not vanish from the report
                out.append(Locked(key[:80], "?", "unreadable lockfile entry"))
                continue
            fields = [v for k, v in resolution.items() if k != "integrity"]
            source = _source_of(key, *(v for v in fields if isinstance(v, str)))
            if not all(isinstance(v, (str, bool)) for v in fields):  # pnpm writes text and `gitHosted: true`, nothing else
                source = "unreadable lockfile entry"
            if not source and not _SEMVER_START.match(version):  # `pkg@github.com/x/y/abc`: the key names the source
                source = version
            out.append(Locked(name, version, source, bool(resolution.get("integrity")), checksum=str(resolution.get("integrity") or "")))
    return out


def _parser_of(file: Path) -> Callable[[str], list[Locked]]:
    return parse_yarn if file.name == "yarn.lock" else parse_pnpm if file.suffix == ".yaml" else parse_npm


def read_lockfile(path: Path) -> tuple[Path, list[Locked]]:
    """The lockfile at `path`, or the first one in that folder. Raises FileNotFoundError if there is none."""
    candidates = [path] if path.is_file() else [path / n for n in LOCKFILES]
    for file in candidates:
        if file.exists():
            try:
                return file, _parser_of(file)(file.read_text(encoding="utf-8"))
            except RecursionError as exc:
                raise ValueError("nested too deeply for a lockfile") from exc
    raise FileNotFoundError(f"no lockfile in {path}")


def locked_at(file: Path, ref: str) -> list[Locked]:
    """The same lockfile at git `ref`; empty if it did not exist there. ValueError if git does not know the ref."""
    def git(*args):
        return subprocess.run(["git", "-C", str(file.parent.resolve()), *args], capture_output=True, encoding="utf-8", errors="replace")

    if ref.startswith("-") or git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").returncode:
        raise ValueError(f"git does not know {ref}")
    shown = git("show", f"{ref}:./{file.name}")
    return _parser_of(file)(shown.stdout) if shown.returncode == 0 else []


def added_since(locked: list[Locked], before: list[Locked]) -> list[Locked]:
    """Versions that were not there before. A new version of an old dependency counts: that is what a hijack looks
    like. So does a known version whose source or hash changed. Names the project never had come first."""
    def identity(p: Locked) -> tuple:
        return p.name, p.version, p.resolved, p.checksum

    had = {identity(p) for p in before}
    names = {p.name for p in before}
    new = {identity(p): p for p in locked if identity(p) not in had}
    return sorted(new.values(), key=lambda p: (not p.install_script, p.name in names, p.name))


def public_release(client: httpx.Client, p: Locked) -> tuple[str, dict | None]:
    """("public", the registry's record of exactly this version), or ("private", None) for a package that is not on the
    public registry and is not sent on, or ("failed", None): that one is not known to be anything, so it stays unread."""
    if p.resolved and not on_registry(p.resolved):
        return "private", None
    if p.version == "?":
        return "failed", None
    try:
        resp = client.get(f"{packument_url(p.name)}/{p.version}")
        if resp.status_code == 404:
            return "private", None
        doc = resp.json() if resp.status_code == 200 else {}
        dist, scripts = doc.get("dist") or {}, doc.get("scripts") or {}
    except (httpx.HTTPError, ValueError, AttributeError):
        return "failed", None
    if not dist.get("tarball"):
        return "failed", None
    return "public", {"name": p.name, "version": p.version, "tarball": dist["tarball"], "integrity": str(dist.get("integrity") or ""),
                      "shasum": str(dist.get("shasum") or ""), "runs_at_install": bool(doc.get("gypfile"))
                      or any(hook in scripts for hook in ("preinstall", "install", "postinstall"))}


def _hash_differs(p: Locked, release: dict) -> bool:
    """True if any hash the two have in common differs: a matching sha1 must not excuse a wrong sha512 next to it.
    False if they share no algorithm: an entry with no hash at all is the NO_INTEGRITY note."""
    for h in p.checksum.split():
        if h.startswith("sha512-") and release["integrity"].startswith("sha512-") and h != release["integrity"]:
            return True
        if h.startswith("sha1-") and release["shasum"]:
            try:
                if base64.b64decode(h[5:], validate=True).hex() != release["shasum"].lower():
                    return True
            except ValueError:
                return True
    return False


def review_added(added: list[Locked], ask: Callable[[dict], dict | None], client: httpx.Client, block_at: float) -> dict:
    """Have up to MAX_REVIEWED of the `added` versions read, what runs at install first. That comes from the registry:
    the lockfile is the thing under review. `ask` returns a verdict, or None if it has no answer."""
    public, private, findings = {}, [], []
    for p in added[:MAX_LOOKUPS]:
        status, release = public_release(client, p)
        if status == "private":
            private.append(f"{p.name}@{p.version}")
        elif release and _hash_differs(p, release):
            findings.append(Finding(UNTRUSTED_SOURCE, p.name, p.version, "the hash in the lockfile is not the hash of the file the registry published"))
        elif release:
            public[p.name, p.version] = release
    releases = sorted(public.values(), key=lambda r: not r["runs_at_install"])
    with ThreadPoolExecutor(REVIEW_WORKERS) as pool:
        answers = list(pool.map(ask, releases[:MAX_REVIEWED]))
    read = []
    for release, v in zip(releases, answers):
        if not v:
            continue
        row = {"name": release["name"], "version": release["version"], "verdict": v["verdict"], "confidence": v["confidence"], "summary": v.get("summary", "")}
        read.append(row)
        if v["verdict"] == "malicious" or (v["verdict"] == "suspicious" and v["confidence"] >= block_at):
            findings.append(Finding(MODEL_FLAGGED, row["name"], row["version"], f"Muse Spark Open read it: {v['verdict']} ({v['confidence']:.2f}), {row['summary'][:300]}"))
    done = {f"{r['name']}@{r['version']}" for r in read} | {f"{f.name}@{f.version}" for f in findings} | set(private)
    unread = dict.fromkeys(f"{p.name}@{p.version}" for p in added)
    return {"added": len(unread), "read": read, "private": private, "findings": [asdict(f) for f in findings],
            "unread": [key for key in unread if key not in done]}


def parse_text(text: str) -> list[Locked]:
    """A lockfile whose name is unknown (pasted into the web page), told apart by its content."""
    head = text.lstrip()[:200]
    try:
        if head.startswith("{"):
            return parse_npm(text)
    except RecursionError as exc:
        raise ValueError("nested too deeply for a lockfile") from exc
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
        if p.resolved and not is_local(p.resolved):
            host = host_of(p.resolved)
            if host in CODE_HOSTS:
                out.append(Finding(CODE_HOST_SOURCE, p.name, p.version, f"resolved from {host[:80]}, not the npm registry"))
            elif not on_registry(p.resolved):
                out.append(Finding(UNTRUSTED_SOURCE, p.name, p.version, f"resolved from {p.resolved[:80]}, not the npm registry"))
            elif names_another_file(p):
                out.append(Finding(UNTRUSTED_SOURCE, p.name, p.version, f"the entry points to another file: {p.resolved[:80]}"))
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
