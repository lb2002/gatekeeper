"""Install guard: decide whether `npm install` / `npx` may proceed.

Flow per package spec: resolve with the real npm (read-only `npm view`), download the tarball,
verify its integrity, read it in memory, run the static rules, and only if they find something
ask the local Muse Glimmer. Nothing from the package is executed before the decision.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from gatekeeper.evidence.bundle import build_bundle
from gatekeeper.npm.tarball import read_tarball
from gatekeeper.triage.content import score_content

INSTALL_COMMANDS = {"install", "i", "add", "isntall", "in"}
EXEC_COMMANDS = {"exec", "x"}
RULES_ALLOW_BELOW = 4  # content score under this: allow without asking the model
BLOCK_CONFIDENCE = 0.6
ALLOW_FLAG = "--gk-allow"
# While this file exists the laptop worker leases no new queue items, so an install check gets
# the local model next instead of waiting behind the monitor queue.
BUSY_FILE = Path(os.environ.get("USERPROFILE") or Path.home()) / ".gatekeeper" / "guard.busy"
FAST_MODEL_FILE = BUSY_FILE.parent / "fastclf.json"  # exported by modal_app/fastclf.py::export
CACHE_FILE = BUSY_FILE.parent / "verdicts.json"
MAL_INDEX_FILE = BUSY_FILE.parent / "mal_npm.json"  # `gk guard update-osv`: npm names OSV lists as malicious
# Versions younger than this are held back even when every check is clean: 82% of October's npm malware
# was publicly reported within an hour of publication, 89% within a day (OSV, 785 entries).
MIN_AGE_HOURS = float(os.environ.get("GK_MIN_AGE_HOURS", "24"))
MAL_INDEX_URL = os.environ.get("GK_MAL_INDEX_URL", "https://lb2002--gatekeeper-api.us-east.modal.run/osv/mal_npm.json")
OSV_ONLINE = os.environ.get("GK_OFFLINE", "") != "1"  # GK_OFFLINE=1: never contact OSV, local list only


def _cache_key(meta: dict) -> str | None:
    # Only versions with a sha512 integrity are cached: npm verifies the tarball it installs against
    # that same value, so a cached decision always refers to exactly the bytes being installed.
    integrity = meta.get("integrity") or ""
    return f"{meta['name']}@{meta['version']} {integrity}" if integrity.startswith("sha512-") else None


def _cache_get(meta: dict) -> dict | None:
    key = _cache_key(meta)
    if key is None or not CACHE_FILE.exists():
        return None
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8")).get(key)
    except ValueError:
        return None


def _cache_put(meta: dict, decision: "Decision") -> None:
    key = _cache_key(meta)
    if key is None:
        return
    try:
        cache = json.loads(CACHE_FILE.read_text(encoding="utf-8")) if CACHE_FILE.exists() else {}
    except ValueError:
        cache = {}
    cache[key] = {"allowed": decision.allowed, "reason": decision.reason, "verdict": decision.verdict, "rules": decision.rules}
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache), encoding="utf-8")


def load_fast_model():
    """The local first-stage classifier (plain JSON, no pickle), or None if not downloaded."""
    from gatekeeper.fastclf import PortableModel

    if not FAST_MODEL_FILE.exists():
        return None
    return PortableModel(json.loads(FAST_MODEL_FILE.read_text(encoding="utf-8")))
BUSY_STALE_S = 15 * 60


@contextlib.contextmanager
def model_priority():
    BUSY_FILE.parent.mkdir(parents=True, exist_ok=True)
    BUSY_FILE.write_text(str(os.getpid()))
    try:
        yield
    finally:
        BUSY_FILE.unlink(missing_ok=True)


def guard_busy() -> bool:
    try:
        return time.time() - BUSY_FILE.stat().st_mtime < BUSY_STALE_S
    except FileNotFoundError:
        return False


@dataclass
class Decision:
    spec: str
    allowed: bool
    reason: str
    name: str = ""
    version: str = ""
    verdict: dict | None = None
    rules: list[str] = field(default_factory=list)
    seconds: float = 0.0
    kind: str = "analysis"  # analysis | osv | dependency | too_new
    suggestion: str = ""


_MAL_CACHE: dict = {}


def load_mal_index() -> dict:
    try:
        mtime = MAL_INDEX_FILE.stat().st_mtime
    except OSError:
        return {}
    if _MAL_CACHE.get("mtime") != mtime:
        _MAL_CACHE.update(mtime=mtime, index=json.loads(MAL_INDEX_FILE.read_text(encoding="utf-8")))
    return _MAL_CACHE["index"]


def reported_malicious(meta: dict, index: dict) -> str | None:
    if meta["version"].endswith("-security"):
        return f"npm removed {meta['name']} as malware (only its {meta['version']} placeholder is left)"
    e = index.get(meta["name"])
    if e and (e["all"] or meta["version"] in e["versions"]):
        return f"{meta['name']}@{meta['version']} is listed as malicious in OSV (reported {e['public'][:10]})"
    return None


def osv_online(meta: dict, timeout: float = 4.0) -> str | None:
    """Ask OSV directly about this exact version: the local list can be a day old, and most reports land
    in the first days after publication. Sends only the package name and version. None when offline."""
    from gatekeeper.confirm.osv import OSV_QUERY_URL, first_public

    if not OSV_ONLINE:
        return None
    try:
        resp = httpx.post(OSV_QUERY_URL, json={"package": {"name": meta["name"], "ecosystem": "npm"}, "version": meta["version"]},
                          timeout=timeout)
        resp.raise_for_status()
        vulns = (resp.json() or {}).get("vulns") or []
    except (httpx.HTTPError, ValueError):
        return None
    mal = [v for v in vulns if str(v.get("id", "")).startswith("MAL-") and not v.get("withdrawn")]
    if not mal:
        return None
    when = (first_public(mal[0]) or mal[0].get("published") or "")[:10]
    return f"{meta['name']}@{meta['version']} is listed as malicious in OSV ({mal[0]['id']}, {when})"


def index_age_days() -> float | None:
    try:
        return (time.time() - MAL_INDEX_FILE.stat().st_mtime) / 86400
    except OSError:
        return None


def age_hours(meta: dict, now: float | None = None) -> float | None:
    from gatekeeper.confirm import parse_ts

    published = parse_ts((meta.get("time") or {}).get(meta["version"]))
    if published is None:
        return None
    return ((now or time.time()) - published.timestamp()) / 3600


def older_version(meta: dict, min_age_h: float, now: float | None = None) -> str | None:
    """The newest stable version that is already older than `min_age_h`, to suggest instead."""
    from gatekeeper.confirm import parse_ts

    cutoff = (now or time.time()) - min_age_h * 3600
    best = None
    for ver, ts in (meta.get("time") or {}).items():
        t = parse_ts(ts)
        if ver in ("created", "modified") or "-" in ver or t is None or t.timestamp() > cutoff:
            continue
        if best is None or t > best[1]:
            best = (ver, t)
    return best[0] if best else None


RESOLVE_COMMANDS = INSTALL_COMMANDS | {"update", "up", "upgrade", "udpate"}
# read-only commands where --before would change what the user sees
VIEW_COMMANDS = {"view", "v", "info", "show", "outdated", "search", "s", "se", "find"}
# commands that never fetch a package from the registry: if npm's own parse fails, these may still run
SAFE_COMMANDS = {"run", "run-script", "rum", "urn", "test", "t", "tst", "start", "stop", "restart", "ls", "list", "ll", "la",
                 "version", "help", "help-search", "config", "c", "get", "set", "whoami", "ping", "root", "prefix",
                 "docs", "home", "bugs", "repo", "issues", "explain", "why", "query", "fund", "doctor", "completion",
                 "login", "logout", "adduser", "profile", "token", "owner", "access", "team", "org", "star", "unstar",
                 "stars", "hook", "dist-tag", "deprecate", "undeprecate", "unpublish", "prune", "edit", "sbom", "pkg",
                 "uninstall", "un", "unlink", "remove", "rm", "r"}
# npm options that take the next argument as their value (`--registry URL`); `--flag=value` needs no entry. Only
# options that take a value everywhere: at the top level `-p` is the boolean --parseable, so `npm -p install x`
# must still be read as an install. The exec-only ones (-p/--package, -c/--call) are handled in _exec_specs.
VALUE_FLAGS = {"--registry", "--prefix", "-C", "--workspace", "-w", "--tag", "--loglevel", "--userconfig", "--globalconfig",
               "--cache", "--otp", "--before", "--omit", "--include", "--install-strategy", "--script-shell", "--node-options"}
EXEC_VALUE_FLAGS = VALUE_FLAGS | {"-p", "--package", "-c", "--call"}
NPM_COMMANDS = RESOLVE_COMMANDS | EXEC_COMMANDS | {
    "ci", "clean-install", "install-clean", "ic", "run", "run-script", "rum", "urn", "test", "t", "tst", "start", "stop", "restart",
    "publish", "uninstall", "un", "unlink", "remove", "rm", "r", "view", "v", "info", "show", "ls", "list", "ll", "la",
    "outdated", "audit", "init", "create", "innit", "link", "ln", "pack", "config", "c", "get", "set", "cache", "login",
    "logout", "adduser", "whoami", "version", "help", "doctor", "fund", "dedupe", "ddp", "find-dupes", "prune", "rebuild",
    "rb", "explain", "why", "query", "pkg", "search", "s", "se", "find", "owner", "access", "token", "team", "org", "profile",
    "ping", "root", "prefix", "completion", "edit", "explore", "diff", "dist-tag", "deprecate", "unpublish", "hook",
    "shrinkwrap", "sbom", "star", "unstar", "stars", "docs", "home", "bugs", "repo", "issues", "install-test", "it",
    "install-ci-test", "cit", "help-search", "undeprecate"}


def _canonical(token: str) -> str | None:
    """The npm command a token names. npm also accepts unique prefixes; failing closed, any prefix (2+ letters) of
    a command that installs or runs packages counts as that command, so at worst a few extra packages are checked."""
    if token in NPM_COMMANDS:
        return token
    if len(token) >= 2:
        for full in ("install", "exec", "update", "upgrade", "add"):
            if full.startswith(token):
                return full
    return None


def _positionals(args: list[str], value_flags: set[str] = VALUE_FLAGS) -> list[int]:
    """Indexes of the arguments that are not options or option values. After `--` everything is positional:
    `npm install -- evil` installs evil."""
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "--":
            out.extend(range(i + 1, len(args)))
            break
        if a.startswith("-"):
            i += 2 if a in value_flags else 1
            continue
        out.append(i)
        i += 1
    return out


def command_index(args: list[str]) -> int | None:
    """Where the npm command is, after any leading options (`npm --loglevel warn install x`): the first positional
    that names a command. A value of an option this parser does not know is skipped rather than mistaken for the
    command, which would let the install through unchecked."""
    return next((i for i in _positionals(args) if _canonical(args[i])), None)


def _is_package_option(a: str) -> bool:
    """-p, --package and the abbreviations nopt accepts (--pack, --packa, ...), with or without `=value`."""
    name = a.split("=", 1)[0]
    return name == "-p" or (len(name) >= 6 and "--package".startswith(name))


def _exec_specs(args: list[str]) -> list[str]:
    """npx / npm exec: every package given with -p/--package (any spelling), otherwise the first positional (the
    package to run). Arguments after that positional belong to the package and are not specs."""
    pkgs, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "--":
            break
        if _is_package_option(a):
            if "=" in a:
                pkgs.append(a.split("=", 1)[1])
            elif i + 1 < len(args):
                pkgs.append(args[i + 1])
                i += 1
        i += 1
    if not pkgs:
        pos = _positionals(args, EXEC_VALUE_FLAGS)
        pkgs = [args[pos[0]]] if pos else []
    return pkgs


def _all_specs(tool: str, args: list[str]) -> list[str]:
    """Every package spec this npm/npx invocation would install or run, wherever it comes from."""
    args = [a for a in args if a != ALLOW_FLAG]
    if tool == "npx":
        return _exec_specs(args)
    i = command_index(args)
    if i is None:
        return []
    cmd, rest = _canonical(args[i]), args[i + 1:]
    if cmd in EXEC_COMMANDS:
        return _exec_specs(rest)
    if cmd not in INSTALL_COMMANDS:
        return []
    return [rest[j] for j in _positionals(rest)]


def package_specs(tool: str, args: list[str]) -> list[str]:
    """Registry package specs that this npm/npx invocation would install or run."""
    return [s for s in _all_specs(tool, args) if _is_registry_spec(s)]


_GITHUB_SHORTHAND = re.compile(r"[A-Za-z0-9][\w.-]*/[\w.-]+(#.*)?")


def _is_remote_spec(a: str) -> bool:
    """Code from git or a URL: no registry metadata, no integrity hash, so nothing for the guard to check."""
    if "@npm:" in a:  # an alias of a registry package
        return False
    # what follows the name: `name@<target>` / `@scope/name@<target>`; a bare `user/repo` is GitHub shorthand
    if a.startswith("@"):
        rest = a[1:].split("@", 1)
        target = rest[1] if len(rest) > 1 else ""
    else:
        target = a.split("@", 1)[1] if "@" in a and not a.startswith(("http:", "https:", "git")) else a
    return bool(
        re.match(r"(git\+[a-z]+|git|github|gitlab|bitbucket|gist|https?):", target)
        or _GITHUB_SHORTHAND.fullmatch(target)
    )


def remote_specs(tool: str, args: list[str]) -> list[str]:
    """Specs that npm would fetch from git or a URL (`github:u/r`, `u/r`, `https://…/x.tgz`, `name@git+ssh://…`)."""
    return [s for s in _all_specs(tool, args) if _is_remote_spec(s)]


def registry_args(args: list[str]) -> list[str]:
    """A `--registry` given on the command line, so the guard checks the package where npm will fetch it."""
    for i, a in enumerate(args):
        if a == "--registry" and i + 1 < len(args):
            return ["--registry", args[i + 1]]
        if a.startswith("--registry="):
            return ["--registry", a.split("=", 1)[1]]
    return []


NPM_ARGV_JS = Path(__file__).with_name("npm_argv.js")


def npm_root(npm_exe: str) -> Path | None:
    """The npm package directory behind an npm executable (Windows npm.cmd, a unix symlink to npm-cli.js, ...)."""
    exe = Path(npm_exe)
    candidates = []
    if os.name == "nt" and os.environ.get("APPDATA"):
        # npm.cmd runs a globally upgraded npm from %APPDATA%\npm when there is one (bin/npm-prefix.js)
        candidates.append(Path(os.environ["APPDATA"]) / "npm" / "node_modules" / "npm")
    candidates += [exe.parent / "node_modules" / "npm", exe.parent.parent / "lib" / "node_modules" / "npm"]
    with contextlib.suppress(OSError):
        candidates.append(exe.resolve().parent.parent)
    return next((c for c in candidates if (c / "lib" / "utils" / "cmd-list.js").exists()), None)


def npm_native_parse(npm_exe: str, tool: str, args: list[str], timeout: float = 90) -> dict | None:
    """Ask the installed npm itself what this command line installs or runs: npm's config loader (options,
    shorthands, abbreviations, .npmrc, npm_config_* variables), its command aliases, npm-package-arg for the
    spec type and pacote for the exact version, with the user's registry, tag and before settings. Re-parsing
    npm's arguments in Python kept missing cases (`npm -p install x`, `npm it x`, `npm create x`, ...).
    Returns None when this npm cannot be used that way; the caller falls back to the Python parser."""
    root = npm_root(npm_exe)
    if root is None:
        return None
    node = next((str(p) for p in (Path(npm_exe).parent / "node.exe", Path(npm_exe).parent / "node") if p.exists()), "node")
    try:
        out = subprocess.run([node, str(NPM_ARGV_JS), str(root), tool, *args], capture_output=True, text=True,
                             timeout=timeout, encoding="utf-8")
        data = json.loads(out.stdout or "{}")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    return None if "error" in data or "specs" not in data else data


def with_before(tool: str, args: list[str], min_age_hours: float | None = None, now: float | None = None) -> list[str]:
    """`args` with `--before=<now - waiting period>` for npm/npx commands that resolve versions: npm then picks,
    for the whole dependency tree, only versions published before that moment. The explicit package is checked
    (and held) by check_spec; this covers what npm resolves on its own, such as a hijacked patch release of a
    dependency. The flag goes right after the command, so `npx pkg --x` / `npm exec pkg -- --x` never pass it on."""
    from datetime import datetime, timezone

    hours = MIN_AGE_HOURS if min_age_hours is None else min_age_hours
    if hours <= 0 or any(a == "--before" or a.startswith("--before=") for a in args):
        return list(args)
    flag = f"--before={datetime.fromtimestamp((now or time.time()) - hours * 3600, timezone.utc):%Y-%m-%dT%H:%M:%SZ}"
    # first, so it is always read as an option (after `--`, or after npx's package, it would be an argument)
    if tool == "npx":
        return [flag, *args]
    # Every other npm command gets it: harmless where nothing is resolved, and deciding "does this install?" in
    # Python is exactly the guesswork npm_native_parse replaced (audit fix, dedupe, link, it, ... all resolve).
    # whether a command only views something is decided afterwards from npm's own parse (guard_run)
    return [flag, *args] if tool == "npm" else list(args)


def _is_registry_spec(a: str) -> bool:
    # local paths, tarball URLs and git specs are out of scope for the registry check
    return not (
        a.startswith((".", "/", "\\", "file:", "git+", "git:", "github:", "http:", "https:"))
        or a.endswith((".tgz", ".tar.gz"))
        or (len(a) > 1 and a[1] == ":")  # Windows drive path
        or _is_remote_spec(a)
    )


def resolve(npm_cmd: list[str], spec: str) -> dict:
    """Use the real npm (read-only) to resolve a spec to name, version, tarball and integrity."""
    out = subprocess.run(
        npm_cmd + ["view", spec, "name", "version", "dist.tarball", "dist.integrity", "time", "dependencies",
                   "optionalDependencies", "peerDependencies", "--json"],
        capture_output=True, text=True, timeout=60,
    )
    if out.returncode != 0:
        raise RuntimeError((out.stderr or out.stdout).strip()[:300])
    data = json.loads(out.stdout)
    if isinstance(data, list):  # a range matching several versions: npm installs the highest
        data = data[-1]
    return {
        "name": data["name"],
        "version": data["version"],
        "tarball": data.get("dist.tarball") or (data.get("dist") or {}).get("tarball"),
        "integrity": data.get("dist.integrity") or (data.get("dist") or {}).get("integrity"),
        "time": data.get("time") if isinstance(data.get("time"), dict) else {},
        "dependencies": [(str(k), str(v)) for section in ("dependencies", "optionalDependencies", "peerDependencies")
                         for k, v in (data.get(section) or {}).items()],
    }


def verify_integrity(data: bytes, integrity: str | None) -> bool:
    if not integrity or not integrity.startswith("sha512-"):
        return True  # older packages only carry sha1; npm itself still verifies on install
    digest = base64.b64encode(hashlib.sha512(data).digest()).decode()
    return digest == integrity.split("-", 1)[1]


def check_spec(npm_cmd: list[str], spec: str, classify=None, fast_model=None, use_cache: bool = True,
               min_age_hours: float | None = None, meta: dict | None = None) -> Decision:
    from gatekeeper.confirm.malindex import KNOWN_MALICIOUS, TAKEN_DOWN, bad_dependencies

    started = time.monotonic()
    meta = meta or resolve(npm_cmd, spec)
    index = load_mal_index()
    listed = reported_malicious(meta, index) or osv_online(meta)
    if listed:
        return Decision(spec, False, listed, meta["name"], meta["version"], kind="osv", seconds=time.monotonic() - started)
    bad = [r for k, r in bad_dependencies(meta.get("dependencies") or [], index) if k in (KNOWN_MALICIOUS, TAKEN_DOWN)]
    if bad:
        return Decision(spec, False, "; ".join(bad[:3]), meta["name"], meta["version"], kind="dependency",
                        seconds=time.monotonic() - started)
    decision = _analyse(meta, spec, started, classify, fast_model, use_cache)
    # Every check is clean, but nobody else has had time to look at this version yet.
    limit = MIN_AGE_HOURS if min_age_hours is None else min_age_hours
    age = age_hours(meta)
    if decision.allowed and limit > 0 and age is not None and age < limit:
        older = older_version(meta, limit)
        return Decision(spec, False, f"published {age:.1f} h ago; Gatekeeper holds versions newer than {limit:.0f} h "
                        f"(about 58% of npm malware is publicly reported within a day). Checks so far: {decision.reason}",
                        meta["name"], meta["version"], decision.verdict, decision.rules, time.monotonic() - started,
                        kind="too_new", suggestion=f"{meta['name']}@{older}" if older else "")
    return decision


def _analyse(meta: dict, spec: str, started: float, classify, fast_model, use_cache: bool) -> Decision:
    cached = _cache_get(meta) if use_cache else None
    if cached:
        return Decision(spec, cached["allowed"], "cached: " + cached["reason"], meta["name"], meta["version"],
                        cached.get("verdict"), cached.get("rules") or [], time.monotonic() - started)
    data = httpx.get(meta["tarball"], timeout=60, follow_redirects=True).content
    if not verify_integrity(data, meta["integrity"]):
        return Decision(spec, False, "tarball integrity mismatch", meta["name"], meta["version"])
    pkg = read_tarball(data)
    content = score_content(pkg)
    rules = sorted(content.rules)
    bundle = build_bundle(meta["name"], meta["version"], pkg, content)
    # Fast path only when both cheap stages are clean: the rules alone miss most malware that has
    # no obvious pattern, the classifier catches much of that in milliseconds.
    fast_risk = fast_model.risk(bundle.render(), meta["name"], meta["version"], rules) if fast_model else None
    fast_clean = fast_risk is not None and fast_risk < fast_model.threshold
    if content.score < RULES_ALLOW_BELOW and (fast_clean or fast_model is None):
        why = f"static rules clean (score {content.score})"
        why += f", classifier clean (risk {fast_risk:.2f})" if fast_risk is not None else ", no local classifier installed"
        return Decision(spec, True, why, meta["name"], meta["version"], rules=rules, seconds=time.monotonic() - started)
    if classify is None:
        from gatekeeper.models.backends import classify_local as classify
    with model_priority():
        result = classify(bundle)
    v = result.verdict
    secs = time.monotonic() - started
    if v is None:
        return Decision(spec, False, "model gave no usable verdict on a package the rules flagged; blocked to be safe",
                        meta["name"], meta["version"], rules=rules, seconds=secs)
    verdict = v.model_dump(mode="json")
    risky = v.verdict.value == "malicious" or (v.verdict.value == "suspicious" and v.confidence >= BLOCK_CONFIDENCE)
    reason = f"Muse Glimmer: {v.verdict.value} ({v.confidence:.2f}) - {v.summary}"
    decision = Decision(spec, not risky, reason, meta["name"], meta["version"], verdict, rules, secs)
    _cache_put(meta, decision)  # model verdicts are the slow part; never cached: errors, missing verdicts
    return decision
