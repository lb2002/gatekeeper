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
import subprocess
import time
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from gatekeeper.evidence.bundle import build_bundle
from gatekeeper.npm.tarball import read_tarball
from gatekeeper.triage.content import score_content
from gatekeeper.triage.phantom import unreadable_imports

RULES_ALLOW_BELOW = 4  # content score under this: allow without asking the model
BLOCK_CONFIDENCE = 0.6
ALLOW_FLAG = "--gk-allow"
# While this file exists the laptop worker leases no new queue items, so an install check gets
# the local model next instead of waiting behind the monitor queue.
BUSY_FILE = Path(os.environ.get("USERPROFILE") or Path.home()) / ".gatekeeper" / "guard.busy"
FAST_MODEL_FILE = BUSY_FILE.parent / "fastclf.json"  # exported by modal_app/fastclf.py::export
CACHE_FILE = BUSY_FILE.parent / "verdicts.json"
MAL_INDEX_FILE = BUSY_FILE.parent / "mal_npm.json"  # `gk guard update-osv`: npm names OSV lists as malicious
# Versions younger than this are held back even when every check is clean: 58% of October's npm malware
# was publicly reported within a day of publication (OSV, measured from the report's import time).
MIN_AGE_HOURS = float(os.environ.get("GK_MIN_AGE_HOURS", "24"))
MAL_INDEX_URL = os.environ.get("GK_MAL_INDEX_URL", "https://lb2002--gatekeeper-api.us-east.modal.run/osv/mal_npm.json")
FAST_MODEL_URL = os.environ.get("GK_FAST_MODEL_URL", MAL_INDEX_URL.rsplit("/osv/", 1)[0] + "/models/fastclf.json")
OSV_ONLINE = os.environ.get("GK_OFFLINE", "") != "1"  # GK_OFFLINE=1: never contact OSV, local list only
CACHE_VERSION = "v2"
CLOUD_URL = MAL_INDEX_URL.rsplit("/osv/", 1)[0]
CLOUD_WAIT_S = 120


def _cache_key(meta: dict) -> str | None:
    # Only versions with a sha512 integrity are cached: npm verifies the tarball it installs against
    # that same value, so a cached decision always refers to exactly the bytes being installed.
    integrity = meta.get("integrity") or ""
    # the version prefix drops decisions made before the current set of checks
    return f"{CACHE_VERSION} {meta['name']}@{meta['version']} {integrity}" if integrity.startswith("sha512-") else None


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


def private_dependencies(meta: dict, pkg) -> list[str]:
    """Packages this public package loads that do not exist for the public (a live campaign hides its payload that
    way). Only for packages from the public registry: on a company registry, private dependencies are normal."""
    if not OSV_ONLINE or urlsplit(meta.get("tarball") or "").hostname != "registry.npmjs.org":
        return []
    deps = meta.get("dependencies") or []
    deps = list(deps.items()) if isinstance(deps, dict) else [tuple(d) for d in deps]
    with httpx.Client(timeout=4, follow_redirects=True) as client:
        return [name for name, _ in unreadable_imports(client, pkg, meta.get("name", ""), set(), deps)]


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


def local_model_up(timeout: float = 1.0) -> bool:
    from gatekeeper.models.backends import LOCAL_URL

    try:
        return httpx.get(f"{LOCAL_URL}/models", timeout=timeout).status_code == 200
    except httpx.HTTPError:
        return False


def cloud_verdict(meta: dict, wait_s: float = CLOUD_WAIT_S, poll_s: float = 2.0) -> dict | None:
    """The hosted investigator, for machines without Muse Glimmer: the 17 GB model should not be the price of being
    protected. Sends the package name and version, nothing about this machine, and only for public npm packages.
    None if it is off (GK_NO_CLOUD=1, GK_OFFLINE=1), unreachable or out of daily runs: the caller then fails closed."""
    if not OSV_ONLINE or os.environ.get("GK_NO_CLOUD") == "1" or urlsplit(meta.get("tarball") or "").hostname != "registry.npmjs.org":
        return None
    try:
        with httpx.Client(timeout=20) as client:
            start = client.post(f"{CLOUD_URL}/try/start", json={"package": f"{meta['name']}@{meta['version']}"})
            if start.status_code != 200:
                return None
            key = start.json()["key"]
            deadline = time.monotonic() + wait_s
            while time.monotonic() < deadline:
                state = client.get(f"{CLOUD_URL}/try/result", params={"key": key}).json()
                if state.get("status") == "done":
                    return state.get("verdict") or None
                time.sleep(poll_s)
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return None
    return None


def _analyse(meta: dict, spec: str, started: float, classify, fast_model, use_cache: bool) -> Decision:
    cached = _cache_get(meta) if use_cache else None
    if cached:
        return Decision(spec, cached["allowed"], "cached: " + cached["reason"], meta["name"], meta["version"],
                        cached.get("verdict"), cached.get("rules") or [], time.monotonic() - started)
    data = httpx.get(meta["tarball"], timeout=60, follow_redirects=True).content
    if not verify_integrity(data, meta["integrity"]):
        return Decision(spec, False, "tarball integrity mismatch", meta["name"], meta["version"])
    pkg = read_tarball(data)
    hidden = private_dependencies(meta, pkg)
    if hidden:
        return Decision(spec, False, f"loads {hidden[0]}, which nobody can read on the public registry: the code that "
                        "would run on this machine cannot be checked by anyone", meta["name"], meta["version"],
                        kind="dependency", seconds=time.monotonic() - started)
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
        if not local_model_up():
            cloud = cloud_verdict(meta)
            if cloud:
                risky = cloud["verdict"] == "malicious" or (cloud["verdict"] == "suspicious" and cloud["confidence"] >= BLOCK_CONFIDENCE)
                reason = f"Muse Spark Open investigator: {cloud['verdict']} ({cloud['confidence']:.2f}) - {cloud['summary']}"
                decision = Decision(spec, not risky, reason, meta["name"], meta["version"], cloud, rules, time.monotonic() - started)
                _cache_put(meta, decision)
                return decision
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
