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


def package_specs(tool: str, args: list[str]) -> list[str]:
    """Registry package specs that this npm/npx invocation would install or run."""
    args = [a for a in args if a != ALLOW_FLAG]
    if tool == "npx":
        for a in args:
            if not a.startswith("-"):
                return [a] if _is_registry_spec(a) else []
        return []
    if not args:
        return []
    cmd, rest = args[0], args[1:]
    if cmd in EXEC_COMMANDS:
        return package_specs("npx", rest)
    if cmd not in INSTALL_COMMANDS:
        return []
    specs, skip_next = [], False
    for a in rest:
        if skip_next:
            skip_next = False
            continue
        if a in ("--registry", "--prefix", "-C", "--workspace", "-w", "--tag"):
            skip_next = True
            continue
        if a.startswith("-"):
            continue
        if _is_registry_spec(a):
            specs.append(a)
    return specs


def _is_registry_spec(a: str) -> bool:
    # local paths, tarball URLs and git specs are out of scope for the registry check
    return not (
        a.startswith((".", "/", "\\", "file:", "git+", "git:", "github:", "http:", "https:"))
        or a.endswith((".tgz", ".tar.gz"))
        or (len(a) > 1 and a[1] == ":")  # Windows drive path
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
               min_age_hours: float | None = None) -> Decision:
    from gatekeeper.confirm.malindex import KNOWN_MALICIOUS, TAKEN_DOWN, bad_dependencies

    started = time.monotonic()
    meta = resolve(npm_cmd, spec)
    index = load_mal_index()
    listed = reported_malicious(meta, index)
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
                        f"(most npm malware is reported within hours). Checks so far: {decision.reason}",
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
