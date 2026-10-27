"""Install guard: decide whether `npm install` / `npx` may proceed.

Flow per package spec: resolve with the real npm (read-only `npm view`), download the tarball,
verify its integrity, read it in memory, run the static rules, and only if they find something
ask the local Muse Glimmer. Nothing from the package is executed before the decision.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from dataclasses import dataclass, field

import httpx

from gatekeeper.evidence.bundle import build_bundle
from gatekeeper.npm.tarball import read_tarball
from gatekeeper.triage.content import score_content

INSTALL_COMMANDS = {"install", "i", "add", "isntall", "in"}
EXEC_COMMANDS = {"exec", "x"}
RULES_ALLOW_BELOW = 4  # content score under this: allow without asking the model
BLOCK_CONFIDENCE = 0.6
ALLOW_FLAG = "--gk-allow"


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
        npm_cmd + ["view", spec, "name", "version", "dist.tarball", "dist.integrity", "--json"],
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
    }


def verify_integrity(data: bytes, integrity: str | None) -> bool:
    if not integrity or not integrity.startswith("sha512-"):
        return True  # older packages only carry sha1; npm itself still verifies on install
    digest = base64.b64encode(hashlib.sha512(data).digest()).decode()
    return digest == integrity.split("-", 1)[1]


def check_spec(npm_cmd: list[str], spec: str, classify=None) -> Decision:
    import time

    started = time.monotonic()
    meta = resolve(npm_cmd, spec)
    data = httpx.get(meta["tarball"], timeout=60, follow_redirects=True).content
    if not verify_integrity(data, meta["integrity"]):
        return Decision(spec, False, "tarball integrity mismatch", meta["name"], meta["version"])
    pkg = read_tarball(data)
    content = score_content(pkg)
    rules = sorted(content.rules)
    if content.score < RULES_ALLOW_BELOW:
        return Decision(spec, True, f"static rules clean (score {content.score})", meta["name"], meta["version"],
                        rules=rules, seconds=time.monotonic() - started)
    if classify is None:
        from gatekeeper.models.backends import classify_local as classify
    bundle = build_bundle(meta["name"], meta["version"], pkg, content)
    result = classify(bundle)
    v = result.verdict
    secs = time.monotonic() - started
    if v is None:
        return Decision(spec, False, "model gave no usable verdict on a package the rules flagged; blocked to be safe",
                        meta["name"], meta["version"], rules=rules, seconds=secs)
    verdict = v.model_dump(mode="json")
    risky = v.verdict.value == "malicious" or (v.verdict.value == "suspicious" and v.confidence >= BLOCK_CONFIDENCE)
    reason = f"Muse Glimmer: {v.verdict.value} ({v.confidence:.2f}) - {v.summary}"
    return Decision(spec, not risky, reason, meta["name"], meta["version"], verdict, rules, secs)
