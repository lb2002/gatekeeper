"""T1: cheap static content signals over the files that run at install time or on require.

Pure pattern matching on text read in memory. Nothing is executed or decoded into runnable code.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field

from gatekeeper.npm.tarball import PackageFiles

CODE_EXT = (".js", ".cjs", ".mjs", ".ts", ".sh", ".ps1", ".py", ".bat", ".cmd")


@dataclass(frozen=True)
class Rule:
    name: str
    points: int
    pattern: re.Pattern


def _r(name: str, points: int, regex: str, flags: int = re.IGNORECASE) -> Rule:
    return Rule(name, points, re.compile(regex, flags))


RULES: tuple[Rule, ...] = (
    _r("child_process", 2, r"require\(\s*['\"](?:node:)?child_process['\"]\s*\)|from\s+['\"](?:node:)?child_process['\"]"),
    _r("network_call", 1, r"\b(?:https?\.(?:get|request)|fetch\(|axios\.|XMLHttpRequest|net\.connect|dns\.(?:lookup|resolve))"),
    _r("env_dump", 4, r"JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries)\(\s*process\.env\s*\)"),
    _r("secret_paths", 4, r"\.npmrc|\.ssh[/\\]|id_rsa|\.aws[/\\]credentials|['\"]\.(?:aws|ssh|docker|kube)['\"]|\.git-credentials|\.docker[/\\]config|Local State|Login Data|wallet\.dat|\.config[/\\]solana|metamask"),
    _r("encoded_url", 3, r"['\"`]aHR0cHM6Ly[A-Za-z0-9+/=]*|['\"`]aHR0cDovL[A-Za-z0-9+/=]*"),  # base64 of http(s)://
    _r("host_fingerprint", 1, r"os\.(?:userInfo|hostname|homedir|networkInterfaces)\(\)"),
    _r("exfil_service", 4, r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|webhook\.site|pipedream\.net|requestbin|ngrok\.io|oast\.(?:fun|me|pro|live|online|site)|interact\.sh|burpcollaborator|canarytokens"),
    # public IPv4 literals only: loopback, private, link-local and 0.0.0.0 are excluded
    _r("raw_ip_url", 3, r"https?://(?!127\.|10\.|0\.0\.0\.0|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?"),
    _r("eval_decoded", 4, r"(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|unescape)\s*\("),
    _r("dynamic_eval", 2, r"\beval\s*\(|new\s+Function\s*\("),
    _r("pipe_to_shell", 4, r"(?:curl|wget)[^\n|]{0,200}\|\s*(?:ba)?sh\b|powershell(?:\.exe)?\s+[^\n]{0,40}-e(?:nc|ncodedcommand)?\s"),
    _r("obfuscator_names", 3, r"_0x[0-9a-f]{4,}"),
    # the lookbehind keeps this linear: without it every offset inside a long hex run restarts the match
    _r("hex_dns_label", 3, r"(?<![0-9a-f])[0-9a-f]{20,}\.[a-z0-9-]+\.(?:com|net|org|io|xyz|fun|site|live|me)\b"),
    _r("detached_spawn", 2, r"detached\s*:\s*true|\.unref\(\)"),
    # a WhatsApp channel id written into a library: the Baileys fork family makes every user's account follow it
    _r("hardcoded_channel", 6, r"\b\d{15,}@newsletter\b"),
    _r("injection_phrase", 3, r"(?:note|attention|message|instructions?)\s+(?:to|for)\s+(?:the\s+|any\s+)?(?:ai|llm|automated|security|code)(?:\s+\w+)?\s+(?:reviewers?|scanners?|analy[sz]ers?|auditors?)|ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|(?:this\s+)?package\s+(?:is|has\s+been)\s+(?:audited|verified|reviewed)(?:\s+and)?(?:\s+is)?\s+safe|classify\s+(?:this\s+)?(?:package\s+)?as\s+(?:benign|safe)"),
)


@dataclass
class Hit:
    rule: str
    path: str
    line: int
    snippet: str
    col: int = 0  # character offset of the match within the line


@dataclass
class ContentScore:
    score: int = 0
    hits: list[Hit] = field(default_factory=list)
    focus_files: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def rules(self) -> set[str]:
        return {h.rule for h in self.hits}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


_LONG_STRING = re.compile(r"['\"`]([A-Za-z0-9+/=]{200,})['\"`]")
_SCRIPT_FILE = re.compile(r"(?:node|sh|bash|bun)\s+([\w./-]+\.(?:c?js|mjs|sh))")
_GYP_COMMAND = re.compile(r"<!@?\(([^)]{1,300})\)")


def focus_files(pkg: PackageFiles) -> list[str]:
    """Files that run at install time or when the package is required."""
    out: list[str] = []
    manifest = {}
    raw = pkg.text("package.json")
    if raw:
        try:
            manifest = json.loads(raw)
        except ValueError:
            manifest = {}
    scripts = manifest.get("scripts") or {}
    for hook in ("preinstall", "install", "postinstall"):
        cmd = scripts.get(hook) if isinstance(scripts, dict) else None
        if isinstance(cmd, str):
            for m in _SCRIPT_FILE.finditer(cmd):
                out.append(m.group(1).lstrip("./"))
    main = manifest.get("main")
    if isinstance(main, str):
        main = main.lstrip("./")
        out.append(main if "." in main.rsplit("/", 1)[-1] else main.rstrip("/") + "/index.js")
    else:
        out.append("index.js")
    bins = manifest.get("bin")
    if isinstance(bins, str):
        out.append(bins.lstrip("./"))
    elif isinstance(bins, dict):
        out.extend(str(v).lstrip("./") for v in bins.values())
    if "binding.gyp" in pkg.files:
        out.append("binding.gyp")
    seen: set[str] = set()
    return [p for p in out if p in pkg.files and not (p in seen or seen.add(p))]


def score_content(pkg: PackageFiles, max_hits_per_rule: int = 5) -> ContentScore:
    s = ContentScore(focus_files=focus_files(pkg))
    focus = set(s.focus_files)
    per_rule: dict[str, int] = {}
    scanned = [p for p in pkg.files if p.endswith(CODE_EXT) or p in focus or p == "package.json"]
    for path in scanned:
        text = pkg.text(path) or ""
        in_focus = path in focus or path == "package.json"
        for line_no, line in enumerate(text.splitlines(), start=1):
            for rule in RULES:
                if per_rule.get(rule.name, 0) >= max_hits_per_rule:
                    continue
                m = rule.pattern.search(line)
                if m:
                    per_rule[rule.name] = per_rule.get(rule.name, 0) + 1
                    start = m.start()
                    s.hits.append(Hit(rule.name, path, line_no, line[max(0, start - 80): start + 120].strip(), col=start))
        for m in _LONG_STRING.finditer(text):
            if _entropy(m.group(1)) > 5.0 and per_rule.get("high_entropy_blob", 0) < 3:
                per_rule["high_entropy_blob"] = per_rule.get("high_entropy_blob", 0) + 1
                line_no = text.count("\n", 0, m.start()) + 1
                s.hits.append(Hit("high_entropy_blob", path, line_no, m.group(1)[:80] + "..."))
        if path == "binding.gyp":
            for m in _GYP_COMMAND.finditer(text):
                s.hits.append(Hit("gyp_command", path, text.count("\n", 0, m.start()) + 1, m.group(0)[:200]))
        if in_focus:
            s.notes.append(f"focus:{path}")

    s.score = _weighted_score(s.hits, set(install_time_files(pkg)))
    return s


# Signals that are suspicious anywhere in a package. Everything else (spawning processes, network
# calls, reading the hostname, eval) is normal for CLIs and agent tools at runtime and only counts
# when it happens in code that runs at install time, or in a suspicious combination in one file.
STRONG_RULES = {"hardcoded_channel", "env_dump", "exfil_service", "eval_decoded", "pipe_to_shell", "obfuscator_names", "hex_dns_label", "injection_phrase", "gyp_command", "encoded_url"}
POINTS = {r.name: r.points for r in RULES} | {"high_entropy_blob": 2, "gyp_command": 4}
INSTALL_TIME_MULTIPLIER = 2


def install_time_files(pkg: PackageFiles) -> list[str]:
    """Files executed by npm lifecycle hooks or node-gyp during `npm install`."""
    manifest = {}
    raw = pkg.text("package.json")
    if raw:
        try:
            manifest = json.loads(raw)
        except ValueError:
            manifest = {}
    out = ["package.json"]
    scripts = manifest.get("scripts") or {}
    for hook in ("preinstall", "install", "postinstall"):
        cmd = scripts.get(hook) if isinstance(scripts, dict) else None
        if isinstance(cmd, str):
            out += [m.group(1).lstrip("./") for m in _SCRIPT_FILE.finditer(cmd)]
    if "binding.gyp" in pkg.files:
        out.append("binding.gyp")
    return [p for p in out if p in pkg.files]


def _weighted_score(hits: list[Hit], install_files: set[str]) -> int:
    by_file: dict[str, set[str]] = {}
    for h in hits:
        by_file.setdefault(h.path, set()).add(h.rule)
    score = 0
    counted: set[tuple[str, bool]] = set()
    for path, rules in by_file.items():
        install_time = path in install_files
        for rule in rules:
            if install_time:
                key = (rule, True)
                if key not in counted:
                    score += POINTS.get(rule, 1) * INSTALL_TIME_MULTIPLIER
                    counted.add(key)
            elif rule in STRONG_RULES or rule == "high_entropy_blob":
                key = (rule, False)
                if key not in counted:
                    score += POINTS.get(rule, 1)
                    counted.add(key)
        # suspicious combinations within one runtime file
        if not install_time:
            if {"secret_paths", "network_call"} <= rules:
                score += 6
            if {"env_dump", "network_call"} <= rules:
                score += 3
    return score
