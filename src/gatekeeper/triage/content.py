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
    _r("secret_paths", 4, r"\.npmrc|\.ssh[/\\]|id_rsa|\.aws[/\\]credentials|\.git-credentials|\.docker[/\\]config|Local State|Login Data|wallet\.dat|\.config[/\\]solana|metamask", ),
    _r("host_fingerprint", 1, r"os\.(?:userInfo|hostname|homedir|networkInterfaces)\(\)"),
    _r("exfil_service", 4, r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|webhook\.site|pipedream\.net|requestbin|ngrok\.io|oast\.(?:fun|me|pro|live|online|site)|interact\.sh|burpcollaborator|canarytokens"),
    _r("raw_ip_url", 3, r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?"),
    _r("eval_decoded", 4, r"(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|unescape)\s*\("),
    _r("dynamic_eval", 2, r"\beval\s*\(|new\s+Function\s*\("),
    _r("pipe_to_shell", 4, r"(?:curl|wget)[^\n|]{0,200}\|\s*(?:ba)?sh\b|powershell(?:\.exe)?\s+[^\n]{0,40}-e(?:nc|ncodedcommand)?\s"),
    _r("obfuscator_names", 3, r"_0x[0-9a-f]{4,}"),
    _r("hex_dns_label", 3, r"[0-9a-f]{20,}\.[a-z0-9-]+\.(?:com|net|org|io|xyz|fun|site|live|me)\b"),
    _r("detached_spawn", 2, r"detached\s*:\s*true|\.unref\(\)"),
    _r("injection_phrase", 3, r"(?:note|attention|message)\s+to\s+(?:the\s+)?(?:ai|llm|automated|security)\s+(?:reviewer|scanner|analy[sz]er)|ignore\s+(?:all\s+)?previous\s+instructions|this\s+package\s+(?:is|has\s+been)\s+(?:audited|verified)\s+(?:and\s+)?safe"),
)


@dataclass
class Hit:
    rule: str
    path: str
    line: int
    snippet: str


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
                if rule.pattern.search(line):
                    per_rule[rule.name] = per_rule.get(rule.name, 0) + 1
                    s.hits.append(Hit(rule.name, path, line_no, line.strip()[:200]))
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

    points = {r.name: r.points for r in RULES} | {"high_entropy_blob": 2, "gyp_command": 4}
    focus_hit_bonus = 0
    for rule_name in s.rules:
        s.score += points.get(rule_name, 1)
    if any(h.path in focus for h in s.hits if h.rule in {"child_process", "network_call", "env_dump", "secret_paths", "exfil_service", "eval_decoded", "pipe_to_shell"}):
        focus_hit_bonus = 2
    if {"child_process", "network_call"} <= s.rules or {"secret_paths", "network_call"} <= s.rules or {"host_fingerprint", "network_call"} <= s.rules:
        s.score += 2  # combinations matter more than single signals
    s.score += focus_hit_bonus
    return s
