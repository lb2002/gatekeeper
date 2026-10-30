"""Autonomous reports to OpenSSF malicious-packages, only for cases beyond reasonable doubt.

A version is reported automatically only if every check passes:

1. Code, re-read from the published archive at report time (sha512 integrity checked). npm must
   provably run it during `npm install`: a lifecycle script that is exactly `node <file>`, or the
   build actions of binding.gyp when npm's default `node-gyp rebuild` applies. In that code, with
   comments removed and within a few lines of each other, there must be
   - a request address whose host is a public request-collection service, a webhook endpoint
     (Discord, Telegram) or a raw global IP,
   - a read of the whole environment (`JSON.stringify(process.env)`, `/proc/<pid>/environ`, ...)
     or of a credential file (`.npmrc`, SSH keys, cloud credentials, mounted secrets),
   - a network request call.
2. Models: Muse Spark and Muse Spark Open both say malicious with confidence >= 0.9 and citations
   without errors; Muse Glimmer, if it answered, must agree in the same way. Llama Guard is the
   flagging stage and does not count.
3. Package: created at most 7 days ago, at most 30 versions, not on the popular list, no OSV entry
   and no pull request for the name yet, and no human review other than "malicious".

The report text is built from those static facts (quoted code, file, line, SHA-256), never from
model prose.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from gatekeeper.npm.tarball import PackageFiles

JUDGES = ("glimmer-local", "spark", "spark-open")
REQUIRED_JUDGES = ("spark", "spark-open")
SPARK_OPEN_HOSTS = ("spark-open-fireworks", "spark-open-baseten")
MIN_CONFIDENCE = 0.9
MAX_AGE = timedelta(days=7)
MAX_VERSIONS = 30
DAILY_LIMIT = 5
PROXIMITY_LINES = 30

# hosts whose only purpose is receiving requests for inspection; subdomains count
COLLECTION_HOSTS = (
    "webhook.site", "pipedream.net", "requestbin.net", "requestcatcher.com", "ngrok.io", "ngrok-free.app",
    "ngrok.app", "ngrok.dev", "oast.fun", "oast.me", "oast.pro", "oast.live", "oast.online", "oast.site",
    "oastify.com", "interact.sh", "burpcollaborator.net", "canarytokens.com", "dnslog.cn",
)
WEBHOOK_PATHS = {"discord.com": "/api/webhooks/", "discordapp.com": "/api/webhooks/", "api.telegram.org": "/bot"}

_URL = re.compile(r"https?://[^\s'\"`<>()\\,;]+", re.IGNORECASE)
_HOST_OPTION = re.compile(r"\bhost(?:name)?\s*:\s*['\"]([A-Za-z0-9.-]+)['\"](?:[^{}]{0,200}?\bpath\s*:\s*['\"](/[^'\"]*)['\"])?")
_REQUEST = re.compile(r"\bhttps?\.(?:request|get)\s*\(|\bfetch\s*\(|\baxios(?:\.(?:get|post|request))?\s*\(|\bnet\.connect\s*\(|\bcurl\s+-")
# `const h = require('https'); h.request(...)`: a .request/.get call counts once the module is loaded
_NET_MODULE = re.compile(r"\brequire\(\s*['\"](?:node:)?(?:https?|net)['\"]\s*\)")
_REQUEST_METHOD = re.compile(r"\.(?:request|get)\s*\(")
_ENV_READ = re.compile(r"JSON\.stringify\(\s*process\.env\s*\)|Object\.entries\(\s*process\.env\s*\)|\{\s*\.\.\.process\.env\s*\}|/proc/(?:\d+|self)/environ")
_CREDENTIAL = r"\.npmrc|\.ssh/id_\w+|\.aws/credentials|\.git-credentials|\.docker/config\.json|\.kube/config|/(?:var/)?run/secrets"
_CREDENTIAL_READ = re.compile(rf"\breadFile(?:Sync)?\s*\([^)]{{0,200}}?({_CREDENTIAL})|\bcat\s+[^'\"\n|;&]{{0,80}}?({_CREDENTIAL})")
# dependency-confusion probes send the host's identity instead of secrets; one call alone is ordinary code
_HOST_READ = re.compile(r"\bos\.(hostname|homedir|userInfo)\s*\(\s*\)")
_SCRIPT = re.compile(r"(?:node|bun)\s+(?:\./)?((?:[\w-][\w.-]*/)*[\w-][\w.-]*\.(?:c?js|mjs))")

UPSTREAM = "ossf/malicious-packages"
FORK_OWNER = "lb2002"
AUTHOR = {"name": "Linus Baumberger", "email": "81171023+lb2002@users.noreply.github.com"}
SIGN_OFF = f"Signed-off-by: {AUTHOR['name']} <{AUTHOR['email']}>"


@dataclass
class Fact:
    kind: str  # "destination", "read" or "request"
    line: int
    text: str  # the quoted code
    note: str = ""  # what it is, e.g. the host


@dataclass
class Evidence:
    version: str
    file: str
    sha256: str
    how_it_runs: str
    unit: str  # where in the file, e.g. "lines 3-20" or "the build action `x`"
    facts: list[Fact] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)  # collection-service hosts and raw IPs (IoCs)
    urls: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- model gate

def judge_verdicts(verdicts: dict) -> dict[str, dict]:
    """Known judges only; the two Spark Open hosts are one judge (weakest answer counts)."""
    out: dict[str, dict] = {}
    for backend, v in (verdicts or {}).items():
        if not isinstance(v, dict) or not v.get("verdict"):
            continue
        judge = "spark-open" if backend in SPARK_OPEN_HOSTS else backend
        if judge not in JUDGES:
            continue
        if judge in out:
            prev = out[judge]
            v = {"verdict": prev["verdict"] if prev["verdict"] != "malicious" else v["verdict"],
                 "confidence": min(prev.get("confidence") or 0, v.get("confidence") or 0),
                 "errors": list(prev.get("errors") or []) + list(v.get("errors") or [])}
        out[judge] = v
    return out


def models_agree(verdicts: dict) -> tuple[bool, str]:
    if ((verdicts or {}).get("investigator") or {}).get("verdict") == "benign":
        return False, "the investigator read further and says benign"
    judges = judge_verdicts(verdicts)
    for j in REQUIRED_JUDGES:
        if j not in judges:
            return False, f"waiting for {j}"
    for j, v in judges.items():
        if v["verdict"] != "malicious":
            return False, f"{j} says {v['verdict']}"
        if (v.get("confidence") or 0) < MIN_CONFIDENCE:
            return False, f"{j} confidence {v.get('confidence')}"
        if v.get("errors"):
            return False, f"{j} citation errors"
    return True, ", ".join(sorted(judges))


def package_is_new(doc: dict, popular: set[str], now: datetime) -> tuple[bool, str]:
    if doc.get("name", "") in popular:
        return False, "popular package"
    created = (doc.get("time") or {}).get("created")
    if not created or now - datetime.fromisoformat(created.replace("Z", "+00:00")) > MAX_AGE:
        return False, "package older than 7 days"
    if len(doc.get("versions") or {}) > MAX_VERSIONS:
        return False, "too many versions"
    return True, "new package"


# ---------------------------------------------------------------- static gate

def strip_js_comments(code: str) -> str:
    """Remove // and /* */ comments outside string literals; newlines are kept so line numbers hold.
    Regex literals are not recognised, which can only remove code, never add it."""
    out, i, n = [], 0, len(code)
    quote = None
    while i < n:
        c = code[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(code[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
        elif c in "'\"`":
            quote = c
            out.append(c)
            i += 1
        elif code.startswith("//", i):
            j = code.find("\n", i)
            i = n if j < 0 else j
        elif code.startswith("/*", i):
            j = code.find("*/", i + 2)
            out.append("\n" * code.count("\n", i, n if j < 0 else j))
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _destination(host: str, path: str) -> str | None:
    """'ip', 'service' or 'webhook' if a request to host+path goes to a collection endpoint."""
    host = host.lower().rstrip(".")
    try:
        return "ip" if ipaddress.ip_address(host).is_global else None
    except ValueError:
        pass
    if any(host == h or host.endswith("." + h) for h in COLLECTION_HOSTS):
        return "service"
    if host in WEBHOOK_PATHS and path.startswith(WEBHOOK_PATHS[host]):
        return "webhook"
    return None


def _unit_facts(code: str) -> tuple[list[Fact], list[str], list[str]] | None:
    """Facts for one piece of install-time code, or None unless destination, read and request are
    all present and a destination lies within PROXIMITY_LINES of a read."""
    lines = code.splitlines() or [code]
    dests, reads, requests, host_reads = [], [], [], []
    hosts, urls = set(), set()
    for no, line in enumerate(lines, start=1):
        for m in _URL.finditer(line):
            parts = urlsplit(m.group(0))
            kind = _destination(parts.hostname or "", parts.path or "")
            if kind:
                dests.append(Fact("destination", no, m.group(0), kind))
                urls.add(m.group(0))
                if kind in ("ip", "service"):
                    hosts.add(parts.hostname.lower())
        for m in _HOST_OPTION.finditer(line):
            host, path = m.group(1), m.group(2) or ""
            kind = _destination(host, path)
            if kind:
                dests.append(Fact("destination", no, m.group(0), kind))
                urls.add(f"https://{host.lower()}{path}")
                if kind in ("ip", "service"):
                    hosts.add(host.lower())
        for m in _ENV_READ.finditer(line):
            reads.append(Fact("read", no, m.group(0), "environment"))
        for m in _CREDENTIAL_READ.finditer(line):
            reads.append(Fact("read", no, m.group(0), m.group(1) or m.group(2)))
        host_reads += [Fact("read", no, m.group(0), "host") for m in _HOST_READ.finditer(line)]
        for m in _REQUEST.finditer(line):
            requests.append(Fact("request", no, m.group(0)))
    if not requests and _NET_MODULE.search(code):
        for no, line in enumerate(lines, start=1):
            requests += [Fact("request", no, m.group(0)) for m in _REQUEST_METHOD.finditer(line)]
    if len({f.text for f in host_reads}) >= 2:
        reads += host_reads
    if not (dests and reads and requests):
        return None
    if not any(abs(d.line - r.line) <= PROXIMITY_LINES for d in dests for r in reads):
        return None
    facts = _dedupe(dests)[:3] + _dedupe(reads)[:4] + _dedupe(requests)[:1]
    return facts, sorted(hosts), sorted(urls)


def _dedupe(facts: list[Fact]) -> list[Fact]:
    seen, out = set(), []
    for f in facts:
        if f.text not in seen:
            seen.add(f.text)
            out.append(f)
    return out


def _manifest(pkg: PackageFiles) -> dict | None:
    try:
        m = json.loads(pkg.text("package.json") or "")
    except ValueError:
        return None
    return m if isinstance(m, dict) else None


def _scripts(manifest: dict) -> dict[str, str]:
    s = manifest.get("scripts")
    return {h: c.strip() for h, c in s.items() if isinstance(c, str) and c.strip()} if isinstance(s, dict) else {}


def _gyp_actions(text: str) -> list[tuple[str, str]] | None:
    """(action name, command) for every build action and <!( ) command, or None if unparsable."""
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    try:
        doc = json.loads(body)
    except ValueError:
        try:
            doc = ast.literal_eval(body)
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            return None
    found: list[tuple[str, str]] = []

    def walk(node):
        if isinstance(node, dict):
            action = node.get("action")
            if isinstance(action, list) and all(isinstance(a, str) for a in action):
                found.append((str(node.get("action_name", "unnamed")), " ".join(action)))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, str) and "<!" in node:
            found.append(("command expansion", node))

    walk(doc)
    return found


def install_evidence(pkg: PackageFiles, version: str) -> Evidence | None:
    """Static proof from the archive itself, or None if the code does not meet check 1."""
    manifest = _manifest(pkg)
    if manifest is None:
        return None
    scripts = _scripts(manifest)
    for hook in ("preinstall", "install", "postinstall"):
        m = _SCRIPT.fullmatch(scripts.get(hook, ""))
        if not m or ".." in m.group(1).split("/"):
            continue
        path = m.group(1)
        if path not in pkg.files or path in pkg.truncated:
            continue
        found = _unit_facts(strip_js_comments(pkg.text(path) or ""))
        if found:
            facts, hosts, urls = found
            lines = [f.line for f in facts]
            how = f"its `{hook}` script is `{_code(scripts[hook])}`, which npm runs during `npm install`"
            return Evidence(version, path, hashlib.sha256(pkg.files[path]).hexdigest(), how,
                            f"lines {min(lines)}-{max(lines)}", facts, hosts, urls)
    if "binding.gyp" in pkg.files and "binding.gyp" not in pkg.truncated and manifest.get("gypfile") is not False:
        if "install" not in scripts and "preinstall" not in scripts:
            how = ("it ships a binding.gyp and has no install or preinstall script, so `npm install` runs "
                   "`node-gyp rebuild`, which executes the build actions declared in binding.gyp")
        elif scripts.get("install") == "node-gyp rebuild" and "preinstall" not in scripts:
            how = "its `install` script is `node-gyp rebuild`, which executes the build actions declared in binding.gyp"
        else:
            return None
        for name, command in _gyp_actions(pkg.text("binding.gyp") or "") or []:
            found = _unit_facts(strip_js_comments(command))
            if found:
                facts, hosts, urls = found
                return Evidence(version, "binding.gyp", hashlib.sha256(pkg.files["binding.gyp"]).hexdigest(), how,
                                f"the build action `{_code(name, 60)}`", facts, hosts, urls)
    return None


# ---------------------------------------------------------------- report text

def _code(text: str, limit: int = 120) -> str:
    """Attacker-controlled text for a single Markdown code span: osv.dev renders `details` as
    Markdown, so quoted code must not be able to add links, mentions or formatting."""
    flat = " ".join(text.split()).replace("`", "'")
    return flat[:limit] + ("…" if len(flat) > limit else "")


def _fact_text(f: Fact, lines: bool) -> str:
    where = f" (line {f.line})" if lines else ""
    if f.kind == "destination":
        what = {"ip": "a request address with a raw public IP", "service": "a request address on a public request-collection service",
                "webhook": "a webhook address"}[f.note]
        return f"{what}, `{_code(f.text, 100)}`{where}"
    if f.kind == "read":
        what = {"environment": "a read of the process environment", "host": "a read of the machine's identity"}.get(
            f.note, f"a read of the credential path `{_code(f.note, 40)}`")
        return f"{what}, `{_code(f.text, 80)}`{where}"
    return f"a network request call, `{_code(f.text, 40)}`{where}"


def _join(parts: list[str]) -> str:
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def build_osv(name: str, evidence: list[Evidence], published: dict[str, str], judges: str, now: datetime) -> dict:
    """OSV report from static facts. `published` maps version -> publish time (ISO)."""
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    bullets = []
    for e in evidence:
        when = (published.get(e.version) or "")[:16].replace("T", " ")
        bullets.append(
            f"- {e.version}{f' (published {when} UTC)' if when else ''}: {e.how_it_runs}. In `{e.file}` "
            f"(SHA-256 `{e.sha256}`), {e.unit} contain{'s' if e.unit.startswith('the ') else ''} "
            + _join([_fact_text(f, e.file != "binding.gyp") for f in e.facts]) + "."
        )
    details = (
        f"{name} runs code during `npm install` that reads the process environment, credential files or the machine's identity and contains "
        f"a request to an external collection endpoint:\n\n" + "\n".join(bullets) + "\n\n"
        f"The code is quoted from the published archive. Gatekeeper (https://github.com/lb2002/gatekeeper) flagged it "
        f"statically, and the Meta models {judges} classified it as malicious. Submitted automatically by Gatekeeper on "
        f"behalf of Linus Baumberger (https://github.com/lb2002)."
    )
    files = {}
    for e in evidence:
        files.setdefault(e.sha256, {"source": "PACKAGE_ARCHIVE", "paths": [e.file], "digests": {"sha256": e.sha256},
                                    "note": f"Run during npm install ({e.unit})."})
    hosts = {h for e in evidence for h in e.hosts}
    ips = {h for h in hosts if _is_ip(h)}
    return {
        "schema_version": "1.7.4",
        "modified": stamp,
        "published": stamp,
        "details": details,
        "affected": [{
            "package": {"ecosystem": "npm", "name": name},
            "versions": [e.version for e in evidence],
            "database_specific": {"cwes": [{"cweId": "CWE-506", "name": "Embedded Malicious Code",
                                            "description": "The product contains code that appears to be malicious in nature."}]},
        }],
        "references": [{"type": "PACKAGE", "url": f"https://www.npmjs.com/package/{name}"}],
        "credits": [{"name": "Linus Baumberger (Gatekeeper)", "contact": ["https://github.com/lb2002"], "type": "FINDER"}],
        "database_specific": {"iocs": {
            "domains": sorted(hosts - ips),
            "ips": sorted(ips),
            "urls": sorted({u for e in evidence for u in e.urls}),
            "files": list(files.values()),
        }},
    }


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- GitHub

def report_path(name: str) -> str:
    return f"osv/malicious/npm/{name}/MAL-0000-gatekeeper-{slug(name)}.json"


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def branch_name(name: str) -> str:
    """Deterministic, so a second attempt for the same package fails instead of opening a duplicate."""
    return f"gatekeeper-{slug(name)}"


def existing_pr(client, name: str) -> str | None:
    """URL of any pull request (any state) that already reports this package: ours by branch, or
    anyone's by title."""
    r = client.get(f"/repos/{UPSTREAM}/pulls", params={"head": f"{FORK_OWNER}:{branch_name(name)}", "state": "all"})
    r.raise_for_status()
    if r.json():
        return r.json()[0]["html_url"]
    r = client.get("/search/issues", params={"q": f'repo:{UPSTREAM} is:pr in:title "{name}"'})
    r.raise_for_status()
    hit = next((it for it in r.json().get("items", []) if name in (it.get("title") or "").split()), None)
    return hit["html_url"] if hit else None


def submit(client, osv: dict, name: str) -> dict:
    """Branch in the fork, add the report, open the pull request. Raises on any HTTP error; the
    deterministic branch name makes a retry fail rather than duplicate."""
    path = report_path(name)
    content = base64.b64encode((json.dumps(osv, indent=2, ensure_ascii=False) + "\n").encode()).decode()
    branch = branch_name(name)
    base = client.get(f"/repos/{UPSTREAM}/git/ref/heads/main")
    base.raise_for_status()
    client.post(f"/repos/{FORK_OWNER}/malicious-packages/git/refs",
                json={"ref": f"refs/heads/{branch}", "sha": base.json()["object"]["sha"]}).raise_for_status()
    client.put(f"/repos/{FORK_OWNER}/malicious-packages/contents/{path}", json={
        "message": f"Add malicious npm package `{name}`\n\n{SIGN_OFF}", "branch": branch,
        "content": content, "author": AUTHOR, "committer": AUTHOR,
    }).raise_for_status()
    pr = client.post(f"/repos/{UPSTREAM}/pulls", json={
        "title": f"Add malicious npm package {name}", "head": f"{FORK_OWNER}:{branch}", "base": "main",
        "body": "Submitted automatically by Gatekeeper (https://github.com/lb2002/gatekeeper) on behalf of Linus Baumberger, "
                "who maintains it. Gatekeeper only submits on its own when the install-time code in the published archive "
                "reads the environment, credential files or the machine's identity and sends a request to an external "
                "collection endpoint, and "
                "Muse Spark and Muse Spark Open both classify the version as malicious. The code in the report is quoted "
                "from the archive (file, location, SHA-256).",
    })
    pr.raise_for_status()
    return {"branch": branch, "pr": pr.json()["html_url"], "path": path}
