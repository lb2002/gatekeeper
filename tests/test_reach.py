"""Install reachability, and the check that holds a verdict's trigger claim against it."""

import json

from gatekeeper.evidence.bundle import Bundle, Excerpt
from gatekeeper.evidence.reach import reachable, runs_at_install
from gatekeeper.investigate import trigger_errors
from gatekeeper.npm.tarball import PackageFiles
from gatekeeper.report import auto
from gatekeeper.schema import Verdict


def pkg_of(scripts: dict, files: dict[str, bytes]) -> PackageFiles:
    files = {"package.json": json.dumps({"name": "a", "scripts": scripts}).encode(), **files}
    return PackageFiles(files=files, sizes={p: len(b) for p, b in files.items()})


def test_follows_requires_and_imports_from_the_hook():
    pkg = pkg_of({"postinstall": "node ./bin/build.js && echo done"}, {
        "bin/build.js": b"const c = require('../lib/config')\nimport('./steps/a.mjs')\n",
        "lib/config.js": b"import x from './util'\n",
        "lib/util/index.js": b"module.exports = 1\n",
        "bin/steps/a.mjs": b"export default 1\n",
        "bin/cli.js": b"telegram()\n",
    })
    assert runs_at_install(pkg) == {"bin/build.js", "lib/config.js", "lib/util/index.js", "bin/steps/a.mjs"}


def test_no_hook_means_nothing_runs_at_install():
    assert runs_at_install(pkg_of({"test": "node a.js"}, {"a.js": b"1"})) == set()


def test_import_cycles_terminate():
    pkg = pkg_of({}, {"a.js": b"require('./b')", "b.js": b"require('./a')"})
    assert reachable(pkg, {"a.js"}) == {"a.js", "b.js"}


def test_binding_gyp_counts_as_install_time():
    assert "binding.gyp" in runs_at_install(pkg_of({}, {"binding.gyp": b"{}"}))


def verdict(trigger: str, label: str = "malicious") -> Verdict:
    return Verdict.model_validate({
        "verdict": label, "confidence": 0.9, "category": "exfiltration", "trigger": trigger, "iocs": [],
        "evidence": [{"excerpt_id": "T1", "line_start": 1, "line_end": 1, "why": "w"}],
        "injection_attempt_observed": False, "summary": "s"})


PKG = pkg_of({"postinstall": "node bin/build.js"}, {"bin/build.js": b"1", "bin/cli.js": b"telegram()"})


def cited(path: str) -> Bundle:
    return Bundle("a", "1", excerpts=[Excerpt("T1", path, 1, ["x"])])


def test_install_claim_on_code_the_hook_never_reaches_is_not_proven():
    # the esoftplay false positive: a build command in the CLI, blamed on the postinstall hook
    assert "not reachable" in trigger_errors(verdict("install_script"), cited("bin/cli.js"), PKG)[0]


def test_install_claim_on_reachable_code_stands():
    assert trigger_errors(verdict("install_script"), cited("bin/build.js"), PKG) == []


def test_an_inline_install_hook_is_cited_from_package_json():
    pkg = pkg_of({"postinstall": "node -e \"require('http').get('http://192.0.2.1')\""}, {})
    assert trigger_errors(verdict("install_script"), cited("package.json"), pkg) == []


def test_other_triggers_are_not_checked():
    assert trigger_errors(verdict("bin"), cited("bin/cli.js"), PKG) == []
    assert trigger_errors(verdict("install_script", "benign"), cited("bin/cli.js"), PKG) == []


def test_a_benign_investigation_stops_the_automatic_report():
    bad = {"verdict": "malicious", "confidence": 0.95, "errors": []}
    verdicts = {"spark": bad, "spark-open-fireworks": bad, "investigator": {"verdict": "benign"}}
    assert auto.models_agree(verdicts)[0] is False
