import base64
import hashlib

from gatekeeper.guard.core import package_specs, verify_integrity


def test_install_specs_skip_flags_and_local_paths():
    args = ["install", "-D", "axios-retry@^4", "@types/node", "./local-dir", "file:../x", "--registry", "https://r.example", "lodash"]
    assert package_specs("npm", args) == ["axios-retry@^4", "@types/node", "lodash"]


def test_non_install_commands_are_not_checked():
    assert package_specs("npm", ["run", "build"]) == []
    assert package_specs("npm", ["install"]) == []  # lockfile install: out of scope for now
    assert package_specs("npm", ["test"]) == []


def test_exec_and_npx():
    assert package_specs("npx", ["-y", "create-vite@latest", "my-app"]) == ["create-vite@latest"]
    assert package_specs("npm", ["exec", "cowsay"]) == ["cowsay"]


def test_allow_flag_is_ignored_in_specs():
    assert package_specs("npm", ["i", "--gk-allow", "left-pad"]) == ["left-pad"]


def test_integrity_check():
    data = b"tarball bytes"
    good = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
    assert verify_integrity(data, good)
    assert not verify_integrity(b"tampered", good)
    assert verify_integrity(data, "sha1-abc")  # only sha512 is checked here


def test_rules_clean_but_classifier_suspicious_goes_to_the_model(monkeypatch):
    import gatekeeper.guard.core as core

    class Model:
        threshold = 0.5

        def risk(self, *a):
            return 0.9

    monkeypatch.setattr(core, "resolve", lambda cmd, spec: {"name": "quiet", "version": "1.0.0", "tarball": "x", "integrity": None})
    monkeypatch.setattr(core.httpx, "get", lambda *a, **k: type("R", (), {"content": b""})())
    monkeypatch.setattr(core, "verify_integrity", lambda data, integrity: True)
    from gatekeeper.npm.tarball import PackageFiles

    pkg = PackageFiles()
    pkg.files["package.json"] = b'{"name":"quiet"}'
    pkg.sizes["package.json"] = 16
    monkeypatch.setattr(core, "read_tarball", lambda data: pkg)
    asked = []

    def classify(bundle):
        asked.append(bundle)
        raise RuntimeError("model called")

    try:
        core.check_spec(["npm"], "quiet", classify=classify, fast_model=Model())
    except RuntimeError:
        pass
    assert asked, "a package the classifier flags must not take the rules-only fast path"


def test_model_decisions_are_cached_by_integrity(tmp_path, monkeypatch):
    import gatekeeper.guard.core as core

    monkeypatch.setattr(core, "CACHE_FILE", tmp_path / "verdicts.json")
    meta = {"name": "x", "version": "1.0.0", "integrity": "sha512-abc"}
    core._cache_put(meta, core.Decision("x", False, "Muse Glimmer: malicious", "x", "1.0.0"))
    assert core._cache_get(meta)["allowed"] is False
    assert core._cache_get({**meta, "integrity": "sha512-other"}) is None  # different bytes, no reuse
    assert core._cache_get({**meta, "integrity": None}) is None


def _fake_install(monkeypatch, tmp_path, meta, index=None):
    import json as js

    import gatekeeper.guard.core as core

    monkeypatch.setattr(core, "CACHE_FILE", tmp_path / "verdicts.json")
    monkeypatch.setattr(core, "MAL_INDEX_FILE", tmp_path / "mal.json")
    core._MAL_CACHE.clear()
    (tmp_path / "mal.json").write_text(js.dumps(index or {}))
    monkeypatch.setattr(core, "resolve", lambda cmd, spec: meta)
    monkeypatch.setattr(core, "_analyse", lambda *a: core.Decision("x", True, "static rules clean", meta["name"], meta["version"]))
    return core


def test_osv_listed_and_bad_dependency_are_blocked(monkeypatch, tmp_path):
    evil = {"evil": {"public": "2026-10-01T00:00:00Z", "all": True, "versions": []}}
    meta = {"name": "evil", "version": "1.0.0", "integrity": None, "time": {}, "dependencies": []}
    assert _fake_install(monkeypatch, tmp_path, meta, evil).check_spec(["npm"], "evil").kind == "osv"
    meta2 = {"name": "wrapper", "version": "1.0.0", "integrity": None, "time": {}, "dependencies": [("libsignal", "npm:evil@1")]}
    d = _fake_install(monkeypatch, tmp_path, meta2, evil).check_spec(["npm"], "wrapper")
    assert not d.allowed and d.kind == "dependency"


def test_brand_new_version_is_held_with_an_older_suggestion(monkeypatch, tmp_path):
    import time as t
    from datetime import datetime, timezone

    def iso(hours_ago):
        return datetime.fromtimestamp(t.time() - hours_ago * 3600, timezone.utc).isoformat()

    meta = {"name": "lib", "version": "2.0.0", "integrity": None, "dependencies": [],
            "time": {"created": iso(500), "1.9.0": iso(100), "2.0.0-beta.1": iso(30), "2.0.0": iso(2)}}
    core = _fake_install(monkeypatch, tmp_path, meta)
    d = core.check_spec(["npm"], "lib", min_age_hours=24)
    assert not d.allowed and d.kind == "too_new" and d.suggestion == "lib@1.9.0"
    assert core.check_spec(["npm"], "lib", min_age_hours=0).allowed
