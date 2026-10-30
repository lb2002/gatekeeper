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


def test_online_osv_hit_blocks_even_with_an_empty_local_list(monkeypatch, tmp_path):
    import httpx

    meta = {"name": "fresh-evil", "version": "1.0.0", "integrity": None, "time": {}, "dependencies": []}
    core = _fake_install(monkeypatch, tmp_path, meta)
    monkeypatch.setattr(core, "OSV_ONLINE", True)

    def fake_post(url, json, timeout):
        assert json == {"package": {"name": "fresh-evil", "ecosystem": "npm"}, "version": "1.0.0"}
        return httpx.Response(200, json={"vulns": [{"id": "MAL-2026-1", "published": "2026-10-30T00:00:00Z"}]},
                              request=httpx.Request("POST", url))

    monkeypatch.setattr(core.httpx, "post", fake_post)
    d = core.check_spec(["npm"], "fresh-evil")
    assert not d.allowed and d.kind == "osv" and "MAL-2026-1" in d.reason


def test_offline_osv_check_fails_open_to_the_other_checks(monkeypatch, tmp_path):
    import httpx

    meta = {"name": "lib", "version": "1.0.0", "integrity": None, "time": {}, "dependencies": []}
    core = _fake_install(monkeypatch, tmp_path, meta)
    monkeypatch.setattr(core, "OSV_ONLINE", True)

    def no_network(*a, **k):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(core.httpx, "post", no_network)
    assert core.check_spec(["npm"], "lib", min_age_hours=0).allowed


def test_waiting_period_reaches_the_whole_dependency_tree():
    from gatekeeper.guard.core import with_before

    now = 1_793_318_400.0  # 2026-10-30T00:00:00Z
    flag = "--before=2026-10-29T00:00:00Z"
    assert with_before("npm", ["install", "lodash"], 24, now) == [flag, "install", "lodash"]
    assert with_before("npm", ["install"], 24, now) == [flag, "install"]  # from package.json
    assert with_before("npm", ["--loglevel", "warn", "i", "x"], 24, now) == [flag, "--loglevel", "warn", "i", "x"]
    assert with_before("npm", ["update"], 72, now) == ["--before=2026-10-27T00:00:00Z", "update"]
    assert with_before("npm", ["exec", "pkg", "--", "--x"], 24, now) == [flag, "exec", "pkg", "--", "--x"]
    assert with_before("npm", ["--", "install", "evil"], 24, now) == [flag, "--", "install", "evil"]  # never after --
    assert with_before("npm", ["create", "vite"], 24, now) == [flag, "create", "vite"]
    assert with_before("npx", ["cowsay", "--x"], 24, now) == [flag, "cowsay", "--x"]
    assert with_before("npm", ["run", "build"], 24, now) == ["run", "build"]
    assert with_before("npm", ["install", "x", "--before=2020-01-01"], 24, now) == ["install", "x", "--before=2020-01-01"]
    assert with_before("npm", ["install", "x"], 0, now) == ["install", "x"]


def test_leading_options_do_not_hide_the_install():
    from gatekeeper.guard.core import package_specs

    assert package_specs("npm", ["-s", "install", "evil"]) == ["evil"]
    assert package_specs("npm", ["--loglevel", "warn", "install", "evil", "--save-dev"]) == ["evil"]
    assert package_specs("npm", ["--some-new-flag", "value", "install", "evil"]) == ["evil"]  # unknown value: skipped
    assert package_specs("npm", ["--registry", "http://r", "i", "a", "--tag", "next", "b"]) == ["a", "b"]
    assert package_specs("npm", ["run", "install"]) == []  # a script called install


def test_npx_packages_given_with_p_are_the_ones_checked():
    from gatekeeper.guard.core import package_specs

    assert package_specs("npx", ["-p", "evil", "some-bin"]) == ["evil"]
    assert package_specs("npx", ["--package=evil", "-c", "some-bin --x"]) == ["evil"]
    assert package_specs("npx", ["--yes", "cowsay", "hi"]) == ["cowsay"]
    assert package_specs("npm", ["exec", "-p", "evil", "--", "bin"]) == ["evil"]


def test_installs_from_git_or_urls_are_recognised_and_not_sent_to_the_registry_check():
    from gatekeeper.guard.core import package_specs, registry_args, remote_specs

    args = ["install", "github:user/evil", "user/evil#main", "https://x.test/evil.tgz", "x@git+ssh://git@host/r.git",
            "lodash", "@scope/pkg", "alias@npm:lodash@4", "./local-dir", "file:../pkg"]
    assert remote_specs("npm", args) == ["github:user/evil", "user/evil#main", "https://x.test/evil.tgz",
                                         "x@git+ssh://git@host/r.git"]
    assert package_specs("npm", args) == ["lodash", "@scope/pkg", "alias@npm:lodash@4"]
    assert remote_specs("npx", ["github:user/tool"]) == ["github:user/tool"]
    assert registry_args(["install", "--registry", "http://r.test", "x"]) == ["--registry", "http://r.test"]
    assert registry_args(["--registry=http://r.test", "i", "x"]) == ["--registry", "http://r.test"]
    assert registry_args(["install", "x"]) == []


def test_parser_differentials_fail_closed():
    from gatekeeper.guard.core import package_specs, with_before

    assert package_specs("npm", ["-p", "install", "evil"]) == ["evil"]  # top-level -p is --parseable (no value)
    assert package_specs("npm", ["install", "--", "evil"]) == ["evil"]
    assert package_specs("npm", ["install", "ok", "--", "evil"]) == ["ok", "evil"]
    assert package_specs("npm", ["exe", "evil"]) == ["evil"]  # a command prefix npm may accept
    assert package_specs("npx", ["--pack", "evil", "bin"]) == ["evil"]
    assert package_specs("npx", ["-p=evil", "bin"]) == ["evil"]
    assert package_specs("npx", ["--packa=evil", "--package", "evil2", "bin"]) == ["evil", "evil2"]
    assert package_specs("npx", ["--", "evil", "--flag"]) == ["evil"]
    assert package_specs("npm", ["exec", "--", "evil", "arg"]) == ["evil"]
    assert with_before("npm", ["-p", "i", "x"], 24, 1_793_318_400.0) == ["--before=2026-10-29T00:00:00Z", "-p", "i", "x"]


def _real_npm():
    import shutil

    from gatekeeper.guard.core import npm_root

    exe = shutil.which("npm.cmd") or shutil.which("npm")
    return exe if exe and npm_root(exe) else None


def test_npm_itself_reads_the_command_line(monkeypatch):
    """The cases a review found the Python parser getting wrong, read by the installed npm (registry metadata
    only; nothing is installed or run). Skipped without npm."""
    import pytest

    from gatekeeper.guard.core import npm_native_parse

    exe = _real_npm()
    if exe is None:
        pytest.skip("npm not installed")
    monkeypatch.delenv("NPM_CONFIG_REGISTRY", raising=False)

    def read(tool, *args):
        d = npm_native_parse(exe, tool, list(args))
        assert d is not None
        return d["command"], [(s["spec"], s["type"]) for s in d["specs"]]

    assert read("npm", "-p", "install", "lodash") == ("install", [("lodash", "registry")])
    assert read("npm", "it", "lodash") == ("install-test", [("lodash", "registry")])
    assert read("npm", "--editor", "view", "install", "lodash") == ("install", [("lodash", "registry")])
    assert read("npm", "create", "vite@5") == ("init", [("create-vite@5", "registry")])
    assert read("npx", "--editor", "lodash", "cowsay") == ("exec", [("cowsay", "registry")])
    assert read("npm", "install", "https://evil.example/x.tgz?@npm:") == ("install", [("https://evil.example/x.tgz?@npm:", "remote")])
    assert read("npm", "install", "git@github.com:u/r") == ("install", [("git@github.com:u/r", "remote")])
    assert read("npm", "run", "build") == ("run-script", [])
