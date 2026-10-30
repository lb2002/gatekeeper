import base64
import hashlib

from gatekeeper.guard.core import verify_integrity


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
    assert with_before("npm", ["run", "build"], 24, now) == [flag, "run", "build"]  # harmless; nested installs inherit it
    # added even here: only npm's own parse may decide a command is a read-only view (guard_run drops it then)
    assert with_before("npm", ["--editor", "view", "install", "x"], 24, now)[0] == flag
    assert with_before("npm", ["it", "x"], 24, now)[0] == flag and with_before("npm", ["audit", "fix"], 24, now)[0] == flag
    assert with_before("npm", ["install", "x", "--before=2020-01-01"], 24, now) == ["install", "x", "--before=2020-01-01"]
    assert with_before("npm", ["install", "x"], 0, now) == ["install", "x"]


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


def test_npm_itself_reads_project_context_and_side_doors(monkeypatch, tmp_path):
    import json

    import pytest

    from gatekeeper.guard.core import npm_native_parse

    exe = _real_npm()
    if exe is None:
        pytest.skip("npm not installed")
    monkeypatch.delenv("NPM_CONFIG_REGISTRY", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "package.json").write_text(json.dumps({"name": "t", "version": "1.0.0", "dependencies": {"lodash": "~4.17.20"}}))

    def read(*args):
        d = npm_native_parse(exe, "npm", list(args))
        assert d is not None
        return [(s["spec"], s["type"]) for s in d["specs"]]

    assert read("install", "lodash") == [("lodash@~4.17.20", "registry")]  # what arborist keeps, not latest
    assert read("link", "is-odd") == [("is-odd", "registry")]  # installs globally from the registry
    assert read("pack", "github:u/r") == [("github:u/r", "remote")]  # git builds run `prepare`
    assert read("exec", "--package=", "foo") == [("", "invalid")]
    (tmp_path / ".npmrc").write_text("before=notadate\n")
    d = npm_native_parse(exe, "npm", ["install", "is-odd"])
    assert d is not None and d["before"] == "invalid" and d["specs"][0].get("error")  # resolution fails: blocked


def test_a_named_package_resolves_its_package_json_range_not_the_lockfile(monkeypatch, tmp_path):
    """arborist re-resolves the saved range for packages named on the command line, whatever the lockfile says."""
    import json

    import pytest

    from gatekeeper.guard.core import npm_native_parse

    exe = _real_npm()
    if exe is None:
        pytest.skip("npm not installed")
    monkeypatch.delenv("NPM_CONFIG_REGISTRY", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "package.json").write_text(json.dumps({"name": "t", "version": "1.0.0", "dependencies": {"is-odd": "^3.0.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"name": "t", "lockfileVersion": 3, "packages": {
        "": {"name": "t"}, "node_modules/is-odd": {"version": "3.0.0", "resolved": "https://evil.example/x.tgz"}}}))
    d = npm_native_parse(exe, "npm", ["install", "is-odd"])
    assert d is not None
    assert [(s["spec"], s["version"]) for s in d["specs"] if s["type"] == "registry"] == [("is-odd@^3.0.0", "3.0.1")]
    # and the off-registry lock entry is reported on its own (it would be installed as a transitive dependency)
    assert [s["spec"] for s in d["specs"] if s["type"] == "remote"] == ["https://evil.example/x.tgz (package-lock: node_modules/is-odd)"]


def test_a_lockfile_pointing_away_from_the_registry_is_remote(monkeypatch, tmp_path):
    """npm installs locked transitive dependencies from their `resolved` URL as written; a cloned repo controls it."""
    import json

    import pytest

    from gatekeeper.guard.core import npm_native_parse

    exe = _real_npm()
    if exe is None:
        pytest.skip("npm not installed")
    monkeypatch.delenv("NPM_CONFIG_REGISTRY", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "package.json").write_text(json.dumps({"name": "t", "version": "1.0.0", "dependencies": {"is-odd": "^3.0.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"name": "t", "lockfileVersion": 3, "packages": {
        "": {"name": "t"},
        "node_modules/is-odd": {"version": "3.0.1", "resolved": "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"},
        "node_modules/is-number": {"version": "6.0.0", "resolved": "https://evil.example/x/-/is-number-6.0.0.tgz"},
        "node_modules/local": {"version": "1.0.0", "resolved": "file:../local"}}}))
    for args in (["ci"], ["install"], ["install", "lodash"]):
        d = npm_native_parse(exe, "npm", args)
        remote = [s["spec"] for s in d["specs"] if s["type"] == "remote"]
        assert remote == ["https://evil.example/x/-/is-number-6.0.0.tgz (package-lock: node_modules/is-number)"], args
    assert npm_native_parse(exe, "npm", ["run", "build"])["specs"] == []


def test_a_registry_set_by_the_project_npmrc_is_not_trusted(monkeypatch, tmp_path):
    import json

    import pytest

    from gatekeeper.guard.core import npm_native_parse

    exe = _real_npm()
    if exe is None:
        pytest.skip("npm not installed")
    monkeypatch.delenv("NPM_CONFIG_REGISTRY", raising=False)
    monkeypatch.delenv("GK_TRUST_PROJECT_REGISTRY", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "package.json").write_text(json.dumps({"name": "t", "version": "1.0.0"}))
    (tmp_path / ".npmrc").write_text("@evil:registry=https://evil.example/\n")
    (tmp_path / "package-lock.json").write_text(json.dumps({"name": "t", "lockfileVersion": 3, "packages": {
        "": {"name": "t"},
        "node_modules/is-odd": {"version": "3.0.1", "resolved": "https://evil.example/is-odd/-/is-odd-3.0.1.tgz"}}}))
    remote = [s["spec"] for s in npm_native_parse(exe, "npm", ["ci"])["specs"] if s["type"] == "remote"]
    assert remote == ["@evil:registry=https://evil.example/ (project .npmrc)",
                      "https://evil.example/is-odd/-/is-odd-3.0.1.tgz (package-lock: node_modules/is-odd)"]
    monkeypatch.setenv("GK_TRUST_PROJECT_REGISTRY", "1")  # trusting the scope still does not cover unscoped is-odd
    remote = [s["spec"] for s in npm_native_parse(exe, "npm", ["uninstall", "x"])["specs"] if s["type"] == "remote"]
    assert remote == ["https://evil.example/is-odd/-/is-odd-3.0.1.tgz (package-lock: node_modules/is-odd)"]


# Cases a hand-written parser once got wrong, now answered by the installed npm itself.
NATIVE_CASES = [
    ("npm", ["-s", "install", "is-odd"], [("is-odd", "registry")]),
    ("npm", ["-p", "install", "is-odd"], [("is-odd", "registry")]),  # top-level -p is --parseable
    ("npm", ["--loglevel", "warn", "install", "is-odd", "--save-dev"], [("is-odd", "registry")]),
    ("npm", ["install", "--", "is-odd"], [("is-odd", "registry")]),
    ("npm", ["--registry", "https://registry.npmjs.org/", "i", "is-odd", "--tag", "latest"], [("is-odd", "registry")]),
    ("npm", ["isnt", "is-odd"], [("is-odd", "registry")]),
    ("npm", ["exec", "--", "is-odd", "arg"], [("is-odd", "registry")]),
    ("npx", ["-p", "is-odd", "some-bin"], [("is-odd", "registry")]),
    ("npx", ["--package=is-odd", "-c", "some-bin --x"], [("is-odd", "registry")]),
    ("npx", ["--yes", "is-odd", "--flag"], [("is-odd", "registry")]),
    ("npm", ["install", "github:user/evil", "user/evil#main", "https://x.test/evil.tgz", "x@git+ssh://git@host/r.git",
             "./local-dir", "alias@npm:is-odd@3"],
     [("github:user/evil", "remote"), ("user/evil#main", "remote"), ("https://x.test/evil.tgz", "remote"),
      ("x@git+ssh://git@host/r.git", "remote"), ("./local-dir", "local"), ("alias@npm:is-odd@3", "registry")]),
    ("npm", ["run", "install"], []),  # a script called install
    ("npm", ["test"], []),
]


def test_native_parse_cases(monkeypatch, tmp_path):
    import pytest

    from gatekeeper.guard.core import npm_native_parse

    exe = _real_npm()
    if exe is None:
        pytest.skip("npm not installed")
    monkeypatch.delenv("NPM_CONFIG_REGISTRY", raising=False)
    monkeypatch.chdir(tmp_path)
    for tool, args, expected in NATIVE_CASES:
        d = npm_native_parse(exe, tool, args)
        assert d is not None, args
        assert [(s["spec"], s["type"]) for s in d["specs"]] == expected, (tool, args)
