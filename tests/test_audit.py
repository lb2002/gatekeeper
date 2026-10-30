"""`gk audit`: lockfile parsing and the checks. Package names here are invented; nothing is installed."""

import json

import httpx
import pytest

from gatekeeper import audit as au

INDEX = {"evil-pkg": {"public": "2026-10-01T00:00:00Z", "all": True, "versions": []},
         "hijacked": {"public": "2026-09-01T00:00:00Z", "all": False, "versions": ["2.0.1"]}}
REG = "https://registry.npmjs.org"


def lock_v3(packages: dict) -> str:
    return json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "app"}, **packages}})


def test_npm_lockfile_v3_with_nested_and_scoped_packages():
    text = lock_v3({"node_modules/a": {"version": "1.0.0", "resolved": f"{REG}/a/-/a-1.0.0.tgz", "integrity": "sha512-x"},
                    "node_modules/a/node_modules/@s/b": {"version": "2.0.0", "hasInstallScript": True},
                    "packages/local": {"name": "local", "version": "0.0.1", "link": False}})
    locked = au.parse_npm(text)
    assert [(p.name, p.version) for p in locked] == [("a", "1.0.0"), ("@s/b", "2.0.0"), ("local", "0.0.1")]
    assert locked[1].install_script


def test_workspace_links_are_skipped():
    assert au.parse_npm(lock_v3({"node_modules/w": {"resolved": "packages/w", "link": True}})) == []


def test_npm_lockfile_v1():
    text = json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}})
    assert [(p.name, p.version) for p in au.parse_npm(text)] == [("a", "1.0.0"), ("b", "2.0.0")]


def test_yarn_lock():
    text = '''# yarn lockfile v1

"@s/a@^1.0.0":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@s/a/-/a-1.2.3.tgz#abc"
  integrity sha512-x

b@~2.0.0, b@^2.0.1:
  version "2.0.5"
  resolved "https://evil.example/b.tgz"
'''
    locked = au.parse_yarn(text)
    assert [(p.name, p.version) for p in locked] == [("@s/a", "1.2.3"), ("b", "2.0.5")]
    assert locked[0].integrity and not locked[1].integrity and locked[1].resolved.startswith("https://evil")


def test_pnpm_lock():
    text = "lockfileVersion: '9.0'\n\nimporters:\n\npackages:\n\n  '@s/a@1.2.3':\n    resolution: {integrity: sha512-x}\n\n  b@2.0.5(peer@1.0.0):\n    resolution: {integrity: sha512-y}\n\nsnapshots:\n\n  c@9.9.9:\n    dependencies: {}\n"
    assert [(p.name, p.version) for p in au.parse_pnpm(text)] == [("@s/a", "1.2.3"), ("b", "2.0.5")]


def test_known_malware_by_name_or_exact_version():
    locked = [au.Locked("evil-pkg", "1.0.0"), au.Locked("hijacked", "2.0.1"), au.Locked("hijacked", "2.0.0"), au.Locked("fine", "1.0.0")]
    assert [(f.name, f.version) for f in au.check_index(locked, INDEX)] == [("evil-pkg", "1.0.0"), ("hijacked", "2.0.1")]


def test_npm_security_placeholder_means_it_was_removed():
    assert au.check_index([au.Locked("gone", "0.0.1-security")], {})[0].kind == au.MALICIOUS


def test_a_poisoned_lockfile_entry_is_severe():
    found = au.check_index([au.Locked("lodash", "4.17.21", "https://evil.example/lodash.tgz", True)], {})
    assert found[0].kind == au.UNTRUSTED_SOURCE and "evil.example" in found[0].detail
    assert au.check_index([au.Locked("a", "1.0.0", "git+ssh://git@github.com/x/y.git#abc", True)], {})[0].kind == au.UNTRUSTED_SOURCE


def test_registry_sources_and_local_files_are_fine():
    locked = [au.Locked("a", "1.0.0", f"{REG}/a/-/a-1.0.0.tgz", True), au.Locked("b", "1.0.0", "https://registry.yarnpkg.com/b/-/b.tgz", True),
              au.Locked("c", "1.0.0", "file:vendor/c", True)]
    assert au.check_index(locked, {}) == []


def test_a_lookalike_registry_host_is_not_trusted():
    found = au.check_index([au.Locked("a", "1.0.0", "https://registry.npmjs.org.evil.example/a.tgz", True)], {})
    assert found and found[0].kind == au.UNTRUSTED_SOURCE


def test_missing_integrity_is_a_note_not_severe():
    report = au.audit([au.Locked("a", "1.0.0", f"{REG}/a.tgz", False)], {}, online=False)
    assert report["findings"][0]["kind"] == au.NO_INTEGRITY and not report["severe"]


def test_osv_batch_finds_what_the_list_does_not_have_yet(monkeypatch):
    def handler(request):
        body = json.loads(request.content)
        assert all(set(q) == {"package", "version"} for q in body["queries"])  # names and versions, nothing else
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "MAL-2026-1"}, {"id": "GHSA-x"}]}, {}]})

    real = httpx.Client
    monkeypatch.setattr(au.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler)))
    report = au.audit([au.Locked("a", "1.0.0"), au.Locked("b", "1.0.0")], {})
    assert report["severe"] and report["osv_online"] and report["findings"][0]["detail"] == "reported as malware: MAL-2026-1"


def test_no_network_still_gives_the_offline_answer(monkeypatch):
    def boom(request):
        raise httpx.ConnectError("offline")

    real = httpx.Client
    monkeypatch.setattr(au.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(boom)))
    report = au.audit([au.Locked("evil-pkg", "1.0.0")], INDEX)
    assert report["severe"] and not report["osv_online"]


def test_read_lockfile_prefers_npm_and_reports_a_missing_one(tmp_path):
    with pytest.raises(FileNotFoundError):
        au.read_lockfile(tmp_path)
    (tmp_path / "yarn.lock").write_text('a@^1:\n  version "1.0.0"\n', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(lock_v3({"node_modules/b": {"version": "2.0.0"}}), encoding="utf-8")
    file, locked = au.read_lockfile(tmp_path)
    assert file.name == "package-lock.json" and locked[0].name == "b"


def test_a_pasted_lockfile_is_recognised_by_its_content():
    assert au.parse_text(lock_v3({"node_modules/a": {"version": "1.0.0"}}))[0].name == "a"
    assert au.parse_text("lockfileVersion: '9.0'\n\npackages:\n\n  a@1.0.0:\n    resolution: {}\n")[0].name == "a"
    assert au.parse_text('a@^1:\n  version "1.0.0"\n')[0].name == "a"


def test_pnpm_sources_are_read_from_the_resolution():
    text = ("lockfileVersion: '9.0'\n\npackages:\n\n"
            "  good@1.0.0:\n    resolution: {integrity: sha512-x}\n\n"
            "  bad@1.0.0:\n    resolution: {integrity: sha512-y, tarball: https://evil.example/bad.tgz}\n\n"
            "  gitdep@https://codeload.github.com/x/y/tar.gz/abc:\n    resolution: {tarball: https://codeload.github.com/x/y/tar.gz/abc}\n\n"
            "  unsigned@1.0.0:\n    resolution: {tarball: https://registry.npmjs.org/unsigned/-/unsigned-1.0.0.tgz}\n")
    locked = {p.name: p for p in au.parse_pnpm(text)}
    assert set(locked) == {"good", "bad", "gitdep", "unsigned"}
    found = {(f.kind, f.name) for f in au.check_index(list(locked.values()), {})}
    assert found == {(au.UNTRUSTED_SOURCE, "bad"), (au.UNTRUSTED_SOURCE, "gitdep"), (au.NO_INTEGRITY, "gitdep"), (au.NO_INTEGRITY, "unsigned")}


def test_yarn_berry_lockfile():
    text = ('__metadata:\n  version: 8\n\n'
            '"good@npm:^1.0.0":\n  version: 1.2.3\n  resolution: "good@npm:1.2.3"\n  checksum: 10c0/abc\n\n'
            '"bad@https://evil.example/bad.tgz":\n  version: 1.0.0\n  resolution: "bad@https://evil.example/bad.tgz"\n  checksum: 10c0/def\n')
    locked = {p.name: p for p in au.parse_yarn(text)}
    assert locked["good"].version == "1.2.3" and locked["good"].resolved == ""
    assert au.check_index([locked["bad"]], {})[0].kind == au.UNTRUSTED_SOURCE
