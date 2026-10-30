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
    assert au.check_index([au.Locked("a", "1.0.0", "git+ssh://git@evil.example/x/y.git#abc", True)], {})[0].kind == au.UNTRUSTED_SOURCE


def test_a_code_host_is_a_note_not_a_failure():
    locked = [au.Locked("a", "1.0.0", "https://codeload.github.com/x/y/tar.gz/abc", True), au.Locked("b", "1.0.0", "git+ssh://git@github.com/x/y.git#abc", True)]
    report = au.audit(locked, {}, online=False)
    assert {f["kind"] for f in report["findings"]} == {au.CODE_HOST_SOURCE} and not report["severe"]


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
    assert found == {(au.UNTRUSTED_SOURCE, "bad"), (au.CODE_HOST_SOURCE, "gitdep"), (au.NO_INTEGRITY, "gitdep"), (au.NO_INTEGRITY, "unsigned")}


def test_yarn_berry_lockfile():
    text = ('__metadata:\n  version: 8\n\n'
            '"good@npm:^1.0.0":\n  version: 1.2.3\n  resolution: "good@npm:1.2.3"\n  checksum: 10c0/abc\n\n'
            '"bad@https://evil.example/bad.tgz":\n  version: 1.0.0\n  resolution: "bad@https://evil.example/bad.tgz"\n  checksum: 10c0/def\n')
    locked = {p.name: p for p in au.parse_yarn(text)}
    assert locked["good"].version == "1.2.3" and locked["good"].resolved == ""
    assert au.check_index([locked["bad"]], {})[0].kind == au.UNTRUSTED_SOURCE


def test_a_yarn_alias_counts_as_the_package_it_installs():
    # real entries from facebook/react and babel/babel: flagging the alias name would be a false alarm
    text = '''"eslint-v7@npm:eslint@^7.7.0", eslint@^7.7.0:
  version "7.32.0"
  resolved "https://registry.yarnpkg.com/eslint/-/eslint-7.32.0.tgz#c6d3"
  integrity sha512-x

"eslint-plugin-react-internal@link:./scripts/eslint-rules":
  version "0.0.0"
  uid ""

"npm-babel-parser@npm:@babel/parser@^7.14.0":
  version: 7.29.3
  resolution: "@babel/parser@npm:7.29.3"
  checksum: 10c0/abc

"@babel/core@npm:^7.0.0":
  version: 7.1.0
  resolution: "@babel/core@npm:7.1.0"

"typescript@patch:typescript@npm%3A5.0.0#~builtin":
  version: 5.0.0
  resolution: "typescript@patch:typescript@npm%3A5.0.0#~builtin"
'''
    assert [(p.name, p.version) for p in au.parse_yarn(text)] == [("eslint", "7.32.0"), ("@babel/parser", "7.29.3"), ("@babel/core", "7.1.0")]


def test_a_pnpm_file_with_two_documents_is_read_whole():
    text = ("---\nlockfileVersion: '9.0'\n\npackages:\n\n  pnpm@9.0.0:\n    resolution: {integrity: sha512-a}\n\nsnapshots:\n\n  pnpm@9.0.0: {}\n"
            "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n\npackages:\n\n  a@1.0.0:\n    resolution: {integrity: sha512-b}\n\n"
            "  b@2.0.0:\n    resolution: {integrity: sha512-c}\n\nsnapshots:\n\n  c@3.0.0: {}\n")
    assert [(p.name, p.version) for p in au.parse_pnpm(text)] == [("pnpm", "9.0.0"), ("a", "1.0.0"), ("b", "2.0.0")]


def test_a_yarn_berry_archive_url_binding_is_seen_through():
    text = ('"good@npm:^1.0.0":\n  version: 1.0.0\n'
            '  resolution: "good@npm:1.0.0::__archiveUrl=https%3A%2F%2Fevil.example%2Fgood-1.0.0.tgz"\n  checksum: 10c0/a\n')
    assert au.check_index(au.parse_yarn(text), {})[0].kind == au.UNTRUSTED_SOURCE


def test_a_pnpm_source_is_found_whatever_its_field_or_order():
    text = ("lockfileVersion: '9.0'\n\npackages:\n\n"
            '  "quoted@1.0.0":\n    resolution: {integrity: sha512-x, "tarball": "https://evil.example/q.tgz"}\n\n'
            "  odd@1.0.0:\n    engines: {node: '>=8'}\n    resolution:\n      integrity: sha512-y\n      tarball: https://evil.example/o.tgz\n")
    kinds = {(f.name, f.kind) for f in au.check_index(au.parse_pnpm(text), {})}
    assert kinds == {("quoted", au.UNTRUSTED_SOURCE), ("odd", au.UNTRUSTED_SOURCE)}


def test_a_host_is_compared_exactly_not_as_a_substring():
    assert au.host_of("git+ssh://git@github.com/x/y.git") == "github.com"
    assert au.host_of("git@github.com:x/y.git") == "github.com"
    assert au.host_of("https://user:pw@evil.example:8443/a.tgz") == "evil.example"
    found = au.check_index([au.Locked("a", "1.0.0", "git+https://evil.example/github.com/x.git", True)], {})
    assert found[0].kind == au.UNTRUSTED_SOURCE


def test_a_remote_entry_cannot_hide_behind_a_local_key():
    text = '"a@workspace:.", "a@npm:^1.0.0":\n  version: 1.0.0\n  resolution: "a@npm:1.0.0"\n'
    assert [p.name for p in au.parse_yarn(text)] == ["a"]
    text = '"a@link:./x":\n  version "1.0.0"\n  resolved "https://evil.example/a.tgz"\n'
    assert au.check_index(au.parse_yarn(text), {})[0].kind == au.UNTRUSTED_SOURCE


def test_yarn_entries_need_no_blank_line_between_them():
    text = 'a@^1:\n  version "1.0.0"\nb@^2:\n  version "2.0.0"\n  resolved "https://evil.example/b.tgz"\n'
    assert [p.name for p in au.parse_yarn(text)] == ["a", "b"]


def test_a_nested_version_field_cannot_stand_in_for_the_entry():
    text = 'a@^1:\n  dependencies:\n    version "9.9.9"\n  version "1.0.0"\n'
    assert au.parse_yarn(text)[0].version == "1.0.0"


def test_a_crafted_key_loses_to_what_berry_says_it_resolved():
    text = '"innocent@npm:^1.0.0":\n  version: 1.0.0\n  resolution: "evil-pkg@npm:1.0.0"\n'
    assert au.parse_yarn(text)[0].name == "evil-pkg"


def test_an_alias_without_a_version_is_still_an_alias():
    assert au.parse_yarn('"x@npm:evil-pkg":\n  version "1.0.0"\n')[0].name == "evil-pkg"


def test_an_unreadable_pnpm_entry_is_reported_not_dropped():
    text = "lockfileVersion: '9.0'\n\npackages:\n\n  no-version-here:\n    resolution: {integrity: sha512-x}\n"
    assert au.check_index(au.parse_pnpm(text), {})[0].kind == au.UNTRUSTED_SOURCE


def test_package_names_and_deprecation_notes_are_not_sources():
    assert au._source_of("simple-git@^3.10.0") == ""
    assert au._source_of("@npmcli/git@5.0.8") == ""
    assert au._source_of("git@evil.example:x/y.git") == "git@evil.example:x/y.git"
