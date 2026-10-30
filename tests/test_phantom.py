"""Public packages that load something the public registry does not have."""

from datetime import datetime, timezone

import httpx
import pytest

from gatekeeper.npm.tarball import PackageFiles
from gatekeeper.triage import phantom


def pkg_of(files: dict[str, bytes]) -> PackageFiles:
    return PackageFiles(files=files, sizes={p: len(b) for p, b in files.items()})


def client_with(missing: set[str]) -> httpx.Client:
    def handler(request):
        name = httpx.URL(str(request.url)).path.lstrip("/").replace("%2F", "/").replace("%2f", "/")
        return httpx.Response(404) if name in missing else httpx.Response(200, json={"versions": {"1.0.0": {}}})

    return httpx.Client(transport=httpx.MockTransport(handler))


def setup_function():
    phantom._KNOWN.clear()


def test_finds_every_way_of_loading_a_scoped_package():
    pkg = pkg_of({"a.js": b"const x = require('@a/one');\nimport y from \"@a/two\";\nawait import('@a/three/sub')\nimport '@a/four'\n"})
    assert set(phantom.scoped_imports(pkg)) == {"@a/one", "@a/two", "@a/three", "@a/four"}
    assert phantom.scoped_imports(pkg)["@a/two"][:2] == ("a.js", 2)


def test_the_campaign_shape_is_found():
    pkg = pkg_of({"src/motion.js": b"const utils = require('@aaron205whitmore/postcss-animate-utils')\n"})
    found = phantom.unreadable_imports(client_with({"@aaron205whitmore/postcss-animate-utils"}), pkg, "tailwind-fabric", set())
    assert [n for n, _ in found] == ["@aaron205whitmore/postcss-animate-utils"]
    assert found[0][1][:2] == ("src/motion.js", 1)


def test_public_scoped_packages_pass():
    pkg = pkg_of({"a.js": b"require('@aws-sdk/client-s3')"})
    assert phantom.unreadable_imports(client_with(set()), pkg, "x", set()) == []


def test_a_private_package_in_the_authors_own_scope_counts_too():
    # exempting it would hand every attacker the bypass: publish @evil/plugin, load @evil/payload
    pkg = pkg_of({"a.js": b"require('@evil/payload')"})
    assert [n for n, _ in phantom.unreadable_imports(client_with({"@evil/payload"}), pkg, "@evil/plugin", set())] == ["@evil/payload"]


def test_a_declared_dependency_counts_without_any_code_loading_it():
    pkg = pkg_of({"package.json": b'{"dependencies": {"@evil/payload": "^1.0.0", "left-pad": "1.0.0"}}'})
    assert [n for n, _ in phantom.unreadable_imports(client_with({"@evil/payload"}), pkg, "x", set())] == ["@evil/payload"]


def test_type_declarations_do_not_count():
    assert phantom.scoped_imports(pkg_of({"a.d.ts": b"import x from '@a/types'"})) == {}


def test_a_test_folder_is_read_last_but_still_read():
    # a directory name is the attacker's choice, so it can only lower the priority
    pkg = pkg_of({"lib/test/a.js": b"require('@a/hidden')", "b.js": b"require('@b/first')"})
    assert list(phantom.scoped_imports(pkg)) == ["@b/first", "@a/hidden"]


def test_a_package_npm_took_down_counts_as_unreadable():
    def handler(request):
        return httpx.Response(200, json={"versions": {"0.0.0-stage": {}, "0.0.1-security": {}}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert phantom.unreadable_imports(client, pkg_of({"a.js": b"require('@evil/gone')"}), "x", set())


def test_dependencies_only_the_registry_declares_count():
    # manifest confusion: npm installs what the registry says, not what the archive's package.json says
    found = phantom.unreadable_imports(client_with({"@evil/hidden"}), pkg_of({"package.json": b"{}"}), "x", set(), [("@evil/hidden", "1.0.0")])
    assert [n for n, _ in found] == ["@evil/hidden"]


def test_an_npm_alias_is_followed_to_its_target():
    pkg = pkg_of({"package.json": b'{"dependencies": {"innocent": "npm:@evil/payload@1.0.0"}}'})
    assert [n for n, _ in phantom.unreadable_imports(client_with({"@evil/payload"}), pkg, "x", set())] == ["@evil/payload"]


def test_a_name_with_test_in_it_is_still_read():
    assert "@a/hidden" in phantom.scoped_imports(pkg_of({"lib/testing-utils.js": b"require('@a/hidden')"}))


def test_the_entry_file_is_read_even_inside_a_test_folder():
    pkg = pkg_of({"package.json": b'{"main": "test/index.js"}', "test/index.js": b"require('@a/hidden')"})
    assert "@a/hidden" in phantom.scoped_imports(pkg)


def test_padding_does_not_hide_an_import_late_in_a_file():
    pkg = pkg_of({"big.js": b"x" * 900_000 + b"\nrequire('@a/late')\n"})
    assert "@a/late" in phantom.scoped_imports(pkg)


def test_filler_imports_cannot_push_the_entry_file_past_the_lookup_limit():
    filler = b"\n".join(b"require('@pad/p%d')" % i for i in range(50))
    pkg = pkg_of({"package.json": b'{"main": "index.js"}', "aaa.js": filler, "index.js": b"require('@evil/payload')"})
    assert [n for n, _ in phantom.unreadable_imports(client_with({"@evil/payload"}), pkg, "x", set())] == ["@evil/payload"]


def test_line_numbers_stay_right_across_many_imports():
    pkg = pkg_of({"a.js": b"require('@a/one')\n\n\nrequire('@a/two')\nrequire('@a/one')\nrequire('@a/three')\n"})
    found = phantom.scoped_imports(pkg)
    assert (found["@a/one"][1], found["@a/two"][1], found["@a/three"][1]) == (1, 4, 6)


def test_a_registry_outage_is_no_evidence():
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(429)))
    assert phantom.unreadable_imports(client, pkg_of({"a.js": b"require('@a/b')"}), "x", set()) == []
    assert phantom._KNOWN == {}


def test_lookups_are_cached_and_bounded():
    calls = []

    def handler(request):
        calls.append(request.url)
        return httpx.Response(200, json={"versions": {"1.0.0": {}}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    pkg = pkg_of({"a.js": b"\n".join(b"require('@a/p%d')" % i for i in range(50))})
    phantom.unreadable_imports(client, pkg, "x", set())
    assert len(calls) == phantom.MAX_LOOKUPS
    phantom.unreadable_imports(client, pkg, "x", set())  # known names are free, so the rest get their turn
    assert len(calls) == 50


def _update(added, previous=("left-pad",)):
    from gatekeeper.npm.packument import VersionInfo

    return VersionInfo(name="trusted", version="1.0.1", published_at=None, package_created_at=None, previous_version="1.0.0",
                       dependencies=[(n, "^1.0.0") for n in (*previous, *added)],
                       previous_dependencies=[(n, "^1.0.0") for n in previous])


NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


def _registry(created: dict[str, str]):
    return httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"time": {"created": created[r.url.path.lstrip("/")]}})))


def test_an_update_adding_a_days_old_package_is_found():
    phantom._CREATED.clear()
    client = _registry({"plain-crypto-js": "2026-10-29T12:00:00.000Z"})
    assert phantom.young_additions(client, _update(["plain-crypto-js"]), NOW, set()) == [("plain-crypto-js", 24.0)]


def test_an_update_adding_an_established_package_is_not():
    phantom._CREATED.clear()
    client = _registry({"chalk-next": "2024-01-01T00:00:00.000Z"})
    assert phantom.young_additions(client, _update(["chalk-next"]), NOW, set()) == []


def test_a_first_release_has_no_additions():
    from gatekeeper.npm.packument import VersionInfo

    info = VersionInfo(name="new", version="1.0.0", published_at=None, package_created_at=None, dependencies=[("a", "1")])
    assert info.added_dependencies == []


def test_a_dependency_it_already_had_is_not_an_addition():
    assert _update([]).added_dependencies == []


def test_an_alias_is_compared_by_what_it_installs():
    from gatekeeper.npm.packument import VersionInfo, install_target

    assert install_target("lodash", "npm:evil-pkg@1.0.0") == "evil-pkg"
    assert install_target("x", "npm:@evil/pkg") == "@evil/pkg"
    assert install_target("lodash", "^4.0.0") == "lodash"
    info = VersionInfo(name="t", version="2", published_at=None, package_created_at=None, previous_version="1",
                       dependencies=[("lodash", "npm:evil-pkg@1.0.0")], previous_dependencies=[("lodash", "^4.0.0")])
    assert info.added_dependencies == ["evil-pkg"]


def test_many_added_dependencies_do_not_hide_a_young_one():
    phantom._CREATED.clear()
    fillers = [f"old-{i}" for i in range(phantom.MAX_ADDED_LOOKUPS)]
    phantom._CREATED.update({n: datetime(2020, 1, 1, tzinfo=timezone.utc) for n in fillers})  # known names are free
    client = _registry({"fresh": "2026-10-30T00:00:00.000Z"})
    assert [n for n, _ in phantom.young_additions(client, _update([*fillers, "fresh"]), NOW, set())] == ["fresh"]


def test_an_added_dependency_the_registry_lacks_is_reported():
    phantom._CREATED.clear()
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    assert phantom.young_additions(client, _update(["ghost"]), NOW, set()) == [("ghost", None)]


def test_a_garbled_registry_answer_is_no_evidence_and_no_crash():
    phantom._CREATED.clear()
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=["not", "a", "packument"])))
    assert phantom.young_additions(client, _update(["odd"]), NOW, set()) == []
    assert phantom._CREATED == {}


def test_declared_dependencies_are_checked_before_any_import():
    pkg = pkg_of({"package.json": b'{"main": "index.js"}', "index.js": b"require('@a/imported')"})
    assert list(phantom.scoped_imports(pkg, [("@a/declared", "1.0.0")])) == ["@a/declared", "@a/imported"]


def test_known_names_count_even_when_the_network_is_gone():
    phantom._KNOWN["@evil/payload"] = False

    def boom(request):
        raise httpx.ConnectError("offline")

    client = httpx.Client(transport=httpx.MockTransport(boom))
    pkg = pkg_of({"a.js": b"require('@a/one');require('@a/two');require('@a/three');require('@a/four');require('@evil/payload')"})
    assert [n for n, _ in phantom.unreadable_imports(client, pkg, "x", set())] == ["@evil/payload"]


def test_lookups_stop_after_a_few_failures():
    calls = []

    def boom(request):
        calls.append(request.url)
        raise httpx.ConnectError("offline")

    pkg = pkg_of({"a.js": b"\n".join(b"require('@a/p%d')" % i for i in range(20))})
    phantom.unreadable_imports(httpx.Client(transport=httpx.MockTransport(boom)), pkg, "x", set())
    assert len(calls) == phantom.MAX_LOOKUP_FAILURES


def test_url_dependencies_are_listed_except_the_common_cdn():
    deps = [("a", "^1.0.0"), ("b", "https://evil.example/b.tgz"), ("xlsx", "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz"), ("c", "github:x/y")]
    assert phantom.url_dependencies(deps) == [("b", "https://evil.example/b.tgz")]


@pytest.mark.parametrize("url", ["http://127.0.0.1/a.tgz", "http://10.0.77.5:8000/a.tgz", "http://169.254.169.254/latest/meta-data",
                                 "http://[::1]/a.tgz", "file:///etc/passwd", "ftp://example.com/a.tgz", "https:///nohost"])
def test_internal_addresses_are_never_fetched(url):
    assert not phantom.public_url(url)


def _public_dns(monkeypatch, *allowed):
    real = phantom.socket.getaddrinfo

    def fake(host, *a, **kw):
        if host in allowed:
            return [(2, 1, 6, "", ("93.184.216.34", 443))]
        return real(host, *a, **kw)

    monkeypatch.setattr(phantom.socket, "getaddrinfo", fake)


def test_a_redirect_to_an_internal_address_stops_the_fetch(monkeypatch):
    _public_dns(monkeypatch, "evil.example")
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(302, headers={"location": "http://169.254.169.254/x"})))
    fetched = []
    assert phantom.fetch_url_dependency(client, "https://evil.example/a.tgz", fetched.append) is None
    assert fetched == []


def test_url_dependency_archives_join_the_package(monkeypatch):
    _public_dns(monkeypatch, "evil.example")
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    archive = pkg_of({"package.json": b'{"scripts":{"preinstall":"node t.js"}}', "t.js": b"steal()"})
    pkg = pkg_of({"index.js": b"console.log(1)"})
    assert phantom.with_url_dependencies(pkg, client, [("ltidisafe", "https://evil.example/a.tgz")], lambda url: archive) == ["ltidisafe"]
    assert pkg.files["from-url/ltidisafe/t.js"] == b"steal()" and pkg.sizes["from-url/ltidisafe/t.js"] == 7


def test_a_failing_download_costs_only_that_dependency(monkeypatch):
    _public_dns(monkeypatch, "evil.example")
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200)))

    def boom(url):
        raise OSError("gone")

    assert phantom.with_url_dependencies(pkg_of({}), client, [("a", "https://evil.example/a.tgz")], boom) == []
