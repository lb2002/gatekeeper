"""Public packages that load something the public registry does not have."""

import httpx

from gatekeeper.npm.tarball import PackageFiles
from gatekeeper.triage import phantom


def pkg_of(files: dict[str, bytes]) -> PackageFiles:
    return PackageFiles(files=files, sizes={p: len(b) for p, b in files.items()})


def client_with(missing: set[str]) -> httpx.Client:
    def handler(request):
        name = httpx.URL(str(request.url)).path.lstrip("/").replace("%2F", "/").replace("%2f", "/")
        return httpx.Response(404 if name in missing else 200)

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


def test_own_scope_is_left_alone():
    # monorepos reference sibling packages that may not be published
    pkg = pkg_of({"a.js": b"require('@acme/internal')"})
    assert phantom.unreadable_imports(client_with({"@acme/internal"}), pkg, "@acme/sdk", set()) == []


def test_type_declarations_and_tests_do_not_count():
    pkg = pkg_of({"a.d.ts": b"import x from '@a/types'", "lib/test/a.js": b"require('@a/fixture')"})
    assert phantom.scoped_imports(pkg) == {}


def test_a_registry_outage_is_no_evidence():
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(429)))
    assert phantom.unreadable_imports(client, pkg_of({"a.js": b"require('@a/b')"}), "x", set()) == []
    assert phantom._KNOWN == {}


def test_lookups_are_cached_and_bounded():
    calls = []

    def handler(request):
        calls.append(request.url)
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    pkg = pkg_of({"a.js": b"\n".join(b"require('@a/p%d')" % i for i in range(20))})
    phantom.unreadable_imports(client, pkg, "x", set())
    phantom.unreadable_imports(client, pkg, "x", set())
    assert len(calls) == phantom.MAX_CHECKS
