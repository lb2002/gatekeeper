"""Helpers of the hourly sweep: who is behind a report, and which endpoints it names."""

import httpx

from gatekeeper.evidence.bundle import build_bundle, excerpt_refs
from gatekeeper.npm.tarball import PackageFiles
from gatekeeper.triage import campaign
from gatekeeper.triage.content import score_content


def test_account_names_ignore_npms_own_security_account():
    doc = {"maintainers": [{"name": "npm"}, {"name": "mallory"}],
           "versions": {"1.0.0": {"_npmUser": {"name": "eve"}}, "0.0.1-security": {"_npmUser": {"name": "npm"}}, "x": "junk"}}
    assert campaign.account_names(doc) == {"mallory", "eve"}
    assert campaign.account_names({}) == set()


def test_report_iocs_read_text_and_the_openssf_block():
    vuln = {"details": "posts to https://203.0.114.9:8443/x and https://webhook.site/d730a68c-27bd-4bb5-b1b9-d57a0a4b17ac/a",
            "database_specific": {"iocs": {"ips": ["198.51.99.7", "8.8.8.8", 5], "urls": ["https://abc-def.trycloudflare.com/"]}}}
    found = campaign.report_iocs(vuln)
    assert "203.0.114.9" in found and "198.51.99.7" in found
    assert "webhook.site/d730a68c-27bd-4bb5-b1b9-d57a0a4b17ac" in found
    assert "abc-def.trycloudflare.com" in found
    assert "8.8.8.8" not in found


def test_report_without_iocs_block():
    assert campaign.report_iocs({"details": "nothing here"}) == set()
    assert campaign.report_iocs({"database_specific": {"iocs": "text"}}) == set()


def _client(n: int) -> httpx.Client:
    def handler(request):
        assert request.url.params["text"] == "maintainer:mallory"
        return httpx.Response(200, json={"objects": [{"package": {"name": f"p{i}"}} for i in range(n)]})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_packages_of_throwaway_account():
    assert campaign.packages_of(_client(3), "mallory") == ["p0", "p1", "p2"]


def test_account_with_a_large_portfolio_is_left_alone():
    assert campaign.packages_of(_client(campaign.SWEEP_MAX_PACKAGES + 1), "mallory") is None


def test_excerpt_refs_match_the_bundle_that_was_rendered():
    files = {"package.json": b'{"name":"a","version":"1.0.0","main":"my lib.js"}', "my lib.js": b"const x = 1\n" * 5}
    pkg = PackageFiles(files=files, sizes={p: len(b) for p, b in files.items()})
    bundle = build_bundle("a", "1.0.0", pkg, score_content(pkg))
    refs = excerpt_refs(bundle.render())
    assert [(r["excerpt_id"], r["path"], r["first_line"], r["last_line"]) for r in refs] == \
        [(e.excerpt_id, e.path, e.first_line, e.last_line) for e in bundle.excerpts]
    assert refs[0]["kind"] == "manifest" and all(r["kind"] == "code" for r in refs[1:])
