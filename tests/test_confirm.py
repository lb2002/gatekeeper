import json
from datetime import datetime, timezone

import httpx

from gatekeeper.confirm import Confirmation, check, earliest, flag_lead_minutes, publish_to_flag_minutes
from gatekeeper.confirm.ghsa import malware_advisories
from gatekeeper.confirm.osv import malicious_hits
from gatekeeper.confirm.takedown import from_packument

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
NAME = "colors-utils-pro"

OSV_MAL = {
    "id": "MAL-2026-8812",
    "summary": "Malicious code in colors-utils-pro (npm)",
    "modified": "2026-10-26T09:14:02.551283Z",
    "published": "2026-10-26T08:00:00Z",
    "affected": [{"package": {"ecosystem": "npm", "name": NAME}, "versions": ["1.0.3", "1.0.4"]}],
    "database_specific": {
        "malicious-packages-origins": [
            {"source": "ghsa-malware", "import_time": "2026-10-26T07:41:13.104827Z", "modified_time": "2026-10-26T07:30:00Z"},
            {"source": "ossf-package-analysis", "import_time": "2026-10-25T23:05:47.912345678Z", "versions": ["1.0.3"]},
        ]
    },
}
OSV_CVE = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "published": "2026-01-02T00:00:00Z",
    "affected": [{"package": {"ecosystem": "npm", "name": NAME}, "versions": ["1.0.3"]}],
}
OSV_OTHER_VERSION = {
    "id": "MAL-2026-0101",
    "published": "2026-03-01T00:00:00Z",
    "affected": [{"package": {"ecosystem": "npm", "name": NAME}, "versions": ["0.9.0"]}],
}
OSV_ALL_VERSIONS = {
    "id": "MAL-2026-7777",
    "published": "2026-10-27T13:30:00Z",
    "affected": [
        {"package": {"ecosystem": "npm", "name": NAME}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}
    ],
}


def ghsa_advisory(ghsa_id, published_at, name=NAME, withdrawn_at=None):
    return {
        "ghsa_id": ghsa_id,
        "type": "malware",
        "published_at": published_at,
        "withdrawn_at": withdrawn_at,
        "vulnerabilities": [{"package": {"ecosystem": "npm", "name": name}, "vulnerable_version_range": ">= 0"}],
    }


PACKUMENT_TAKEN_DOWN = {
    "name": NAME,
    "time": {
        "created": "2026-10-25T21:00:00.000Z",
        "modified": "2026-10-26T15:02:11.000Z",
        "1.0.3": "2026-10-25T21:00:00.000Z",
        "0.0.1-security": "2026-10-26T15:02:10.784Z",
    },
    "versions": {"0.0.1-security": {"name": NAME, "version": "0.0.1-security"}},
}


def make_client(osv_pages=None, ghsa_pages=None, ghsa_status=200, packument=None, calls=None):
    """Mock OSV/GitHub/npm. `osv_pages` and `ghsa_pages` are lists of page payloads."""
    osv_pages = osv_pages or [{}]
    ghsa_pages = ghsa_pages or [[]]

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        host = request.url.host
        if host == "api.osv.dev":
            body = json.loads(request.content)
            assert body["package"] == {"name": NAME, "ecosystem": "npm"}
            return httpx.Response(200, json=osv_pages[int(body.get("page_token", 0))])
        if host == "api.github.com":
            if ghsa_status != 200:
                return httpx.Response(ghsa_status, json={"message": "API rate limit exceeded"},
                                      headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1793102400"})
            page = int(request.url.params.get("after", 0))
            headers = {}
            if page + 1 < len(ghsa_pages):
                headers["Link"] = f'<https://api.github.com/advisories?type=malware&after={page + 1}>; rel="next"'
            return httpx.Response(200, json=ghsa_pages[page], headers=headers)
        if host == "registry.npmjs.org":
            return httpx.Response(200, json=packument) if packument else httpx.Response(404, json={"error": "Not found"})
        raise AssertionError(f"unexpected request {request.url}")

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_osv_mal_entry_uses_earliest_import_time_and_ignores_non_mal():
    client = make_client(osv_pages=[{"vulns": [OSV_CVE, OSV_MAL], "next_page_token": "1"}, {"vulns": [OSV_OTHER_VERSION]}])
    hits = malicious_hits(client, NAME, "1.0.3")
    assert [h.id for h in hits] == ["MAL-2026-8812"]
    # nanosecond import_time, earlier than the submitter-set `published`
    assert hits[0].first_public == "2026-10-25T23:05:47.912345Z"


def test_osv_published_is_not_a_public_time_and_rangeonly_entry_affects_all():
    # `published` is submitter-set and often backdated to the package's own publish time
    hits = malicious_hits(make_client(osv_pages=[{"vulns": [OSV_ALL_VERSIONS]}]), NAME, "5.5.5")
    assert [(h.id, h.first_public) for h in hits] == [("MAL-2026-7777", None)]


def test_osv_entry_for_other_versions_does_not_confirm():
    conf = check(make_client(osv_pages=[{"vulns": [OSV_OTHER_VERSION, OSV_CVE]}]), NAME, "1.0.3", now=NOW)
    assert conf.osv_ids == [] and not conf.confirmed and conf.errors == []


def test_ghsa_follows_link_pagination_and_sends_headers(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    calls = []
    client = make_client(
        ghsa_pages=[
            [ghsa_advisory("GHSA-aaaa-bbbb-cccc", "2026-10-26T18:00:00Z"), ghsa_advisory("GHSA-zzzz-0000-1111", "2026-10-20T00:00:00Z", name="other-pkg")],
            [ghsa_advisory("GHSA-dddd-eeee-ffff", "2026-10-26T10:30:00Z"), ghsa_advisory("GHSA-wwww-wwww-wwww", "2026-10-01T00:00:00Z", withdrawn_at="2026-10-02T00:00:00Z")],
        ],
        calls=calls,
    )
    res = malware_advisories(client, NAME)
    assert res.ids == ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]
    assert res.published_at == "2026-10-26T10:30:00Z"
    assert res.error is None
    first = calls[0]
    assert first.url.params["type"] == "malware" and first.url.params["affects"] == NAME
    assert first.headers["Authorization"] == "Bearer test-token"
    assert first.headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert len(calls) == 2


def test_ghsa_rate_limit_is_recorded_not_raised(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    conf = check(make_client(ghsa_status=403, osv_pages=[{"vulns": [OSV_MAL]}]), NAME, "1.0.3", now=NOW)
    assert conf.ghsa_ids == []
    assert any(e.startswith("ghsa: github rate limited (403)") for e in conf.errors)
    assert conf.confirmed  # OSV still counts


def test_takedown_from_packument():
    td = from_packument(PACKUMENT_TAKEN_DOWN, "1.0.3")
    assert td.takedown_at == "2026-10-26T15:02:10.784000Z"
    assert td.version_removed
    assert from_packument(None, "1.0.3").takedown_at is None


def test_full_check_combines_sources():
    client = make_client(
        osv_pages=[{"vulns": [OSV_MAL]}],
        ghsa_pages=[[ghsa_advisory("GHSA-aaaa-bbbb-cccc", "2026-10-26T18:00:00Z")]],
        packument=PACKUMENT_TAKEN_DOWN,
    )
    conf = check(client, NAME, "1.0.3", now=NOW)
    assert conf.confirmed and conf.errors == []
    assert conf.checked_at == "2026-10-27T12:00:00Z"
    assert conf.osv_ids == ["MAL-2026-8812"] and conf.ghsa_ids == ["GHSA-aaaa-bbbb-cccc"]
    assert conf.npm_takedown_at == "2026-10-26T15:02:10.784000Z"
    assert conf.earliest_public == "2026-10-25T23:05:47.912345Z"
    d = conf.as_dict()
    assert d["confirmed"] and d["earliest_public"] == conf.earliest_public


def test_clean_package_not_confirmed():
    packument = {
        "name": NAME,
        "time": {"created": "2020-01-01T00:00:00Z", "1.0.3": "2026-10-27T10:00:00Z"},
        "versions": {"1.0.3": {"name": NAME, "version": "1.0.3"}},
    }
    conf = check(make_client(packument=packument), NAME, "1.0.3", now=NOW)
    assert not conf.confirmed and conf.earliest_public is None
    assert not conf.version_removed and conf.errors == []


def test_failing_source_never_raises():
    def handler(request):
        if request.url.host == "api.osv.dev":
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(500)

    conf = check(httpx.Client(transport=httpx.MockTransport(handler)), NAME, "1.0.3", now=NOW)
    assert not conf.confirmed
    assert [e.split(":")[0] for e in conf.errors] == ["osv", "ghsa", "npm"]


def test_earliest_public_and_minute_math():
    conf = Confirmation(NAME, "1.0.3", "2026-10-27T12:00:00Z", osv_ids=["MAL-1"],
                        osv_first_public="2026-10-26T09:00:00+02:00", ghsa_published_at="2026-10-26T08:00:00Z")
    assert conf.earliest_public == "2026-10-26T07:00:00Z"
    flagged = "2026-10-26T06:15:00Z"
    assert flag_lead_minutes(flagged, conf.earliest_public) == 45.0
    assert flag_lead_minutes("2026-10-26T07:30:00Z", conf.earliest_public) == -30.0
    assert flag_lead_minutes(flagged, None) is None
    assert publish_to_flag_minutes("2026-10-26T06:00:00.000Z", flagged) == 15.0
    assert publish_to_flag_minutes(None, flagged) is None
    assert earliest([None, "garbage"]) is None
