from datetime import datetime, timezone

from gatekeeper.confirm import recall

START = datetime(2026, 10, 27, tzinfo=timezone.utc)


def _vuln(vid, name, versions=(), published="2026-10-28T10:00:00Z", imported="2026-10-28T12:00:00Z"):
    return {"id": vid, "published": published,
            "affected": [{"package": {"ecosystem": "npm", "name": name}, "versions": list(versions)}],
            "database_specific": {"malicious-packages-origins": [{"import_time": imported}]}}


def test_a_change_is_judged_only_on_what_came_out_after_it():
    def outcome(published):
        return recall.Outcome("MAL-1", "a", "missed", [], "2026-10-31T00:00:00Z", published_at=published)

    old, new, undated = outcome("2026-10-29T10:00:00Z"), outcome("2026-10-30T12:00:00Z"), outcome(None)
    assert recall.published_since([old, new, undated], datetime(2026, 10, 30, 11, tzinfo=timezone.utc)) == [new]


def test_recent_ids_stop_at_the_first_older_line():
    csv = "2026-10-29T10:00:00Z,MAL-3\n2026-10-28T10:00:00Z,GHSA-x\n2026-10-27T10:00:00Z,MAL-2\n2026-10-20T00:00:00Z,MAL-1\n2026-10-28T00:00:00Z,MAL-0\n"
    assert recall.recent_mal_ids(csv, START) == ["MAL-3", "MAL-2"]


def test_flagged_missed_not_seen_before_monitor():
    seen = {"evil": [{"version": "1.0.0", "published_at": "2026-10-28T09:58:00Z", "scanned": True, "flagged": False}],
            "quiet": [{"version": "2.0.0", "published_at": "2026-10-28T09:00:00Z", "scanned": False, "flagged": False,
                       "meta_score": 1, "content_score": 0}]}
    flags = {"evil@1.0.0": "2026-10-28T10:00:00Z"}
    out = [o for v in (_vuln("MAL-1", "evil", ["1.0.0"]), _vuln("MAL-2", "quiet"), _vuln("MAL-3", "ghost"),
                       _vuln("MAL-4", "old", published="2025-01-01T00:00:00Z"))
           for o in recall.classify(v, seen, flags, START)]
    assert [o.status for o in out] == ["flagged", "missed", "not_seen", "before_monitor"]
    assert out[0].publish_to_flag_min == 2.0 and out[0].lead_over_osv_min == 120.0
    assert "not downloaded" in out[1].detail
    s = recall.summarize(out)
    assert s["in_scope"] == 3 and s["flagged"] == 1 and s["recall"] == 0.333 and s["flagged_before_osv"] == 1


def test_all_versions_entry_matches_any_flagged_version():
    out = recall.classify(_vuln("MAL-1", "evil"), {}, {"evil@9.9.9": "2026-10-28T11:00:00Z", "evil-not@1.0.0": "x"}, START)
    assert out[0].status == "flagged" and out[0].flagged_at == "2026-10-28T11:00:00Z"


def test_bad_dependencies():
    from gatekeeper.confirm.malindex import bad_dependencies

    index = {"@evil/libsignal-node": {"public": "2026-08-01T00:00:00Z", "all": True, "versions": []},
             "chalk": {"public": "2025-09-08T00:00:00Z", "all": False, "versions": ["5.6.1"]},
             "late-evil": {"public": "2026-12-01T00:00:00Z", "all": True, "versions": []}}
    deps = {"libsignal": "npm:@evil/libsignal-node@^0.0.1", "chalk": "^5.0.0", "late-evil": "1.0.0",
            "gone": "^0.0.1-security", "lodash": "^4.17.21"}
    found = bad_dependencies(deps, index, before="2026-10-01T00:00:00Z")
    assert [k for k, _ in found] == ["known_malicious", "taken_down"]
    assert "libsignal (alias of @evil/libsignal-node)" in found[0][1] and "placeholder" in found[1][1]
    assert bad_dependencies({"chalk": "5.6.1"}, index, popular={"chalk"})  # pinned to the hijacked version
    assert not bad_dependencies({"@evil/libsignal-node": "1.0.0"}, index, popular={"@evil/libsignal-node"})


def test_index_keeps_every_version_and_reads_optional_deps():
    import io
    import json as js
    import zipfile

    from gatekeeper.confirm.malindex import bad_dependencies, build_index
    from gatekeeper.npm.packument import version_info

    versions = [f"1.0.{i}" for i in range(80)]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("MAL-1.json", js.dumps({"id": "MAL-1", "published": "2026-01-01T00:00:00Z",
                                            "affected": [{"package": {"ecosystem": "npm", "name": "lib"}, "versions": versions}]}))
    path = __import__("pathlib").Path(__import__("tempfile").mkdtemp()) / "all.zip"
    path.write_bytes(buf.getvalue())
    index = build_index(path)
    assert bad_dependencies({"lib": "1.0.79"}, index)  # past the old 50-version cap
    doc = {"name": "w", "versions": {"1.0.0": {"optionalDependencies": {"lib": "1.0.79"}, "peerDependencies": {"p": "^1"}}},
           "time": {"1.0.0": "2026-10-29T00:00:00Z"}}
    info = version_info(doc, "1.0.0")
    assert info.dependencies == [("lib", "1.0.79"), ("p", "^1")] and bad_dependencies(info.dependencies, index)
    assert bad_dependencies({"x": "https://evil.example/x.tgz"}, {})[0][0] == "remote_url"


def test_dependency_names_cannot_lower_the_weight():
    from gatekeeper.npm.packument import VersionInfo
    from gatekeeper.triage.meta import score_metadata

    index = {"evil": {"public": "2026-01-01T00:00:00Z", "all": True, "versions": []}}
    deps = [(f"from a URL {i}", f"https://x.example/{i}.tgz") for i in range(5)]
    deps += [("from a URL", "npm:evil@1.0.0"), ("evil", "1.0.0"), ("evil", "^1")]  # also: same name, two sections
    meta = score_metadata(VersionInfo("w", "1.0.0", None, None, has_repository=True, dependencies=deps), set(), mal_index=index)
    assert meta.score == 11 and any(r.startswith("+9 depends on from a URL (alias of evil)") for r in meta.reasons)


def test_a_queued_flag_the_models_called_benign_is_a_miss():
    from datetime import datetime, timezone

    from gatekeeper.confirm.recall import classify

    vuln = {"id": "MAL-1", "published": "2026-10-29T15:00:00Z",
            "affected": [{"package": {"ecosystem": "npm", "name": "spam"}, "versions": ["1.0.0"]}],
            "database_specific": {"malicious-packages-origins": [{"import_time": "2026-10-29T15:30:00Z"}]}}
    seen = {"spam": [{"version": "1.0.0", "published_at": "2026-10-29T15:00:00Z", "seen_at": "2026-10-29T15:01:00Z",
                      "scanned": True, "flagged": True, "meta_score": 2, "content_score": 0, "error": None}]}
    start = datetime(2026, 10, 27, tzinfo=timezone.utc)
    [o] = classify(vuln, seen, {}, start, queued={"spam@1.0.0": "2026-10-29T15:01:00Z"})
    assert o.status == "missed" and "benign" in o.detail
    [o] = classify(vuln, seen, {"spam@1.0.0": "2026-10-29T15:01:00Z"}, start)
    assert o.status == "flagged"


def test_seeing_only_npms_takedown_placeholders_means_before_monitor():
    from datetime import datetime, timezone

    from gatekeeper.confirm.recall import classify

    vuln = {"id": "MAL-2", "published": "2026-10-28T14:40:00Z",
            "affected": [{"package": {"ecosystem": "npm", "name": "camelot-x"}, "versions": ["99.0.0", "0.0.0-stage"]}]}
    seen = {"camelot-x": [{"version": "0.0.0-stage", "published_at": "2026-10-28T14:32:18Z", "seen_at": "2026-10-28T14:34:00Z",
                           "scanned": True, "flagged": False, "meta_score": 2, "content_score": 0, "error": None}]}
    times = {"camelot-x": {"created": "2026-10-28T14:32:18Z", "99.0.0": "2026-05-07T05:20:59Z",
                           "0.0.0-stage": "2026-10-28T14:32:18Z", "0.0.1-security": "2026-10-28T14:32:55Z"}}
    start = datetime(2026, 10, 27, tzinfo=timezone.utc)
    [o] = classify(vuln, seen, {"camelot-x@0.0.0-stage": "2026-10-28T14:34:00Z"}, start, npm_times=times)
    assert o.status == "before_monitor" and o.published_at.startswith("2026-05-07")
    times["camelot-x"]["99.0.0"] = "2026-10-28T10:00:00Z"
    [o] = classify(vuln, seen, {}, start, npm_times=times)
    assert o.status == "not_seen"


def test_npm_placeholders_are_never_scanned():
    from gatekeeper.npm.packument import VersionInfo

    for version, publisher, expected in (("0.0.0-stage", "npm", True), ("0.0.1-security", "npm", True),
                                         ("0.0.1-security", "attacker", False), ("0.0.0-stage", "attacker", False),
                                         ("1.0.0-security", None, False), ("1.0.0", "someone", False)):
        info = VersionInfo(name="x", version=version, published_at=None, package_created_at=None, publisher=publisher)
        assert info.is_npm_placeholder is expected


def test_a_sweep_that_read_a_package_after_its_report_detected_nothing():
    from datetime import datetime, timezone

    from gatekeeper.confirm.recall import classify

    vuln = {"id": "MAL-1", "published": "2026-10-29T13:00:00Z", "affected": [{"package": {"ecosystem": "npm", "name": "p"}, "versions": ["1.0.0"]}]}
    seen = {"p": [{"version": "1.0.0", "published_at": "2026-10-28T10:00:00+00:00", "scanned": True, "meta_score": 0, "content_score": 0}]}
    start = datetime(2026, 10, 27, tzinfo=timezone.utc)
    late = {"p@1.0.0": "2026-10-30T11:00:00+00:00"}
    assert classify(vuln, seen, late, start, read_later={"p@1.0.0"})[0].status == "missed"
    early = {"p@1.0.0": "2026-10-28T11:00:00+00:00"}
    assert classify(vuln, seen, early, start, read_later={"p@1.0.0"})[0].status == "flagged"
    assert classify(vuln, seen, late, start)[0].status == "flagged"  # flagged late by the live monitor still counts
