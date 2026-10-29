from datetime import datetime, timezone

from gatekeeper.confirm import recall

START = datetime(2026, 10, 27, tzinfo=timezone.utc)


def _vuln(vid, name, versions=(), published="2026-10-28T10:00:00Z", imported="2026-10-28T12:00:00Z"):
    return {"id": vid, "published": published,
            "affected": [{"package": {"ecosystem": "npm", "name": name}, "versions": list(versions)}],
            "database_specific": {"malicious-packages-origins": [{"import_time": imported}]}}


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
    assert "scanned=False" in out[1].detail
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
    reasons = bad_dependencies(deps, index, before="2026-10-01T00:00:00Z")
    assert len(reasons) == 2
    assert "libsignal (alias of @evil/libsignal-node)" in reasons[0] and "placeholder" in reasons[1]
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
    assert info.dependencies == {"p": "^1", "lib": "1.0.79"} and bad_dependencies(info.dependencies, index)
    assert "from a URL" in bad_dependencies({"x": "https://evil.example/x.tgz"}, {})[0]
