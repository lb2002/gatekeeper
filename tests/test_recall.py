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
