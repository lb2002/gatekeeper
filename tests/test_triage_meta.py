from datetime import datetime, timedelta, timezone

from gatekeeper.npm.packument import version_info
from gatekeeper.triage.meta import score_metadata
from gatekeeper.triage.typosquat import damerau_levenshtein, typosquat_target

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
POPULAR = {"axios-retry", "lodash", "express", "react-dom"}


def packument(name, versions, created):
    times = {"created": created}
    vers = {}
    for ver, (ts, manifest) in versions.items():
        times[ver] = ts
        vers[ver] = {"name": name, "version": ver, **manifest}
    return {"name": name, "time": times, "versions": vers}


def test_new_typosquat_with_postinstall_scores_high():
    p = packument(
        "axois-retry",
        {"1.0.0": ("2026-10-27T11:00:00Z", {"scripts": {"postinstall": "node setup.js"}})},
        created="2026-10-27T11:00:00Z",
    )
    s = score_metadata(version_info(p, "1.0.0"), POPULAR, now=NOW)
    assert s.score >= 3 + 1 + 3 + 1
    assert any("axios-retry" in r for r in s.reasons)


def test_popular_package_gaining_install_hook_and_new_publisher():
    p = packument(
        "lodash",
        {
            "4.17.21": ("2021-02-20T00:00:00Z", {"_npmUser": {"name": "jdalton"}, "repository": "x"}),
            "4.17.22": (
                "2026-10-27T11:30:00Z",
                {"_npmUser": {"name": "mallory"}, "repository": "x", "scripts": {"preinstall": "node a.js"}},
            ),
        },
        created="2012-04-23T00:00:00Z",
    )
    s = score_metadata(version_info(p, "4.17.22"), POPULAR, now=NOW)
    assert s.score >= 3 + 6 + 3


def test_plain_old_package_scores_zero():
    p = packument("my-utils-lib", {"2.0.0": ("2026-10-27T11:00:00Z", {"repository": "x"})}, created="2020-01-01T00:00:00Z")
    assert score_metadata(version_info(p, "2.0.0"), POPULAR, now=NOW).score == 0


def test_damerau_transposition():
    assert damerau_levenshtein("axois", "axios", 2) == 1


def test_typosquat_ignores_exact_and_short():
    assert typosquat_target("lodash", POPULAR) is None
    assert typosquat_target("expres", POPULAR) == "express"
    assert typosquat_target("react_dom", POPULAR) == "react-dom"


def test_scoped_names_only_flag_imitated_scopes():
    popular = {"@material/theme", "@typescript-eslint/parser"}
    assert typosquat_target("@orz/themes", popular) is None
    assert typosquat_target("@typescript-eslint/whatever", popular) is None
    assert typosquat_target("@typescript_eslint/parser", popular) == "@typescript-eslint/*"
