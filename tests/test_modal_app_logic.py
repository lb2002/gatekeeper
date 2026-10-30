"""Logic in modal_app/app.py, with the Modal Dicts replaced by plain dicts (no network, no Modal account)."""

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1] / "modal_app" / "app.py"


@pytest.fixture()
def app(monkeypatch):
    spec = importlib.util.spec_from_file_location("gk_modal_app", APP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pushes = []
    monkeypatch.setattr(mod, "state", {})
    monkeypatch.setattr(mod, "queue", {})
    monkeypatch.setattr(mod, "_notify", lambda title, body, **kw: pushes.append((title, body)))
    mod.pushes = pushes
    return mod


def test_daily_report_once_per_day_after_six(app):
    app.state.update(daily={"2026-10-29": {"versions": 84214, "scanned": 15164, "flagged": 697}},
                     catches={"a@1": {"name": "a", "flagged_at": "2026-10-29T10:00:00+00:00"}},
                     spark_spend={"total": 6.4, "days": {"2026-10-29": 1.6}})
    app._daily_report(datetime(2026, 10, 30, 5, 30, tzinfo=timezone.utc))
    assert app.pushes == []  # before 06:00 UTC
    app._daily_report(datetime(2026, 10, 30, 6, 5, tzinfo=timezone.utc))
    app._daily_report(datetime(2026, 10, 30, 7, 5, tzinfo=timezone.utc))
    assert len(app.pushes) == 1
    title, body = app.pushes[0]
    assert "2026-10-29" in title and "84,214 versions" in body and "flagged 2026-10-29: a" in body and "$1.60 yesterday" in body


def test_closed_report_counts_as_duplicate_only_if_osv_lists_the_package(app, monkeypatch):
    from gatekeeper.confirm import osv

    url = "https://github.com/ossf/malicious-packages/pull/1681"
    app.state.update(reports_watch=[url], autoreports={"spectral-core": {"pr": url}})
    pr = {"title": "Add malicious npm package spectral-core", "html_url": url}
    monkeypatch.setattr(osv, "query", lambda client, name: [{"id": "MAL-2026-18377"}])
    assert app._closed_as_duplicate(pr)
    assert app.state["reports_watch"] == [] and app.state["autoreports"]["spectral-core"]["closed_as_duplicate"]
    monkeypatch.setattr(osv, "query", lambda client, name: [{"id": "MAL-1", "withdrawn": "2026-10-30T00:00:00Z"}])
    assert not app._closed_as_duplicate(pr)  # a rejection: the breaker must stop reporting
    assert not app._closed_as_duplicate({"title": "Something else", "html_url": url})


def test_campaign_memory_takes_endpoints_only_from_agreed_verdicts(app):
    bundle = 'https.request("https://130.162.231.177:8443/", opts)'
    items = {
        "probe@1.0.0": {"name": "probe", "version": "1.0.0", "bundle": bundle, "publisher": "notsemz",
                        "verdicts": {"spark": {"verdict": "malicious"}, "glimmer-local": {"verdict": "malicious"}}},
        "maybe@1.0.0": {"name": "maybe", "version": "1.0.0", "bundle": 'fetch("https://203.0.114.7/")', "publisher": "someone",
                        "verdicts": {"spark": {"verdict": "malicious"}, "llamaguard-1b": {"verdict": "malicious"}}},
    }
    app._update_campaign_iocs(items)
    assert app.state["campaign_iocs"] == {"130.162.231.177": "probe@1.0.0"}
    assert app.state["campaign_publishers"] == {"notsemz": "probe@1.0.0"}


def test_catches_need_a_muse_verdict_and_skip_npm_placeholders(app):
    base = {"seen_at": "2026-10-28T10:00:00+00:00", "published_at": "2026-10-28T09:59:00+00:00",
            "confirmation": {"confirmed": True, "earliest_public": "2026-10-29T10:00:00+00:00"}}
    app.queue.update({
        "a@1.0.0": {**base, "name": "a", "version": "1.0.0", "verdicts": {"spark-open-baseten": {"verdict": "malicious"}}},
        "b@1.0.0": {**base, "name": "b", "version": "1.0.0", "verdicts": {"llamaguard-1b": {"verdict": "malicious"}}},
        "c@0.0.0-stage": {**base, "name": "c", "version": "0.0.0-stage", "verdicts": {"spark": {"verdict": "malicious"}}},
        "d@1.0.0": {**base, "name": "d", "version": "1.0.0", "verdicts": {"spark": {"verdict": "benign"}}},
    })
    app._record_catches()
    assert set(app.state["catches"]) == {"a@1.0.0"}
