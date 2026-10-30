import time

from gatekeeper.monitor import process_names


def test_names_past_the_deadline_are_deferred_without_network():
    # client=None: any network call would raise, so this also checks nothing is fetched
    records, deferred = process_names(None, ["a", "b", "@s/c"], set(), set(), deadline=time.monotonic() - 1)
    assert records == []
    assert sorted(deferred) == ["@s/c", "a", "b"]


def test_a_young_package_with_an_install_hook_always_reaches_a_model(monkeypatch):
    import io
    import json
    import tarfile
    from datetime import datetime, timedelta, timezone

    from gatekeeper import monitor
    from gatekeeper.npm.packument import VersionInfo

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        for name, body in (("package/package.json", json.dumps({"name": "x", "version": "1.0.0",
                                                                  "scripts": {"postinstall": "node setup.js"}})),
                           ("package/setup.js", "console.log('thanks for installing');\n")):
            data = body.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    monkeypatch.setattr(monitor, "download_capped", lambda client, url: raw.getvalue())
    now = datetime(2026, 10, 30, tzinfo=timezone.utc)

    def rec(created_days_ago):
        info = VersionInfo(name="x", version="1.0.0", published_at=now, package_created_at=now - timedelta(days=created_days_ago),
                           install_scripts={"postinstall": "node setup.js"}, has_repository=True, tarball_url="https://r/x.tgz",
                           version_count=1)
        return monitor.process_version(None, info, set(), now)

    young, old = rec(1), rec(30)
    assert young.scanned and young.flagged
    assert old.scanned and not old.flagged


def test_a_reupload_to_a_known_campaign_endpoint_is_flagged(monkeypatch):
    import io
    import json
    import tarfile
    from datetime import datetime, timedelta, timezone

    from gatekeeper import monitor
    from gatekeeper.npm.packument import VersionInfo

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        for name, body in (("package/package.json", json.dumps({"name": "y", "version": "2.0.0"})),
                           ("package/lib.js", 'module.exports = () => fetch("https://203.0.114.9:8443/");\n')):
            data = body.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    monkeypatch.setattr(monitor, "download_capped", lambda client, url: raw.getvalue())
    now = datetime(2026, 10, 30, tzinfo=timezone.utc)
    info = VersionInfo(name="y", version="2.0.0", published_at=now, package_created_at=now - timedelta(days=30),
                       has_repository=True, tarball_url="https://r/y.tgz", version_count=3)
    plain = monitor.process_version(None, info, set(), now)
    assert plain.scanned and not plain.flagged
    rec = monitor.process_version(None, info, set(), now, campaign={"203.0.114.9": "evil@1.0.0"})
    assert rec.flagged and "known_campaign_endpoint" in rec.rules
    assert any("evil@1.0.0" in r for r in rec.meta_reasons)


def test_any_new_version_from_a_known_bad_account_reaches_a_model(monkeypatch):
    import io
    import json
    import tarfile
    from datetime import datetime, timedelta, timezone

    from gatekeeper import monitor
    from gatekeeper.npm.packument import VersionInfo

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        data = json.dumps({"name": "z", "version": "5.0.0"}).encode()
        info = tarfile.TarInfo("package/package.json")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    monkeypatch.setattr(monitor, "download_capped", lambda client, url: raw.getvalue())
    now = datetime(2026, 10, 30, tzinfo=timezone.utc)
    # an old, much-updated package: normally not even downloaded
    info = VersionInfo(name="z", version="5.0.0", published_at=now, package_created_at=now - timedelta(days=400),
                       has_repository=True, tarball_url="https://r/z.tgz", version_count=80, publisher="sleeper")
    assert not monitor.process_version(None, info, set(), now).scanned
    rec = monitor.process_version(None, info, set(), now, publishers={"sleeper": "random-transactions-sdk@1.0.1"})
    assert rec.scanned and rec.flagged and "known_bad_publisher" in rec.rules and rec.publisher == "sleeper"
    assert any("random-transactions-sdk@1.0.1" in r for r in rec.meta_reasons)


class _Stream:
    def __init__(self, peer):
        self.peer = peer

    def get_extra_info(self, key):
        return self.peer if key == "server_addr" else None


def _author_url_client(status=200, peer=("93.184.216.34", 443), body=b"ok", headers=None):
    import httpx

    def answer(request):
        return httpx.Response(status, content=body, headers=headers, extensions={"network_stream": _Stream(peer)})

    return httpx.Client(transport=httpx.MockTransport(answer), follow_redirects=True)


def test_a_url_chosen_by_an_author_may_not_redirect():
    import httpx
    import pytest

    from gatekeeper import monitor

    client = _author_url_client(302, headers={"location": "http://169.254.169.254/x"})
    with pytest.raises(httpx.HTTPStatusError):
        monitor.download_capped(client, "https://evil.example/a.tgz", public_only=True)


def test_a_url_that_turns_out_internal_is_not_read():
    import pytest

    from gatekeeper import monitor

    for peer in (("169.254.169.254", 80), ("10.0.0.1", 443), None):
        with pytest.raises(OSError):
            monitor.download_capped(_author_url_client(peer=peer), "https://evil.example/a.tgz", public_only=True)
    assert monitor.download_capped(_author_url_client(), "https://evil.example/a.tgz", public_only=True) == b"ok"


def test_a_slow_url_is_given_up(monkeypatch):
    import pytest

    from gatekeeper import monitor

    ticks = iter([0, 100])
    monkeypatch.setattr(monitor.time, "monotonic", lambda: next(ticks))
    with pytest.raises(OSError):
        monitor.download_capped(_author_url_client(), "https://evil.example/a.tgz", public_only=True)


def test_a_stretch_of_time_can_be_read_again(monkeypatch):
    from datetime import datetime, timedelta, timezone

    from gatekeeper import monitor

    now = datetime(2026, 10, 30, 15, tzinfo=timezone.utc)
    doc = {"name": "x", "dist-tags": {"latest": "2.0.0"}, "time": {"1.0.0": "2026-10-29T18:00:00.000Z", "2.0.0": "2026-10-30T10:00:00.000Z"},
           "versions": {"1.0.0": {"name": "x", "version": "1.0.0", "dist": {}}, "2.0.0": {"name": "x", "version": "2.0.0", "dist": {}}}}
    monkeypatch.setattr(monitor.packument, "fetch_packument", lambda client, name: doc)
    records, _ = process_names(None, ["x"], set(), set(), now=now, window=timedelta(days=1), before=datetime(2026, 10, 29, 22, tzinfo=timezone.utc))
    assert [r.version for r in records] == ["1.0.0"]
