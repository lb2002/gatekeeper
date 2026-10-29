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
