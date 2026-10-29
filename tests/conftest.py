import pytest


@pytest.fixture(autouse=True)
def _no_online_osv(monkeypatch):
    """Tests never contact OSV; the ones that need the online check switch it back on."""
    import gatekeeper.guard.core as core

    monkeypatch.setattr(core, "OSV_ONLINE", False)
