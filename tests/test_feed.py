import time

import httpx
import pytest

from gatekeeper.npm import feed


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_current_seq_retries_a_reset(monkeypatch):
    monkeypatch.setattr(feed.time, "sleep", lambda s: None)
    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            raise httpx.ConnectError("Connection reset by peer")
        return httpx.Response(200, json={"update_seq": 42})

    assert feed.current_seq(_client(handler)) == 42
    assert len(calls) == 2


def test_current_seq_gives_up(monkeypatch):
    monkeypatch.setattr(feed.time, "sleep", lambda s: None)

    def handler(request):
        raise httpx.ConnectError("Connection reset by peer")

    with pytest.raises(httpx.ConnectError):
        feed.current_seq(_client(handler))


def test_fetch_changes_stops_retrying_after_deadline(monkeypatch):
    monkeypatch.setattr(feed.time, "sleep", lambda s: None)
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(504)

    with pytest.raises(TimeoutError):
        feed.fetch_changes(_client(handler), since=1, deadline=time.monotonic() - 1)
    assert len(calls) == 1  # the first attempt runs, no retry after the deadline
