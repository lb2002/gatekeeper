import time

from gatekeeper.monitor import process_names


def test_names_past_the_deadline_are_deferred_without_network():
    # client=None: any network call would raise, so this also checks nothing is fetched
    records, deferred = process_names(None, ["a", "b", "@s/c"], set(), set(), deadline=time.monotonic() - 1)
    assert records == []
    assert sorted(deferred) == ["@s/c", "a", "b"]
