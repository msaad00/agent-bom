"""Retention bounds apply to serialized summaries, not full graph objects."""

from agent_bom.api import graph_rollup_cache as cache


def test_retention_is_bounded_and_returns_independent_payloads(monkeypatch):
    monkeypatch.setattr(cache, "_CACHE", cache.OrderedDict())
    monkeypatch.setattr(cache, "_MAX_ENTRIES", 2)
    for i in range(3):
        cache.put((i,), {"count": i})
    assert cache.get((0,)) is None
    returned = cache.get((1,))
    returned["count"] = 99
    assert cache.get((1,)) == {"count": 1}
    cache.put(("oversized",), {"text": "x" * cache._MAX_ENTRY_BYTES})
    assert cache.get(("oversized",)) is None


def test_expiry_and_byte_eviction(monkeypatch):
    monkeypatch.setattr(cache, "_CACHE", cache.OrderedDict())
    monkeypatch.setattr(cache, "_MAX_BYTES", 32)
    cache.put(("a",), {"value": "a" * 10})
    cache.put(("b",), {"value": "b" * 10})
    assert cache.get(("a",)) is None
    assert cache.get(("b",))
    monkeypatch.setattr(cache.time, "monotonic", lambda: float("inf"))
    assert cache.get(("b",)) is None
