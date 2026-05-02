"""Firewall decision store + ingest + endpoint tests (#982 PR 4)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from agent_bom.api.firewall_decision_store import FirewallDecisionStore


def _decision_event(
    *,
    source: str = "cursor",
    target: str = "snowflake-cli",
    decision: str = "deny",
    effective: str | None = None,
    enforcement_mode: str = "enforce",
    timestamp: float = 1.0,
    matched_description: str = "no direct DB",
) -> dict[str, Any]:
    return {
        "action": "gateway.firewall_decision",
        "source_agent": source,
        "target_agent": target,
        "decision": decision,
        "effective_decision": effective if effective is not None else decision,
        "matched_rule": {
            "source": source,
            "target": target,
            "decision": decision,
            "description": matched_description,
        },
        "tenant_id": "acme",
        "enforcement_mode": enforcement_mode,
        "timestamp": timestamp,
    }


def test_store_ignores_non_firewall_events() -> None:
    store = FirewallDecisionStore()
    store.record(tenant_id="acme", event={"action": "gateway.rate_limited"})
    stats = store.stats(tenant_id="acme")
    assert stats == {
        "total_decisions": 0,
        "allow": 0,
        "warn": 0,
        "deny": 0,
        "last_seen_ts": None,
        "top_pairs": [],
        "recent": [],
    }


def test_store_tallies_deny_and_emits_recent_pair() -> None:
    store = FirewallDecisionStore()
    store.record(tenant_id="acme", event=_decision_event())
    stats = store.stats(tenant_id="acme")
    assert stats["total_decisions"] == 1
    assert stats["deny"] == 1
    assert stats["allow"] == 0
    assert stats["warn"] == 0
    assert stats["last_seen_ts"] == 1.0
    assert len(stats["top_pairs"]) == 1
    assert stats["top_pairs"][0]["source_agent"] == "cursor"
    assert stats["top_pairs"][0]["target_agent"] == "snowflake-cli"
    assert stats["top_pairs"][0]["deny"] == 1
    assert len(stats["recent"]) == 1
    assert stats["recent"][0]["matched_rule"]["description"] == "no direct DB"


def test_store_separates_tenants() -> None:
    store = FirewallDecisionStore()
    store.record(tenant_id="acme", event=_decision_event())
    store.record(tenant_id="globex", event=_decision_event(target="postgres-cli"))
    a = store.stats(tenant_id="acme")
    b = store.stats(tenant_id="globex")
    assert a["total_decisions"] == 1
    assert b["total_decisions"] == 1
    assert a["top_pairs"][0]["target_agent"] == "snowflake-cli"
    assert b["top_pairs"][0]["target_agent"] == "postgres-cli"


def test_store_dry_run_records_warn_effective() -> None:
    store = FirewallDecisionStore()
    store.record(
        tenant_id="acme",
        event=_decision_event(decision="deny", effective="warn", enforcement_mode="dry_run"),
    )
    stats = store.stats(tenant_id="acme")
    assert stats["deny"] == 0
    assert stats["warn"] == 1
    assert stats["recent"][0]["enforcement_mode"] == "dry_run"


def test_store_top_pairs_sorted_by_deny_then_warn_then_allow() -> None:
    store = FirewallDecisionStore()
    # Pair A: 1 deny
    store.record(tenant_id="acme", event=_decision_event(source="A", target="X"))
    # Pair B: 2 warns
    store.record(tenant_id="acme", event=_decision_event(source="B", target="X", decision="warn"))
    store.record(tenant_id="acme", event=_decision_event(source="B", target="X", decision="warn"))
    # Pair C: 3 allows
    for _ in range(3):
        store.record(tenant_id="acme", event=_decision_event(source="C", target="X", decision="allow"))

    stats = store.stats(tenant_id="acme")
    pairs = stats["top_pairs"]
    assert pairs[0]["source_agent"] == "A"  # deny outranks
    assert pairs[1]["source_agent"] == "B"  # warn outranks allow
    assert pairs[2]["source_agent"] == "C"


def test_store_recent_capacity_caps_buffer() -> None:
    store = FirewallDecisionStore(recent_capacity=3)
    for i in range(10):
        store.record(tenant_id="acme", event=_decision_event(source=f"src{i}", timestamp=float(i)))
    stats = store.stats(tenant_id="acme", recent_limit=10)
    assert len(stats["recent"]) == 3
    timestamps = [r["timestamp"] for r in stats["recent"]]
    # Newest first; ring buffer kept i = 7, 8, 9.
    assert timestamps == [9.0, 8.0, 7.0]


def test_store_invalid_event_silently_dropped() -> None:
    store = FirewallDecisionStore()
    # missing source_agent
    store.record(tenant_id="acme", event={"action": "gateway.firewall_decision", "target_agent": "x", "decision": "deny"})
    # decision not a string
    store.record(tenant_id="acme", event={"action": "gateway.firewall_decision", "source_agent": "a", "target_agent": "b", "decision": 1})
    assert store.stats(tenant_id="acme")["total_decisions"] == 0


def test_store_reset_for_tenant() -> None:
    store = FirewallDecisionStore()
    store.record(tenant_id="acme", event=_decision_event())
    store.record(tenant_id="globex", event=_decision_event())
    store.reset(tenant_id="acme")
    assert store.stats(tenant_id="acme")["total_decisions"] == 0
    assert store.stats(tenant_id="globex")["total_decisions"] == 1


# ─── Endpoint integration: ingest -> store -> /v1/firewall/stats ────────────


# Match the constant used by other API auth tests so that regardless of
# which test imports the FastAPI app first, the trusted-proxy secret cached
# in middleware at instance time matches the value our headers use. Tests
# that swap the secret per-test would race against the cached value.
_PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
_AUTH_HEADERS = {
    "X-Agent-Bom-Role": "admin",
    # Use the "default" tenant — /v1/proxy/audit ingest reads tenant_id from
    # request.state which middleware initialises to "default" when no auth
    # dependency runs (the ingest endpoint is intentionally light to keep
    # proxies unblocked). /v1/firewall/stats does run the RBAC dep, but
    # both endpoints converge on "default" when this header matches.
    "X-Agent-Bom-Tenant-ID": "default",
    "X-Agent-Bom-Proxy-Secret": _PROXY_SECRET,
}


@pytest.fixture
def api_client(monkeypatch):  # noqa: ANN001
    """Build the FastAPI app with a fresh firewall store wired in."""
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", _PROXY_SECRET)
    from agent_bom.api.server import app
    from agent_bom.api.stores import set_firewall_decision_store

    set_firewall_decision_store(FirewallDecisionStore())
    yield TestClient(app)
    set_firewall_decision_store(FirewallDecisionStore())  # reset between tests


def test_endpoint_default_empty(api_client) -> None:  # noqa: ANN001
    response = api_client.get("/v1/firewall/stats", headers=_AUTH_HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["total_decisions"] == 0
    assert body["recent"] == []


def test_endpoint_after_ingest(api_client) -> None:  # noqa: ANN001
    ingest = api_client.post(
        "/v1/proxy/audit",
        headers=_AUTH_HEADERS,
        json={
            "source_id": "gateway",
            "session_id": "test",
            "alerts": [_decision_event()],
        },
    )
    assert ingest.status_code == 200, ingest.text
    response = api_client.get("/v1/firewall/stats", headers=_AUTH_HEADERS)
    body = response.json()
    assert body["total_decisions"] == 1
    assert body["deny"] == 1
    assert body["recent"][0]["target_agent"] == "snowflake-cli"
    assert body["top_pairs"][0]["deny"] == 1


def test_gateway_stats_includes_firewall_runtime(api_client) -> None:  # noqa: ANN001
    api_client.post(
        "/v1/proxy/audit",
        headers=_AUTH_HEADERS,
        json={
            "source_id": "gateway",
            "session_id": "test",
            "alerts": [
                _decision_event(),
                _decision_event(decision="warn"),
            ],
        },
    )
    response = api_client.get("/v1/gateway/stats", headers=_AUTH_HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert "firewall_runtime" in body
    assert body["firewall_runtime"]["total_decisions"] == 2
    assert body["firewall_runtime"]["deny"] == 1
    assert body["firewall_runtime"]["warn"] == 1
