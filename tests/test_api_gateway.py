"""Tests for gateway API endpoints (/v1/gateway/*)."""

from starlette.testclient import TestClient

from agent_bom.api.policy_store import (
    GatewayPolicy,
    GatewayRule,
    InMemoryPolicyStore,
    PolicyAuditEntry,
    PolicyMode,
)
from agent_bom.api.server import app, set_policy_store


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _fresh_client() -> tuple[TestClient, InMemoryPolicyStore]:
    store = InMemoryPolicyStore()
    set_policy_store(store)
    return TestClient(app), store


def _make_policy(
    policy_id: str = "p-1",
    name: str = "test-policy",
    mode: PolicyMode = PolicyMode.ENFORCE,
    **kw,
) -> GatewayPolicy:
    ts = _now()
    return GatewayPolicy(
        policy_id=policy_id,
        name=name,
        mode=mode,
        rules=[GatewayRule(id="r1", action="block", block_tools=["exec"])],
        created_at=ts,
        updated_at=ts,
        **kw,
    )


# ── List ──────────────────────────────────────────────────────────────────────


def test_list_empty():
    client, _ = _fresh_client()
    resp = client.get("/v1/gateway/policies")
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_list_with_policies():
    client, store = _fresh_client()
    store.put_policy(_make_policy(policy_id="p-1", name="alpha"))
    store.put_policy(_make_policy(policy_id="p-2", name="beta"))
    resp = client.get("/v1/gateway/policies")
    assert resp.json()["count"] == 2


def test_list_filter_mode():
    client, store = _fresh_client()
    store.put_policy(_make_policy(policy_id="p-1", mode=PolicyMode.AUDIT))
    store.put_policy(_make_policy(policy_id="p-2", mode=PolicyMode.ENFORCE))
    resp = client.get("/v1/gateway/policies?mode=enforce")
    assert resp.json()["count"] == 1


# ── Create ────────────────────────────────────────────────────────────────────


def test_create_policy():
    client, store = _fresh_client()
    resp = client.post("/v1/gateway/policies", json={
        "name": "block-exec",
        "mode": "enforce",
        "rules": [{"id": "r1", "action": "block", "block_tools": ["exec"]}],
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "block-exec"
    assert data["mode"] == "enforce"
    assert len(store.list_policies()) == 1


def test_create_invalid_mode():
    client, _ = _fresh_client()
    resp = client.post("/v1/gateway/policies", json={"name": "bad", "mode": "bogus"})
    assert resp.status_code == 400


# ── Get ───────────────────────────────────────────────────────────────────────


def test_get_policy():
    client, store = _fresh_client()
    store.put_policy(_make_policy(policy_id="p-1", name="alpha"))
    resp = client.get("/v1/gateway/policies/p-1")
    assert resp.status_code == 200
    assert resp.json()["name"] == "alpha"


def test_get_not_found():
    client, _ = _fresh_client()
    resp = client.get("/v1/gateway/policies/missing")
    assert resp.status_code == 404


# ── Update ────────────────────────────────────────────────────────────────────


def test_update_policy():
    client, store = _fresh_client()
    store.put_policy(_make_policy())
    resp = client.put("/v1/gateway/policies/p-1", json={"name": "renamed", "mode": "audit"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "renamed"
    assert resp.json()["mode"] == "audit"


def test_update_not_found():
    client, _ = _fresh_client()
    resp = client.put("/v1/gateway/policies/missing", json={"name": "x"})
    assert resp.status_code == 404


# ── Delete ────────────────────────────────────────────────────────────────────


def test_delete_policy():
    client, store = _fresh_client()
    store.put_policy(_make_policy())
    resp = client.delete("/v1/gateway/policies/p-1")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True
    assert len(store.list_policies()) == 0


def test_delete_not_found():
    client, _ = _fresh_client()
    resp = client.delete("/v1/gateway/policies/missing")
    assert resp.status_code == 404


# ── Evaluate ──────────────────────────────────────────────────────────────────


def test_evaluate_allowed():
    client, store = _fresh_client()
    store.put_policy(_make_policy())
    resp = client.post("/v1/gateway/evaluate", json={"tool_name": "safe_tool"})
    assert resp.status_code == 200
    assert resp.json()["allowed"] is True


def test_evaluate_blocked():
    client, store = _fresh_client()
    store.put_policy(_make_policy())
    resp = client.post("/v1/gateway/evaluate", json={"tool_name": "exec"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["allowed"] is False
    assert "exec" in data["reason"]


def test_evaluate_no_policies():
    client, _ = _fresh_client()
    resp = client.post("/v1/gateway/evaluate", json={"tool_name": "anything"})
    assert resp.json()["allowed"] is True


# ── Audit ─────────────────────────────────────────────────────────────────────


def test_audit_empty():
    client, _ = _fresh_client()
    resp = client.get("/v1/gateway/audit")
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_audit_populated():
    client, store = _fresh_client()
    store.put_audit_entry(PolicyAuditEntry(
        entry_id="e-1",
        policy_id="p-1",
        policy_name="test",
        rule_id="r1",
        agent_name="agent-a",
        tool_name="exec",
        action_taken="blocked",
        reason="blocked",
        timestamp=_now(),
    ))
    resp = client.get("/v1/gateway/audit")
    assert resp.json()["count"] == 1


# ── Stats ─────────────────────────────────────────────────────────────────────


def test_stats_empty():
    client, _ = _fresh_client()
    resp = client.get("/v1/gateway/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_policies"] == 0
    assert data["blocked_count"] == 0


def test_stats_populated():
    client, store = _fresh_client()
    store.put_policy(_make_policy(policy_id="p-1", mode=PolicyMode.ENFORCE))
    store.put_policy(_make_policy(policy_id="p-2", mode=PolicyMode.AUDIT))
    store.put_audit_entry(PolicyAuditEntry(
        entry_id="e-1",
        policy_id="p-1",
        policy_name="test",
        rule_id="r1",
        agent_name="a",
        tool_name="exec",
        action_taken="blocked",
        reason="r",
        timestamp=_now(),
    ))
    resp = client.get("/v1/gateway/stats")
    data = resp.json()
    assert data["total_policies"] == 2
    assert data["enforce_count"] == 1
    assert data["audit_count"] == 1
    assert data["blocked_count"] == 1
