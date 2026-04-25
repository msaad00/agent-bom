"""Tests for gateway API endpoints (/v1/gateway/*)."""

from starlette.testclient import TestClient

from agent_bom.api.audit_log import InMemoryAuditLog, set_audit_log
from agent_bom.api.policy_store import (
    GatewayPolicy,
    GatewayRule,
    InMemoryPolicyStore,
    PolicyAuditEntry,
    PolicyMode,
)
from agent_bom.api.server import app, set_policy_store

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
ADMIN_HEADERS = {
    "X-Agent-Bom-Role": "admin",
    "X-Agent-Bom-Tenant-ID": "default",
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}
VIEWER_HEADERS = {
    "X-Agent-Bom-Role": "viewer",
    "X-Agent-Bom-Tenant-ID": "default",
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}


def setup_module() -> None:
    import os

    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET


def teardown_module() -> None:
    import os

    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH", None)
    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", None)


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _fresh_client() -> tuple[TestClient, InMemoryPolicyStore]:
    store = InMemoryPolicyStore()
    set_policy_store(store)
    client = TestClient(app)
    client.headers.update(ADMIN_HEADERS)
    return client, store


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


def test_list_policies_emits_etag_and_supports_not_modified():
    client, store = _fresh_client()
    store.put_policy(_make_policy(policy_id="p-1", name="alpha"))
    resp = client.get("/v1/gateway/policies?enabled=true")
    assert resp.status_code == 200
    etag = resp.headers["etag"]
    cached = client.get("/v1/gateway/policies?enabled=true", headers={**ADMIN_HEADERS, "If-None-Match": etag})
    assert cached.status_code == 304
    assert cached.headers["etag"] == etag


# ── Create ────────────────────────────────────────────────────────────────────


def test_create_policy():
    client, store = _fresh_client()
    resp = client.post(
        "/v1/gateway/policies",
        json={
            "name": "block-exec",
            "mode": "enforce",
            "rules": [{"id": "r1", "action": "block", "block_tools": ["exec"]}],
        },
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "block-exec"
    assert data["mode"] == "enforce"
    assert data["tenant_id"] == "default"
    assert len(store.list_policies()) == 1


def test_create_invalid_mode():
    client, _ = _fresh_client()
    resp = client.post("/v1/gateway/policies", json={"name": "bad", "mode": "bogus"}, headers=ADMIN_HEADERS)
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


def test_get_cross_tenant_hidden():
    client, store = _fresh_client()
    store.put_policy(_make_policy(policy_id="p-1", tenant_id="tenant-b"))
    resp = client.get("/v1/gateway/policies/p-1")
    assert resp.status_code == 404


# ── Update ────────────────────────────────────────────────────────────────────


def test_update_policy():
    client, store = _fresh_client()
    store.put_policy(_make_policy())
    resp = client.put("/v1/gateway/policies/p-1", json={"name": "renamed", "mode": "audit"}, headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["name"] == "renamed"
    assert resp.json()["mode"] == "audit"


def test_update_not_found():
    client, _ = _fresh_client()
    resp = client.put("/v1/gateway/policies/missing", json={"name": "x"}, headers=ADMIN_HEADERS)
    assert resp.status_code == 404


# ── Delete ────────────────────────────────────────────────────────────────────


def test_delete_policy():
    client, store = _fresh_client()
    store.put_policy(_make_policy())
    resp = client.delete("/v1/gateway/policies/p-1", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True
    assert len(store.list_policies()) == 0


def test_delete_not_found():
    client, _ = _fresh_client()
    resp = client.delete("/v1/gateway/policies/missing", headers=ADMIN_HEADERS)
    assert resp.status_code == 404


def test_policy_crud_writes_general_audit_log():
    client, store = _fresh_client()
    audit_store = InMemoryAuditLog()
    set_audit_log(audit_store)
    store.put_policy(_make_policy())

    created = client.post(
        "/v1/gateway/policies",
        json={"name": "block-exec", "mode": "enforce", "rules": [{"id": "r1", "action": "block", "block_tools": ["exec"]}]},
        headers=ADMIN_HEADERS,
    )
    assert created.status_code == 201

    updated = client.put("/v1/gateway/policies/p-1", json={"name": "renamed"}, headers=ADMIN_HEADERS)
    assert updated.status_code == 200

    deleted = client.delete("/v1/gateway/policies/p-1", headers=ADMIN_HEADERS)
    assert deleted.status_code == 200

    assert audit_store.count("gateway.policy_created") == 1
    assert audit_store.count("gateway.policy_updated") == 1
    assert audit_store.count("gateway.policy_deleted") == 1


def test_write_routes_require_policy_write_permission():
    client, store = _fresh_client()
    store.put_policy(_make_policy())
    payload = {
        "name": "block-exec",
        "mode": "enforce",
        "rules": [{"id": "r1", "action": "block", "block_tools": ["exec"]}],
    }
    assert client.post("/v1/gateway/policies", json=payload, headers=VIEWER_HEADERS).status_code == 403
    assert client.put("/v1/gateway/policies/p-1", json={"name": "renamed"}, headers=VIEWER_HEADERS).status_code == 403
    assert client.delete("/v1/gateway/policies/p-1", headers=VIEWER_HEADERS).status_code == 403


def test_list_hides_other_tenants():
    client, store = _fresh_client()
    store.put_policy(_make_policy(policy_id="p-1", tenant_id="default"))
    store.put_policy(_make_policy(policy_id="p-2", tenant_id="tenant-b"))
    resp = client.get("/v1/gateway/policies")
    assert resp.status_code == 200
    assert [p["policy_id"] for p in resp.json()["policies"]] == ["p-1"]


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
    store.put_audit_entry(
        PolicyAuditEntry(
            entry_id="e-1",
            policy_id="p-1",
            policy_name="test",
            rule_id="r1",
            agent_name="agent-a",
            tool_name="exec",
            action_taken="blocked",
            reason="blocked",
            timestamp=_now(),
        )
    )
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
    assert data["policy_runtime"] == {
        "source": "control_plane",
        "source_kind": "policy_store",
        "enabled_policies": 0,
        "rollout_mode": "disabled",
        "summary": "No runtime policy rules configured.",
        "total_rules": 0,
        "blocking_rules": 0,
        "advisory_rules": 0,
        "allowlist_rules": 0,
        "default_deny_rules": 0,
        "read_only_rules": 0,
        "secret_path_rules": 0,
        "unknown_egress_rules": 0,
        "denied_tool_classes": [],
        "blocks_requests": False,
        "advisory_only": False,
        "default_deny": False,
        "protects_secret_paths": False,
        "restricts_unknown_egress": False,
    }


def test_stats_populated():
    client, store = _fresh_client()
    store.put_policy(_make_policy(policy_id="p-1", mode=PolicyMode.ENFORCE))
    store.put_policy(_make_policy(policy_id="p-2", mode=PolicyMode.AUDIT))
    store.put_audit_entry(
        PolicyAuditEntry(
            entry_id="e-1",
            policy_id="p-1",
            policy_name="test",
            rule_id="r1",
            agent_name="a",
            tool_name="exec",
            action_taken="blocked",
            reason="r",
            timestamp=_now(),
        )
    )
    resp = client.get("/v1/gateway/stats")
    data = resp.json()
    assert data["total_policies"] == 2
    assert data["enforce_count"] == 1
    assert data["audit_count"] == 1
    assert data["blocked_count"] == 1
    assert data["policy_runtime"]["enabled_policies"] == 2
    assert data["policy_runtime"]["rollout_mode"] == "mixed"
    assert data["policy_runtime"]["blocking_rules"] == 1
    assert data["policy_runtime"]["advisory_rules"] == 1


def test_stats_reflect_protective_controls():
    client, store = _fresh_client()
    ts = _now()
    store.put_policy(
        GatewayPolicy(
            policy_id="p-protect",
            name="protective-controls",
            mode=PolicyMode.ENFORCE,
            rules=[
                GatewayRule(
                    id="r-protect",
                    action="block",
                    block_tools=["fetch_url"],
                    description="Protect secrets and outbound egress",
                    block_secret_paths=True,
                    block_unknown_egress=True,
                    allowed_hosts=["api.openai.com"],
                    deny_tool_classes=["network"],
                )
            ],
            created_at=ts,
            updated_at=ts,
            tenant_id="default",
        )
    )

    resp = client.get("/v1/gateway/stats")
    data = resp.json()["policy_runtime"]
    assert data["rollout_mode"] == "blocking"
    assert data["blocking_rules"] == 1
    assert data["protects_secret_paths"] is True
    assert data["restricts_unknown_egress"] is True
    assert data["denied_tool_classes"] == ["network"]
