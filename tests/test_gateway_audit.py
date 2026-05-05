"""Regression tests for gateway-evaluate audit logging (audit finding P1-A).

Every call to ``POST /v1/gateway/evaluate`` must write an audit row to the
policy store regardless of whether the call was allowed, blocked, or
matched in audit-mode. Compliance/forensics requires that every policy
decision be replayable, including which rule fired.
"""

from __future__ import annotations

from datetime import datetime, timezone

from starlette.testclient import TestClient

from agent_bom.api.policy_store import (
    GatewayPolicy,
    GatewayRule,
    InMemoryPolicyStore,
    PolicyMode,
)
from agent_bom.api.server import app, set_policy_store

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
ADMIN_HEADERS = {
    "X-Agent-Bom-Role": "admin",
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
    return datetime.now(timezone.utc).isoformat()


def _fresh_client() -> tuple[TestClient, InMemoryPolicyStore]:
    store = InMemoryPolicyStore()
    set_policy_store(store)
    client = TestClient(app)
    client.headers.update(ADMIN_HEADERS)
    return client, store


def _block_shell_policy(mode: PolicyMode = PolicyMode.ENFORCE) -> GatewayPolicy:
    ts = _now()
    return GatewayPolicy(
        policy_id="p-block-shell",
        name="block-shell",
        mode=mode,
        rules=[
            GatewayRule(id="r-shell", action="block", tool_name_pattern=r"shell\..*"),
        ],
        created_at=ts,
        updated_at=ts,
    )


def test_evaluate_block_writes_audit_entry() -> None:
    client, store = _fresh_client()
    store.put_policy(_block_shell_policy())

    resp = client.post(
        "/v1/gateway/evaluate",
        json={
            "agent_name": "agent-a",
            "tool_name": "shell.exec",
            "arguments": {"cmd": "ls"},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allowed"] is False
    assert body["rule_id"] == "r-shell"
    assert body["policy_id"] == "p-block-shell"
    assert body["policy_name"] == "block-shell"
    assert body["policy_mode"] == "enforce"
    assert body["action_taken"] == "blocked"

    audit_resp = client.get("/v1/gateway/audit")
    assert audit_resp.status_code == 200
    audit_body = audit_resp.json()
    assert audit_body["count"] == 1
    entry = audit_body["entries"][0]
    assert entry["policy_id"] == "p-block-shell"
    assert entry["policy_name"] == "block-shell"
    assert entry["rule_id"] == "r-shell"
    assert entry["agent_name"] == "agent-a"
    assert entry["tool_name"] == "shell.exec"
    assert entry["action_taken"] == "blocked"
    assert "shell.exec" in entry["reason"]
    assert entry["arguments_preview"] == {"cmd": "[replay-only]"}
    assert entry["timestamp"]
    assert entry["tenant_id"] == "default"


def test_evaluate_allow_also_writes_audit_entry() -> None:
    client, store = _fresh_client()
    store.put_policy(_block_shell_policy())

    # block first
    client.post(
        "/v1/gateway/evaluate",
        json={"agent_name": "agent-a", "tool_name": "shell.exec", "arguments": {}},
    )
    # then a clean allow
    resp = client.post(
        "/v1/gateway/evaluate",
        json={"agent_name": "agent-a", "tool_name": "read.file", "arguments": {"path": "/etc/hosts"}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allowed"] is True
    assert body["action_taken"] == "allowed"
    assert body["policy_id"] is None
    assert body["rule_id"] is None

    audit_body = client.get("/v1/gateway/audit").json()
    assert audit_body["count"] == 2
    actions = sorted(e["action_taken"] for e in audit_body["entries"])
    assert actions == ["allowed", "blocked"]
    allow_entry = next(e for e in audit_body["entries"] if e["action_taken"] == "allowed")
    assert allow_entry["tool_name"] == "read.file"
    assert allow_entry["policy_id"] == ""
    assert allow_entry["rule_id"] == ""


def test_evaluate_audit_mode_match_records_alerted() -> None:
    client, store = _fresh_client()
    store.put_policy(_block_shell_policy(mode=PolicyMode.AUDIT))

    resp = client.post(
        "/v1/gateway/evaluate",
        json={"agent_name": "agent-a", "tool_name": "shell.exec", "arguments": {}},
    )
    body = resp.json()
    # audit-mode policies don't actually deny — they alert
    assert body["allowed"] is True
    assert body["action_taken"] == "alerted"
    assert body["policy_mode"] == "audit"
    assert body["rule_id"] == "r-shell"
    assert body["reason"].startswith("[audit]")

    audit_body = client.get("/v1/gateway/audit").json()
    assert audit_body["count"] == 1
    entry = audit_body["entries"][0]
    assert entry["action_taken"] == "alerted"
    assert entry["rule_id"] == "r-shell"


def test_evaluate_block_increments_blocked_count_in_stats() -> None:
    """P1-A symptom check: stats must reflect blocked decisions."""
    client, store = _fresh_client()
    store.put_policy(_block_shell_policy())

    client.post(
        "/v1/gateway/evaluate",
        json={"agent_name": "agent-a", "tool_name": "shell.exec", "arguments": {}},
    )
    stats = client.get("/v1/gateway/stats").json()
    assert stats["audit_entries"] == 1
    assert stats["blocked_count"] == 1


def test_evaluate_redacts_oversized_argument_values() -> None:
    """audit_preview values must be capped — no raw secrets stored."""
    client, store = _fresh_client()
    store.put_policy(_block_shell_policy())

    long_value = "x" * 1024
    client.post(
        "/v1/gateway/evaluate",
        json={
            "agent_name": "agent-a",
            "tool_name": "shell.exec",
            "arguments": {"command_name": long_value, "path": "/Users/alice/prod/secrets.txt"},
        },
    )
    entry = client.get("/v1/gateway/audit").json()["entries"][0]
    preview = entry["arguments_preview"]["command_name"]
    assert len(preview) <= 257  # 256 chars + ellipsis
    assert preview.endswith("…")
    assert entry["arguments_preview"]["path"] == "[replay-only]"
