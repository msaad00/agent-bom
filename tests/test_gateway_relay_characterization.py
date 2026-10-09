"""Characterization tests for gateway relay branches not pinned elsewhere.

Each test drives the public ``/mcp/{server}`` route and asserts the exact
status, body, headers, audit records and upstream reach for one decision
branch, so the relay's stage decomposition stays behaviour-preserving.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom import agent_identity
from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
    issue_identity,
    set_agent_identity_store,
    verify_token,
)
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.runtime.graph_reachability import ReachabilityMap


class _Harness:
    def __init__(self) -> None:
        self.audit: list[dict[str, Any]] = []
        self.upstream: list[dict[str, Any]] = []

    async def sink(self, event: dict[str, Any]) -> None:
        self.audit.append(event)

    async def caller(self, upstream: Any, message: dict[str, Any], extra_headers: dict[str, str]) -> dict[str, Any]:
        self.upstream.append(message)
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    def settings(self, **overrides: Any) -> GatewaySettings:
        values: dict[str, Any] = {
            "registry": UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
            "policy": {"agent_tokens": {"token-a": "agent-a"}},
            "upstream_caller": self.caller,
            "audit_sink": self.sink,
        }
        values.update(overrides)
        return GatewaySettings(**values)

    def actions(self) -> list[str]:
        return [str(event.get("action")) for event in self.audit]


def _call(tool: str = "read_file", token: str | None = "token-a", **meta: Any) -> dict[str, Any]:
    params: dict[str, Any] = {"name": tool, "arguments": {"path": "/tmp/x"}}
    if token is not None:
        meta["agent_identity"] = token
    if meta:
        params["_meta"] = meta
    return {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params}


def _non_loopback(**overrides: Any) -> dict[str, Any]:
    return {
        "listener_host": "0.0.0.0",
        "bearer_token": "gateway-transport-token",
        "bearer_token_expires_at": (datetime.now(timezone.utc) + timedelta(minutes=45)).isoformat(),
        **overrides,
    }


_BEARER = {"Authorization": "Bearer gateway-transport-token"}


@pytest.fixture(autouse=True)
def _reset_identity_store():
    yield
    set_agent_identity_store(None)
    agent_identity.set_local_identity_verifier(None)


def _managed_identity(*, blueprint_id: str = "finance", allowed_tools: list[str] | None = None) -> tuple[Any, str]:
    store = InMemoryAgentIdentityStore()
    identity, token = issue_identity(
        store,
        agent_id="agent-a",
        tenant_id="default",
        blueprint_id=blueprint_id,
        allowed_tools=allowed_tools,
        owner="security-team",
    )
    set_agent_identity_store(store)
    agent_identity.set_local_identity_verifier(lambda raw: verify_token(store, raw))
    return identity, token


def _blocked(code: int, message: str, data: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 7, "error": {"code": code, "message": message, "data": data}}


# --- request parsing -------------------------------------------------------


def test_invalid_content_length_is_rejected_before_body_read() -> None:
    h = _Harness()
    client = TestClient(create_gateway_app(h.settings()))
    resp = client.post("/mcp/filesystem", content=b"{}", headers={"content-length": "abc", "content-type": "application/json"})
    assert resp.status_code == 400
    assert resp.json() == {"detail": "invalid Content-Length header"}
    assert h.audit == [] and h.upstream == []


def test_non_json_body_is_rejected_with_sanitized_detail() -> None:
    h = _Harness()
    client = TestClient(create_gateway_app(h.settings()))
    resp = client.post("/mcp/filesystem", content=b"{not json", headers={"content-type": "application/json"})
    assert resp.status_code == 400
    assert resp.json()["detail"].startswith("body is not valid JSON: ")
    assert h.audit == [] and h.upstream == []


def test_unknown_upstream_is_404_before_any_audit() -> None:
    h = _Harness()
    client = TestClient(create_gateway_app(h.settings()))
    resp = client.post("/mcp/nope", json=_call())
    assert resp.status_code == 404
    assert resp.json() == {"detail": "unknown upstream 'nope'"}
    assert h.audit == [] and h.upstream == []


# --- identity --------------------------------------------------------------


def test_managed_identity_without_blueprint_is_blocked_in_secured_drift_enforce() -> None:
    _identity, token = _managed_identity(blueprint_id="")
    h = _Harness()
    client = TestClient(create_gateway_app(h.settings(drift_enforcement_mode="enforce", **_non_loopback())))
    resp = client.post("/mcp/filesystem", json=_call(token=token), headers=_BEARER)
    assert resp.status_code == 200
    assert resp.json() == {
        "jsonrpc": "2.0",
        "id": 7,
        "error": {
            "code": -32001,
            "message": "Blocked by agent-bom gateway identity policy",
            "data": {"reason": "Identity validation failed"},
        },
    }
    assert h.upstream == []
    assert h.actions() == ["gateway.identity_blocked"]
    event = h.audit[0]
    assert event["reason"] == "Identity invalid: managed identity has no role blueprint binding"
    assert event["reason_code"] == "profile_incomplete"
    assert event["decision"] == "deny"
    assert event["policy_source"] == "identity"
    assert event["event_type"] == "gateway.tool_call.blocked"
    assert event["agent_id"] == "agent-a"


# --- A2A mutual auth -------------------------------------------------------


def test_a2a_warn_mode_audits_weak_edge_and_still_forwards() -> None:
    h = _Harness()
    client = TestClient(create_gateway_app(h.settings(a2a_mutual_auth_enforcement_mode="warn")))
    resp = client.post("/mcp/filesystem", json=_call())
    assert resp.status_code == 200
    assert resp.json() == {"jsonrpc": "2.0", "id": 7, "result": {"ok": True}}
    assert len(h.upstream) == 1
    warned = [e for e in h.audit if e["action"] == "gateway.a2a_mutual_auth_warned"]
    assert len(warned) == 1
    assert {k: warned[0][k] for k in ("upstream", "tenant_id", "source_agent", "target_agent")} == {
        "upstream": "filesystem",
        "tenant_id": "default",
        "source_agent": "agent-a",
        "target_agent": "filesystem",
    }
    assert warned[0]["weakness"]
    assert h.actions()[0] == "gateway.a2a_mutual_auth_warned"


# --- firewall --------------------------------------------------------------


def test_firewall_fail_closed_when_policy_file_unloadable(tmp_path: Path) -> None:
    bad = tmp_path / "fw.json"
    bad.write_text("{not json")
    h = _Harness()
    settings = h.settings(firewall_policy_path=bad, fail_mode="closed")
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.post("/mcp/filesystem", json=_call())
    assert resp.status_code == 403
    assert resp.json() == {"jsonrpc": "2.0", "error": {"code": -32000, "message": "gateway firewall policy unavailable"}, "id": 7}
    assert h.upstream == []
    assert h.audit == []


def test_firewall_warn_decision_audits_and_forwards(tmp_path: Path) -> None:
    policy = tmp_path / "fw.json"
    policy.write_text(
        json.dumps(
            {
                "version": 1,
                "enforcement_mode": "dry_run",
                "rules": [{"source": "agent-a", "target": "filesystem", "decision": "deny", "description": "d"}],
            }
        )
    )
    h = _Harness()
    with TestClient(create_gateway_app(h.settings(firewall_policy_path=policy))) as client:
        resp = client.post("/mcp/filesystem", json=_call())
    assert resp.status_code == 200
    assert len(h.upstream) == 1
    fw = [e for e in h.audit if e["action"].startswith("gateway.firewall")]
    assert [e["action"] for e in fw] == ["gateway.firewall_warned"]
    assert fw[0]["decision"] == "deny"
    assert fw[0]["effective_decision"] == "warn"
    assert fw[0]["enforcement_mode"] == "dry_run"
    assert fw[0]["matched_rule"] == {"source": "agent-a", "target": "filesystem", "decision": "deny", "description": "d"}


# --- spend controls fail open on store errors ------------------------------


def test_cost_center_budget_store_failure_fails_open(monkeypatch) -> None:
    import agent_bom.api.cost_store as cost_store

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("cost store down")

    monkeypatch.setattr(cost_store, "check_cost_center_budget_enforcement", _boom)
    h = _Harness()
    client = TestClient(create_gateway_app(h.settings()))
    resp = client.post("/mcp/filesystem", json=_call(), headers={"x-cost-center": "cc-1"})
    assert resp.status_code == 200
    assert resp.json()["result"] == {"ok": True}
    assert len(h.upstream) == 1
    assert "gateway.budget_exceeded" not in h.actions()


def test_owner_budget_store_failure_fails_open(monkeypatch) -> None:
    import agent_bom.api.cost_owner as cost_owner

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("owner budget down")

    monkeypatch.setattr(cost_owner, "enforce_owner_budget", _boom)
    h = _Harness()
    client = TestClient(create_gateway_app(h.settings()))
    resp = client.post("/mcp/filesystem", json=_call())
    assert resp.status_code == 200
    assert len(h.upstream) == 1
    assert "gateway.budget_exceeded" not in h.actions()


# --- identity scope / JIT / conditional access ------------------------------


def test_jit_lookup_failure_denies_out_of_scope_tool(monkeypatch) -> None:
    import agent_bom.api.agent_identity_store as identity_store

    _identity, token = _managed_identity(allowed_tools=["other_tool"])

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("jit store down")

    monkeypatch.setattr(identity_store, "active_jit_grant_for_tool", _boom)
    h = _Harness()
    client = TestClient(create_gateway_app(h.settings()))
    resp = client.post("/mcp/filesystem", json=_call(token=token))
    assert resp.status_code == 200
    assert resp.json() == _blocked(
        -32001,
        "Blocked by agent-bom gateway policy",
        {"reason": "Identity scope blocked this tool", "policy_source": "identity_scope"},
    )
    assert h.upstream == []
    blocked = [e for e in h.audit if e["action"] == "gateway.policy_blocked"]
    assert len(blocked) == 1
    assert blocked[0]["reason"] == "tool 'read_file' not in identity scope"
    assert blocked[0]["policy_source"] == "identity_scope"
    assert blocked[0]["method"] == "tools/call"
    assert blocked[0]["tool"] == "read_file"


def test_device_posture_enrichment_failure_does_not_break_decision(monkeypatch) -> None:
    import agent_bom.device_posture as device_posture

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("posture store down")

    monkeypatch.setattr(device_posture, "get_device_posture_store", _boom)
    h = _Harness()
    client = TestClient(create_gateway_app(h.settings()))
    resp = client.post("/mcp/filesystem", json=_call())
    assert resp.status_code == 200
    assert len(h.upstream) == 1


# --- graph reachability ----------------------------------------------------


def test_reachability_bundle_without_signing_key_reports_config_error_in_warn_mode() -> None:
    async def _fetch() -> dict[str, Any]:
        return {}

    h = _Harness()
    settings = h.settings(graph_reachability_enforcement_mode="warn", graph_reachability_bundle_fetcher=_fetch)
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.post("/mcp/filesystem", json=_call())
    assert resp.status_code == 200
    assert len(h.upstream) == 1
    unavailable = [e for e in h.audit if e["action"] == "gateway.graph_reachability_evidence_unavailable"]
    assert unavailable == [
        {
            "action": "gateway.graph_reachability_evidence_unavailable",
            "upstream": "filesystem",
            "tenant_id": "default",
            "source_agent": "agent-a",
            "tool": "read_file",
            "failure_mode": "allow",
            "reason_code": "missing_signing_key",
        }
    ]


def test_missing_static_reachability_evidence_denies_in_strict_mode(tmp_path: Path) -> None:
    h = _Harness()
    settings = h.settings(
        graph_reachability_enforcement_mode="enforce",
        graph_reachability_failure_mode="deny",
        graph_reachability_path=tmp_path / "missing.json",
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call())
    assert resp.json() == _blocked(
        -32001,
        "Blocked by agent-bom gateway policy",
        {
            "reason": "Graph reachability evidence unavailable and strict mode is active",
            "policy_source": "graph_reachability_evidence",
        },
    )
    assert h.upstream == []
    assert h.actions() == ["gateway.graph_reachability_evidence_unavailable", "gateway.policy_blocked"]
    assert h.audit[0]["reason_code"] == "static_evidence_unavailable"
    assert h.audit[0]["failure_mode"] == "deny"
    assert h.audit[1]["reason"] == "signed graph reachability evidence unavailable"


@pytest.mark.parametrize(("failure_mode", "forwarded"), [("allow", True), ("deny", False)])
def test_reachability_evaluator_error_honours_failure_mode(monkeypatch, tmp_path: Path, failure_mode: str, forwarded: bool) -> None:
    report = tmp_path / "facts.json"
    report.write_text(
        json.dumps(
            {
                "graph_reachability": [
                    {
                        "agent": "agent-a",
                        "tool": "other",
                        "node_id": "cred:x",
                        "rule_id": "R1",
                        "severity": "high",
                    }
                ]
            }
        )
    )

    def _boom(self: ReachabilityMap, *_a: Any, **_k: Any) -> Any:
        raise RuntimeError("evaluator down")

    monkeypatch.setattr(ReachabilityMap, "reaches_privileged", _boom)
    monkeypatch.setattr(ReachabilityMap, "__bool__", lambda self: True)
    h = _Harness()
    settings = h.settings(
        graph_reachability_enforcement_mode="enforce",
        graph_reachability_failure_mode=failure_mode,
        graph_reachability_path=report,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call())
    assert resp.status_code == 200
    if forwarded:
        assert len(h.upstream) == 1
        assert "gateway.policy_blocked" not in h.actions()
    else:
        assert h.upstream == []
        assert resp.json()["error"]["data"]["policy_source"] == "graph_reachability_evidence"
        blocked = [e for e in h.audit if e["action"] == "gateway.policy_blocked"]
        assert blocked[0]["reason"] == "graph reachability evaluation unavailable"


# --- OAuth scope mapping ---------------------------------------------------


def test_tool_scope_map_with_only_empty_scopes_does_not_gate() -> None:
    h = _Harness()
    client = TestClient(create_gateway_app(h.settings(tool_scope_map={"read_file": [""], "*": []})))
    resp = client.post("/mcp/filesystem", json=_call())
    assert resp.status_code == 200
    assert len(h.upstream) == 1
    assert "gateway.oauth_scope_blocked" not in h.actions()


def test_tool_scope_map_missing_scope_blocks_with_exact_audit() -> None:
    h = _Harness()
    client = TestClient(create_gateway_app(h.settings(tool_scope_map={"read_file": ["fs:read"], "*": ["base"]})))
    resp = client.post("/mcp/filesystem", json=_call())
    assert resp.json() == _blocked(
        -32001,
        "Blocked by agent-bom gateway policy",
        {"reason": "The caller's OAuth token is missing a required scope for this tool", "policy_source": "oauth_scope"},
    )
    assert h.upstream == []
    scope_events = [e for e in h.audit if e["action"] == "gateway.oauth_scope_blocked"]
    assert scope_events == [
        {
            "action": "gateway.oauth_scope_blocked",
            "upstream": "filesystem",
            "tenant_id": "default",
            "source_agent": "agent-a",
            "tool": "read_file",
            "required_scopes": ["base", "fs:read"],
            "missing_scopes": ["base", "fs:read"],
        }
    ]
    blocked = [e for e in h.audit if e["action"] == "gateway.policy_blocked"]
    assert blocked[0]["reason"] == "caller token missing required OAuth scope(s) for 'read_file': base, fs:read"


# --- end-to-end decision sequence -----------------------------------------


def test_allowed_call_audit_sequence_and_forward_context() -> None:
    h = _Harness()
    policy = {
        "agent_tokens": {"token-a": "agent-a"},
        "rules": [{"id": "warn-read", "action": "warn", "block_tools": ["read_file"]}],
    }
    client = TestClient(create_gateway_app(h.settings(policy=policy)))
    resp = client.post("/mcp/filesystem", json=_call())
    assert resp.status_code == 200
    assert resp.json() == {"jsonrpc": "2.0", "id": 7, "result": {"ok": True}}
    assert len(h.upstream) == 1
    actions = h.actions()
    assert actions[0] == "gateway.policy_warned"
    warned = h.audit[0]
    assert {k: warned[k] for k in ("upstream", "tenant_id", "method", "tool", "rule_id")} == {
        "upstream": "filesystem",
        "tenant_id": "default",
        "method": "tools/call",
        "tool": "read_file",
        "rule_id": "warn-read",
    }
    assert set(warned) == {"action", "upstream", "tenant_id", "method", "tool", "rule_id", "reason"}


def test_audit_sink_is_awaited_on_the_event_loop() -> None:
    h = _Harness()
    seen_loops: list[bool] = []

    async def _sink(event: dict[str, Any]) -> None:
        seen_loops.append(asyncio.get_running_loop() is not None)
        h.audit.append(event)

    client = TestClient(create_gateway_app(h.settings(audit_sink=_sink, a2a_mutual_auth_enforcement_mode="warn")))
    client.post("/mcp/filesystem", json=_call())
    assert seen_loops and all(seen_loops)
