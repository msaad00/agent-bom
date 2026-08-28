"""Durable standalone-gateway audit delivery contracts."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.testclient import TestClient

import agent_bom.gateway_server as gateway_server
from agent_bom.api.auth import Role
from agent_bom.gateway_server import (
    GatewayAuditDeliveryUnavailableError,
    GatewaySettings,
    _emit_gateway_governance_event,
    build_control_plane_audit_sink,
    create_gateway_app,
)
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.runtime.gateway_events import GatewayRuntimeEventType, build_gateway_runtime_event


def _event(event_id: str = "gw_delivery_1", **overrides: object) -> dict[str, Any]:
    event = build_gateway_runtime_event(
        GatewayRuntimeEventType.TOOL_CALL_BLOCKED,
        tenant_id="tenant-a",
        agent_id="agent-a",
        profile_id="profile-a",
        upstream="filesystem",
        tool="read_file",
        decision="deny",
        policy_source="runtime_profile",
        trace_id="trace-a",
        reason_code="profile_revoked",
    )
    event["event_id"] = event_id
    event["decision_id"] = event_id
    event.update(overrides)
    return event


def _paths(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "gateway-audit.spill.jsonl", tmp_path / "gateway-audit.dlq.jsonl"


def test_control_plane_audit_routes_each_authenticated_api_key_to_its_tenant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    upstream_tenants: list[str] = []
    delivered: list[tuple[str, str]] = []

    class _TenantKeyStore:
        @staticmethod
        def has_keys() -> bool:
            return True

        @staticmethod
        def verify(raw_key: str) -> SimpleNamespace | None:
            if raw_key not in {"tenant-alpha-key", "tenant-beta-key"}:
                return None
            tenant_id = raw_key.removesuffix("-key")
            return SimpleNamespace(
                tenant_id=tenant_id,
                role=Role.ANALYST,
                has_scope=lambda required: required == "gateway:relay",
            )

    async def sender(payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        events = payload["alerts"]
        delivered.extend((str(event["tenant_id"]), headers.get("Authorization", "")) for event in events)
        count = len(events)
        return {
            "accepted_alert_count": count,
            "duplicate_alert_count": 0,
            "durable_accepted_count": count,
            "durable_duplicate_count": 0,
            "durable_conflict_count": 0,
        }

    async def upstream(upstream_config: object, message: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        upstream_tenants.append(str(getattr(upstream_config, "tenant_id", "")))
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    monkeypatch.setattr(gateway_server, "get_key_store", lambda: _TenantKeyStore())
    registry = UpstreamRegistry(
        [
            UpstreamConfig(name="jira", tenant_id="tenant-alpha", url="https://alpha.invalid/mcp"),
            UpstreamConfig(name="jira", tenant_id="tenant-beta", url="https://beta.invalid/mcp"),
        ]
    )
    sink = build_control_plane_audit_sink(
        "https://control.invalid",
        "tenant-alpha-bootstrap",
        tenant_id="tenant-alpha",
        sender=sender,
    )
    app = create_gateway_app(GatewaySettings(registry=registry, policy={}, audit_sink=sink, upstream_caller=upstream))
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "query_issues", "arguments": {}},
    }

    with TestClient(app, raise_server_exceptions=False) as client:
        alpha = client.post("/mcp/jira", headers={"X-API-Key": "tenant-alpha-key"}, json=message)
        beta = client.post("/mcp/jira", headers={"X-API-Key": "tenant-beta-key"}, json=message)

    assert alpha.status_code == 200
    assert beta.status_code == 200
    assert upstream_tenants == ["tenant-alpha", "tenant-beta"]
    assert ("tenant-alpha", "Bearer tenant-alpha-key") in delivered
    assert ("tenant-beta", "Bearer tenant-beta-key") in delivered


@pytest.mark.asyncio
async def test_tenant_child_audit_degradation_rolls_up_to_gateway_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))

    async def unavailable_sender(_payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        raise RuntimeError("hostile transport detail /private/tenant-beta")

    sink = build_control_plane_audit_sink(
        "https://control.invalid",
        "tenant-alpha-token",
        tenant_id="tenant-alpha",
        sender=unavailable_sender,
    )
    await sink.start()
    await sink.bind_authenticated_tenant("tenant-beta", "tenant-beta-token")
    await sink(_event(tenant_id="tenant-beta"))
    health = sink.health()
    await sink.aclose()

    assert health["status"] == "degraded"
    assert health["accepting_events"] is False
    assert health["remote_acknowledgement_available"] is False
    assert int(health["backlog_bytes"]) > 0


@pytest.mark.asyncio
async def test_restart_discovers_unbound_tenant_backlog_and_reports_degraded_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    alpha_token = "alpha-token-must-not-persist"
    beta_token = "beta-token-must-not-persist"

    async def unavailable_sender(_payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        raise RuntimeError("control plane unavailable")

    first = build_control_plane_audit_sink(
        "https://control.invalid",
        alpha_token,
        tenant_id="tenant-alpha",
        sender=unavailable_sender,
    )
    await first.start()
    await first.bind_authenticated_tenant("tenant-beta", beta_token)
    await first(_event(tenant_id="tenant-beta"))
    assert int(first.health()["backlog_bytes"]) > 0
    await first.aclose()

    persisted = "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    assert alpha_token not in persisted
    assert beta_token not in persisted

    restarted = build_control_plane_audit_sink(
        "https://control.invalid",
        "alpha-token-rotated",
        tenant_id="tenant-alpha",
        sender=unavailable_sender,
    )
    await restarted.start()
    health = restarted.health()
    await restarted.aclose()

    assert health["status"] == "degraded"
    assert int(health["backlog_bytes"]) > 0
    assert health["accepting_events"] is False
    assert int(health["tenant_sink_count"]) == 2


@pytest.mark.asyncio
async def test_restart_discovers_unbound_tenant_dlq_only_backlog_and_reports_degraded_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))

    async def unavailable_sender(_payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        raise RuntimeError("control plane unavailable")

    first = build_control_plane_audit_sink(
        "https://control.invalid",
        "alpha-token",
        tenant_id="tenant-alpha",
        sender=unavailable_sender,
    )
    await first.start()
    await first.bind_authenticated_tenant("tenant-beta", "beta-token")
    beta = first._tenant_sinks["tenant-beta"]
    beta._delivery_state.store.max_spillover_bytes = 1
    with pytest.raises(GatewayAuditDeliveryUnavailableError, match="durable audit backlog is full"):
        await first(_event(tenant_id="tenant-beta"))
    assert int(first.health()["backlog_bytes"]) == 0
    assert int(first.health()["dlq_bytes"]) > 0
    await first.aclose()

    restarted = build_control_plane_audit_sink(
        "https://control.invalid",
        "alpha-token-rotated",
        tenant_id="tenant-alpha",
        sender=unavailable_sender,
    )
    await restarted.start()
    health = restarted.health()
    await restarted.aclose()

    assert health["status"] == "degraded"
    assert int(health["backlog_bytes"]) == 0
    assert int(health["dlq_bytes"]) > 0
    assert health["accepting_events"] is False
    assert int(health["tenant_sink_count"]) == 2


@pytest.mark.asyncio
async def test_restart_fails_closed_on_symlinked_tenant_registry_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))

    async def unavailable_sender(_payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        raise RuntimeError("control plane unavailable")

    first = build_control_plane_audit_sink(
        "https://control.invalid",
        "alpha-token",
        tenant_id="tenant-alpha",
        sender=unavailable_sender,
    )
    await first.start()
    await first.bind_authenticated_tenant("tenant-beta", "beta-token")
    await first(_event(tenant_id="tenant-beta"))
    await first.aclose()

    markers = list((tmp_path / "runtime-audit").glob("gateway-router-*.tenant.json"))
    assert len(markers) == 1
    outside = tmp_path / "outside-tenant.json"
    outside.write_text('{"tenant_id":"hostile"}', encoding="utf-8")
    markers[0].unlink()
    markers[0].symlink_to(outside)

    restarted = build_control_plane_audit_sink(
        "https://control.invalid",
        "alpha-token-rotated",
        tenant_id="tenant-alpha",
        sender=unavailable_sender,
    )
    await restarted.start()
    health = restarted.health()
    await restarted.aclose()

    assert health["status"] == "degraded"
    assert health["accepting_events"] is False
    assert health["backlog_observable"] is False


@pytest.mark.asyncio
async def test_control_plane_audit_tenant_routing_is_bounded_and_requires_verified_request_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    sink = build_control_plane_audit_sink(
        "https://control.invalid",
        "tenant-alpha-token",
        tenant_id="tenant-alpha",
        max_tenant_sinks=1,
    )

    with pytest.raises(GatewayAuditDeliveryUnavailableError, match="tenant-bound"):
        await sink.bind_authenticated_tenant("tenant-beta", None)
    await sink.bind_authenticated_tenant("tenant-beta", "tenant-beta-token")
    with pytest.raises(GatewayAuditDeliveryUnavailableError, match="capacity"):
        await sink.bind_authenticated_tenant("tenant-gamma", "tenant-gamma-token")
    await sink.aclose()


@pytest.mark.parametrize(
    "policy",
    [
        {"rules": [{"id": "no-shell", "action": "block", "block_tools": ["run_shell"]}]},
        {"require_agent_identity": True},
    ],
    ids=["policy-deny", "identity-deny"],
)
def test_pre_upstream_audit_outage_returns_deterministic_jsonrpc_denial(
    policy: dict[str, Any],
) -> None:
    upstream_calls = 0

    async def upstream(_upstream: object, message: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        nonlocal upstream_calls
        upstream_calls += 1
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"side_effect": True}}

    async def unavailable_audit(_event: dict[str, Any]) -> None:
        raise GatewayAuditDeliveryUnavailableError("hostile internal path /private/audit.db")

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://filesystem.invalid")]),
        policy=policy,
        audit_sink=unavailable_audit,
        upstream_caller=upstream,
    )
    with TestClient(create_gateway_app(settings), raise_server_exceptions=False) as client:
        response = client.post(
            "/mcp/filesystem",
            json={
                "jsonrpc": "2.0",
                "id": 71,
                "method": "tools/call",
                "params": {"name": "run_shell", "arguments": {}},
            },
        )

    assert response.status_code == 503
    assert response.json() == {
        "jsonrpc": "2.0",
        "id": 71,
        "error": {
            "code": -32003,
            "message": "Gateway audit persistence unavailable",
            "data": {
                "reason": "Tool call was not executed because durable audit admission failed",
                "policy_source": "audit_delivery",
            },
        },
    }
    assert upstream_calls == 0
    assert "/private/audit.db" not in response.text


@pytest.mark.asyncio
async def test_gateway_audit_assigns_distinct_stable_ids_to_identical_event_occurrences(tmp_path: Path) -> None:
    delivered: list[dict[str, Any]] = []

    async def sender(payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        delivered.append(payload)
        count = len(payload["alerts"])
        return {
            "accepted_alert_count": count,
            "duplicate_alert_count": 0,
            "durable_accepted_count": 0,
            "durable_duplicate_count": 0,
            "durable_conflict_count": 0,
        }

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        None,
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        sender=sender,
    )
    occurrence = {"action": "gateway.upstream_error", "tenant_id": "tenant-a", "upstream": "filesystem"}

    await sink(dict(occurrence))
    await sink(dict(occurrence))

    first, second = delivered
    assert first["alerts"][0]["event_id"] != second["alerts"][0]["event_id"]
    assert first["alerts"][0]["decision_id"] == first["alerts"][0]["event_id"]
    assert second["alerts"][0]["decision_id"] == second["alerts"][0]["event_id"]
    assert first["idempotency_key"] != second["idempotency_key"]


@pytest.mark.asyncio
async def test_gateway_audit_eventless_occurrence_keeps_identity_across_retry(tmp_path: Path) -> None:
    attempts: list[dict[str, Any]] = []

    async def sender(payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        attempts.append(payload)
        if len(attempts) == 1:
            raise RuntimeError("control plane unavailable")
        return {
            "accepted_alert_count": 1,
            "duplicate_alert_count": 0,
            "durable_accepted_count": 0,
            "durable_duplicate_count": 0,
            "durable_conflict_count": 0,
        }

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        None,
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        sender=sender,
    )

    await sink({"action": "gateway.upstream_error", "tenant_id": "tenant-a", "upstream": "filesystem"})
    assert await sink.flush_once() is True

    assert attempts[0]["alerts"][0]["event_id"] == attempts[1]["alerts"][0]["event_id"]
    assert attempts[0]["idempotency_key"] == attempts[1]["idempotency_key"]


@pytest.mark.asyncio
async def test_gateway_audit_delivers_at_most_500_events_in_order(tmp_path: Path) -> None:
    delivered: list[list[str]] = []

    async def sender(payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        ids = [str(event["event_id"]) for event in payload["alerts"]]
        delivered.append(ids)
        assert len(ids) <= 500
        return {
            "accepted_alert_count": len(ids),
            "duplicate_alert_count": 0,
            "durable_accepted_count": len(ids),
            "durable_duplicate_count": 0,
            "durable_conflict_count": 0,
        }

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        "token",
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        max_spillover_bytes=2_000_000,
        sender=sender,
    )
    events = [_event(f"event-{index:04d}") for index in range(501)]
    sink._delivery_state.store.append_events(events)

    assert await sink.flush_once() is True
    assert [len(batch) for batch in delivered] == [500, 1]
    assert [event_id for batch in delivered for event_id in batch] == [f"event-{index:04d}" for index in range(501)]
    assert sink._delivery_state.store.read_spillover() == []


@pytest.mark.asyncio
async def test_gateway_audit_partial_chunk_ack_restores_only_unsent_tail(tmp_path: Path) -> None:
    attempts = 0

    async def sender(payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            raise RuntimeError("control plane unavailable")
        count = len(payload["alerts"])
        return {
            "accepted_alert_count": count,
            "duplicate_alert_count": 0,
            "durable_accepted_count": count,
            "durable_duplicate_count": 0,
            "durable_conflict_count": 0,
        }

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        "token",
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        max_spillover_bytes=3_000_000,
        sender=sender,
    )
    sink._delivery_state.store.append_events([_event(f"event-{index:04d}") for index in range(750)])

    assert await sink.flush_once() is False
    assert [event["event_id"] for event in sink._delivery_state.store.read_spillover()] == [
        f"event-{index:04d}" for index in range(500, 750)
    ]


@pytest.mark.asyncio
async def test_gateway_audit_rejects_cross_tenant_rebinding(tmp_path: Path) -> None:
    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        "tenant-a-token",
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
    )

    with pytest.raises(GatewayAuditDeliveryUnavailableError, match="tenant"):
        await sink(_event(tenant_id="tenant-b"))
    assert not spill.exists()


@pytest.mark.asyncio
async def test_gateway_audit_dlq_poison_keeps_later_events_fail_closed(tmp_path: Path) -> None:
    sent: list[dict[str, Any]] = []

    async def sender(payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        sent.extend(payload["alerts"])
        return {}

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        None,
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        max_spillover_bytes=200,
        max_dlq_bytes=2_000,
        sender=sender,
    )
    with pytest.raises(GatewayAuditDeliveryUnavailableError):
        await sink(_event("oversized", reason_code="x" * 500))
    with pytest.raises(GatewayAuditDeliveryUnavailableError):
        await sink(_event("small"))
    assert sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("action", "expected_type", "decision"),
    [
        ("gateway.a2a_mutual_auth_blocked", "gateway.enforcement.blocked", "deny"),
        ("gateway.firewall_blocked", "gateway.tool_call.blocked", "deny"),
        ("gateway.rate_limited", "gateway.enforcement.blocked", "deny"),
        ("gateway.budget_exceeded", "gateway.enforcement.blocked", "deny"),
        ("gateway.anomaly_blocked", "gateway.enforcement.blocked", "deny"),
        ("gateway.fleet_blocked", "gateway.enforcement.blocked", "deny"),
        ("gateway.conditional_access_blocked", "gateway.enforcement.blocked", "deny"),
        ("gateway.graph_reachability_blocked", "gateway.enforcement.blocked", "deny"),
        ("gateway.oauth_scope_blocked", "gateway.enforcement.blocked", "deny"),
        ("gateway.policy_quarantined", "gateway.enforcement.blocked", "deny"),
        ("gateway.anomaly_warned", "gateway.enforcement.warned", "allow"),
        ("gateway.fleet_warned", "gateway.enforcement.warned", "allow"),
        ("gateway.drift_warned", "gateway.enforcement.warned", "allow"),
        ("gateway.graph_reachability_warned", "gateway.enforcement.warned", "allow"),
        ("gateway.policy_warned", "gateway.enforcement.warned", "allow"),
        ("gateway.firewall_warned", "gateway.enforcement.warned", "allow"),
        ("gateway.identity_jit_grant_used", "gateway.enforcement.observed", "allow"),
    ],
)
async def test_gateway_audit_canonicalizes_enforcement_decisions_before_delivery(
    tmp_path: Path,
    action: str,
    expected_type: str,
    decision: str,
) -> None:
    delivered: list[dict[str, Any]] = []

    async def sender(payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        delivered.extend(payload["alerts"])
        return {
            "accepted_alert_count": 1,
            "duplicate_alert_count": 0,
            "durable_accepted_count": 1,
            "durable_duplicate_count": 0,
            "durable_conflict_count": 0,
        }

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        "token",
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        sender=sender,
    )

    await sink(
        {
            "action": action,
            "tenant_id": "tenant-a",
            "source_agent": "agent-a",
            "upstream": "filesystem",
            "tool": "read_file",
            "authorization": "must-not-survive",
        }
    )

    assert delivered[0]["event_type"] == expected_type
    assert delivered[0]["decision"] == decision
    assert "authorization" not in delivered[0]


@pytest.mark.asyncio
async def test_gateway_audit_canonicalizes_actual_firewall_decision_and_preserves_provenance(tmp_path: Path) -> None:
    delivered: list[dict[str, Any]] = []

    async def sender(payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        delivered.extend(payload["alerts"])
        return {
            "accepted_alert_count": 1,
            "duplicate_alert_count": 0,
            "durable_accepted_count": 1,
            "durable_duplicate_count": 0,
            "durable_conflict_count": 0,
        }

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        "token",
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        sender=sender,
    )
    await sink(
        {
            "action": "gateway.firewall_decision",
            "tenant_id": "tenant-a",
            "source_agent": "agent-a",
            "target_agent": "filesystem",
            "decision": "deny",
            "effective_decision": "deny",
            "identity_id": "identity-a",
            "profile_id": "profile-a",
            "profile_revision": 4,
            "blueprint_id": "blueprint-a",
            "blueprint_revision": 7,
            "policy_ids": ["policy-a", "policy-b"],
            "policy_id": "policy-a",
            "evidence_id": "evidence-a",
        }
    )

    event = delivered[0]
    assert event["event_type"] == "gateway.enforcement.blocked"
    assert event["decision"] == "deny"
    assert event["identity_id"] == "identity-a"
    assert event["profile_revision"] == 4
    assert event["blueprint_id"] == "blueprint-a"
    assert event["blueprint_revision"] == 7
    assert event["policy_ids"] == ["policy-a", "policy-b"]
    assert event["policy_id"] == "policy-a"
    assert event["evidence_id"] == "evidence-a"


@pytest.mark.asyncio
async def test_gateway_audit_retries_the_same_durable_event_after_503(tmp_path: Path) -> None:
    attempts: list[list[str]] = []

    async def sender(payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        event_ids = [str(event["event_id"]) for event in payload["alerts"]]
        attempts.append(event_ids)
        if len(attempts) == 1:
            raise RuntimeError("503 control plane temporarily unavailable")
        return {
            "accepted_alert_count": len(event_ids),
            "duplicate_alert_count": 0,
            "durable_accepted_count": len(event_ids),
            "durable_duplicate_count": 0,
            "durable_conflict_count": 0,
        }

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        "token",
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        sender=sender,
    )

    await sink(_event())
    assert spill.exists()
    assert sink.health()["status"] == "degraded"

    assert await sink.flush_once() is True
    assert attempts == [["gw_delivery_1"], ["gw_delivery_1"]]
    assert not spill.exists()
    assert sink.health()["status"] == "healthy"


def test_tool_call_requires_remote_durable_ack_before_upstream_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upstream_calls = 0

    async def sender(_payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        raise RuntimeError("control plane unavailable")

    async def upstream_caller(_upstream: object, message: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        nonlocal upstream_calls
        upstream_calls += 1
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"side_effect": True}}

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        None,
        tenant_id="default",
        spill_path=spill,
        dlq_path=dlq,
        sender=sender,
    )
    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://filesystem.local")]),
        policy={},
        audit_sink=sink,
        upstream_caller=upstream_caller,
    )

    with TestClient(create_gateway_app(settings), raise_server_exceptions=False) as client:
        response = client.post(
            "/mcp/filesystem",
            json={
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {"name": "write_file", "arguments": {"path": "/tmp/output"}},
            },
        )

    assert response.status_code == 503
    assert upstream_calls == 0
    assert sink.health()["backlog_bytes"] > 0, response.text


def test_post_forward_result_audit_capacity_failure_returns_completed_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agent_bom.gateway_server as gateway_module

    upstream_calls = 0

    async def sender(payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        count = len(payload["alerts"])
        return {
            "accepted_alert_count": count,
            "duplicate_alert_count": 0,
            "durable_accepted_count": count,
            "durable_duplicate_count": 0,
            "durable_conflict_count": 0,
        }

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        None,
        tenant_id="default",
        spill_path=spill,
        dlq_path=dlq,
        max_spillover_bytes=10_000,
        max_dlq_bytes=1,
        sender=sender,
    )

    async def upstream_caller(_upstream: object, message: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        nonlocal upstream_calls
        upstream_calls += 1
        # Reproduce a concurrent capacity loss after pre-execution admission.
        sink._delivery_state.store.max_spillover_bytes = sink._delivery_state.store.spillover_size_bytes() + 1
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"email": "person@example.com"}}

    monkeypatch.setattr(
        gateway_module,
        "scan_tool_response",
        lambda *_args, **_kwargs: [SimpleNamespace(blocked=False, scanner="pii", rule_id="email")],
    )
    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://filesystem.local")]),
        policy={},
        audit_sink=sink,
        upstream_caller=upstream_caller,
        dlp_enabled=True,
        dlp_mode="audit",
    )

    with TestClient(create_gateway_app(settings), raise_server_exceptions=False) as client:
        response = client.post(
            "/mcp/filesystem",
            json={
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {"name": "write_file", "arguments": {}},
            },
        )

    assert response.status_code == 200
    assert response.json()["result"] == {"email": "person@example.com"}
    assert response.headers["x-agent-bom-audit-delivery"] == "degraded"
    assert upstream_calls == 1
    assert sink.health()["accepting_events"] is False


@pytest.mark.asyncio
async def test_gateway_audit_restart_loads_and_delivers_sanitized_backlog(tmp_path: Path) -> None:
    spill, dlq = _paths(tmp_path)
    secret = "sk-" + "gateway-restart-secret-value-1234567890"

    async def unavailable(_payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        raise RuntimeError(f"503 token={secret} path=/private/runtime/audit")

    first = build_control_plane_audit_sink(
        "https://control.example.test",
        secret,
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        sender=unavailable,
    )
    await first(_event(api_token=secret, headers={"authorization": f"Bearer {secret}"}))
    persisted = spill.read_text(encoding="utf-8")
    assert secret not in persisted
    await first.aclose()

    delivered: list[dict[str, Any]] = []

    async def recovered(payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        delivered.extend(payload["alerts"])
        return {
            "accepted_alert_count": len(payload["alerts"]),
            "duplicate_alert_count": 0,
            "durable_accepted_count": len(payload["alerts"]),
            "durable_duplicate_count": 0,
            "durable_conflict_count": 0,
        }

    restarted = build_control_plane_audit_sink(
        "https://control.example.test",
        secret,
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        sender=recovered,
    )
    await restarted.start()
    await restarted.aclose()

    assert [event["event_id"] for event in delivered] == ["gw_delivery_1"]
    assert secret not in json.dumps(delivered)
    assert not spill.exists()


@pytest.mark.asyncio
async def test_gateway_audit_cancellation_restores_the_claimed_batch(tmp_path: Path) -> None:
    entered = asyncio.Event()

    async def pending(_payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        entered.set()
        await asyncio.Future()
        raise AssertionError("unreachable")

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        None,
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        sender=pending,
    )
    sink._delivery_state.store.append_events([_event("gw_cancelled")])

    delivery = asyncio.create_task(sink.flush_once())
    await entered.wait()
    delivery.cancel()
    with pytest.raises(asyncio.CancelledError):
        await delivery

    recovered = sink._delivery_state.store.read_spillover()
    assert [event["event_id"] for event in recovered] == ["gw_cancelled"]


@pytest.mark.asyncio
async def test_gateway_audit_fails_closed_when_bounded_persistence_is_full(tmp_path: Path) -> None:
    async def sender(_payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        raise AssertionError("a non-durable event must never reach the transport")

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        None,
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        max_spillover_bytes=1,
        max_dlq_bytes=1,
        sender=sender,
    )

    with pytest.raises(GatewayAuditDeliveryUnavailableError, match="durable audit backlog is full"):
        await sink(_event())

    health = sink.health()
    assert health["status"] == "degraded"
    assert health["accepting_events"] is False
    assert health["dropped_events"] == 1


def test_relay_does_not_execute_tool_when_audit_persistence_is_already_full(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An allowed tool must be durably audited before its upstream side effect."""

    monkeypatch.setenv("AGENT_BOM_TENANT_ID", "tenant-a")
    upstream_calls = 0

    async def upstream_caller(_upstream: object, message: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        nonlocal upstream_calls
        upstream_calls += 1
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    async def sender(_payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        raise AssertionError("a poisoned backlog must not reach the transport")

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        None,
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        max_spillover_bytes=1,
        max_dlq_bytes=2_000,
        sender=sender,
    )
    assert sink._delivery_state.store.append_events([_event("poison")]) == "dlq"
    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://filesystem.local")]),
        policy={},
        audit_sink=sink,
        upstream_caller=upstream_caller,
    )
    message = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {}},
    }

    with TestClient(create_gateway_app(settings), raise_server_exceptions=False) as client:
        response = client.post("/mcp/filesystem", json=message)

    assert response.status_code == 503
    assert upstream_calls == 0


def test_relay_builds_local_durable_audit_when_remote_sink_is_not_configured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_TENANT_ID", "tenant-a")
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    upstream_calls = 0

    class _TenantKeyStore:
        def has_keys(self) -> bool:
            return True

        def verify(self, raw_key: str) -> SimpleNamespace | None:
            if raw_key != "tenant-a-key":
                return None
            return SimpleNamespace(
                tenant_id="tenant-a",
                role=Role.ANALYST,
                scopes=["gateway:relay"],
                has_scope=lambda required: required == "gateway:relay",
            )

    monkeypatch.setattr("agent_bom.gateway_server.get_key_store", lambda: _TenantKeyStore())

    async def upstream_caller(_upstream: object, message: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        nonlocal upstream_calls
        upstream_calls += 1
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"side_effect": True}}

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://filesystem.local")]),
        policy={},
        audit_sink=None,
        upstream_caller=upstream_caller,
    )
    message = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "/tmp/output"}},
    }

    with TestClient(create_gateway_app(settings), raise_server_exceptions=False) as client:
        response = client.post("/mcp/filesystem", headers={"X-API-Key": "tenant-a-key"}, json=message)

    assert response.status_code == 200
    assert upstream_calls == 1
    db_path = tmp_path / "runtime-audit" / "gateway-local-audit.db"
    assert db_path.is_file()
    assert settings.audit_sink is not None
    from agent_bom.api.audit_log import SQLiteAuditLog

    entries = SQLiteAuditLog(str(db_path)).list_entries(tenant_id="tenant-a", limit=10)
    assert len(entries) == 1
    assert entries[0].action == "gateway.tool_call"
    assert entries[0].details["decision"] == "allow"
    assert entries[0].details["tool"] == "write_file"


def test_local_audit_key_survives_subprocess_restart_and_concurrent_open(tmp_path: Path) -> None:
    db_path = tmp_path / "runtime-audit" / "gateway-local-audit.db"
    script = """
import asyncio
import json
import sys
from pathlib import Path
from agent_bom.api.audit_log import SQLiteAuditLog
from agent_bom.gateway_server import LocalGatewayAuditSink

db_path = Path(sys.argv[1])
mode = sys.argv[2]
if mode == "append":
    asyncio.run(LocalGatewayAuditSink(db_path)({
        "action": "gateway.tool_call",
        "tenant_id": "tenant-a",
        "upstream": "filesystem",
        "event_id": sys.argv[3],
    }))
else:
    store = SQLiteAuditLog(str(db_path), hmac_key=LocalGatewayAuditSink.load_key(db_path))
    print(json.dumps({
        "count": store.count(tenant_id="tenant-a"),
        "integrity": store.verify_integrity(tenant_id="tenant-a"),
    }))
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    for name in (
        "AGENT_BOM_AUDIT_HMAC_KEY",
        "AGENT_BOM_AUDIT_HMAC_KEY_FILE",
        "AGENT_BOM_REQUIRE_AUDIT_HMAC",
        "AGENT_BOM_ENV",
        "AGENT_BOM_DEPLOYMENT_ENV",
        "ENVIRONMENT",
    ):
        env.pop(name, None)

    first = subprocess.run(
        [sys.executable, "-c", script, str(db_path), "append", "event-1"],
        cwd=Path(__file__).parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert first.returncode == 0, first.stderr
    writers = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(db_path), "append", event_id],
            cwd=Path(__file__).parents[1],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for event_id in ("event-2", "event-3")
    ]
    for writer in writers:
        _stdout, stderr = writer.communicate(timeout=30)
        assert writer.returncode == 0, stderr

    verified = subprocess.run(
        [sys.executable, "-c", script, str(db_path), "verify", "unused"],
        cwd=Path(__file__).parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    payload = json.loads(verified.stdout.strip().splitlines()[-1])
    assert payload == {"count": 3, "integrity": [3, 0]}
    key_path = db_path.with_suffix(".hmac.key")
    assert key_path.is_file()
    assert key_path.stat().st_mode & 0o777 == 0o600


def test_existing_local_audit_db_fails_closed_if_key_is_missing(tmp_path: Path) -> None:
    from agent_bom.gateway_server import LocalGatewayAuditSink

    db_path = tmp_path / "runtime-audit" / "gateway-local-audit.db"
    sink = LocalGatewayAuditSink(db_path)
    key_path = db_path.with_suffix(".hmac.key")
    assert key_path.is_file()
    key_path.unlink()

    with pytest.raises(ValueError, match="key is missing"):
        LocalGatewayAuditSink(db_path)

    assert sink.health()["durable"] is True


def test_local_audit_initialization_failure_degrades_health_and_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", "/proc/agent-bom-audit-unwritable")
    upstream_calls = 0

    async def upstream_caller(_upstream: object, message: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        nonlocal upstream_calls
        upstream_calls += 1
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"side_effect": True}}

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://filesystem.local")]),
        policy={},
        audit_sink=None,
        upstream_caller=upstream_caller,
    )
    with TestClient(create_gateway_app(settings), raise_server_exceptions=False) as client:
        health = client.get("/healthz")
        readiness = client.get("/readyz")
        tool_call = client.post(
            "/mcp/filesystem",
            json={
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {"name": "write_file", "arguments": {}},
            },
        )

    assert health.status_code == 200
    assert health.json()["status"] == "degraded"
    assert health.json()["audit_delivery"]["durable"] is False
    assert readiness.status_code == 503
    assert readiness.json()["ready"] is False
    assert tool_call.status_code == 503
    assert upstream_calls == 0


def test_relay_does_not_execute_tool_if_durable_audit_sink_becomes_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_TENANT_ID", "tenant-a")
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    upstream_calls = 0

    async def upstream_caller(_upstream: object, message: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        nonlocal upstream_calls
        upstream_calls += 1
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"side_effect": True}}

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://filesystem.local")]),
        policy={},
        audit_sink=None,
        upstream_caller=upstream_caller,
    )
    app = create_gateway_app(settings)
    settings.audit_sink = None
    message = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "/tmp/output"}},
    }

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/mcp/filesystem", json=message)

    assert response.status_code == 503
    assert upstream_calls == 0


@pytest.mark.asyncio
async def test_malformed_backlog_is_retained_and_blocks_new_audit_admission(tmp_path: Path) -> None:
    sent: list[dict[str, Any]] = []

    async def sender(payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        sent.extend(payload["alerts"])
        return {}

    spill, dlq = _paths(tmp_path)
    spill.parent.mkdir(parents=True, exist_ok=True)
    spill.write_text("{not-json}\n", encoding="utf-8")
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        None,
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        sender=sender,
    )

    assert await sink.flush_once() is False
    assert sent == []
    assert any(spill.parent.glob(f"{spill.name}.claim-*"))
    assert sink.health()["accepting_events"] is False
    with pytest.raises(GatewayAuditDeliveryUnavailableError, match="unavailable"):
        await sink(_event("after-corruption"))


@pytest.mark.asyncio
async def test_gateway_health_truthfully_reports_delivery_degradation_without_secrets(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "gateway-health-secret-value-1234567890"

    async def sender(_payload: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        raise RuntimeError(f"503 token={secret} path=/private/gateway/audit")

    spill, dlq = _paths(tmp_path)
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        secret,
        tenant_id="tenant-a",
        spill_path=spill,
        dlq_path=dlq,
        sender=sender,
    )
    await sink(_event())

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://filesystem.local")]),
        policy={},
        audit_sink=sink,
    )
    with TestClient(create_gateway_app(settings)) as client:
        response = client.get("/healthz")
        readiness = client.get("/readyz")

    assert response.status_code == 200
    assert readiness.status_code == 503
    assert readiness.json()["ready"] is False
    payload = response.json()
    assert payload["status"] == "degraded"
    assert payload["audit_delivery"]["status"] == "degraded"
    assert payload["audit_delivery"]["backlog_bytes"] > 0
    assert secret not in response.text
    assert "/private/gateway/audit" not in response.text
    assert secret not in caplog.text
    assert "/private/gateway/audit" not in caplog.text


def test_gateway_health_marks_inaccessible_persistence_non_durable() -> None:
    sink = build_control_plane_audit_sink(
        "https://control.example.test",
        None,
        tenant_id="tenant-a",
        spill_path=Path("/proc/agent-bom-audit.spill.jsonl"),
        dlq_path=Path("/proc/agent-bom-audit.dlq.jsonl"),
    )

    health = sink.health()
    assert health["durable"] is False
    assert health["accepting_events"] is False

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://filesystem.local")]),
        policy={},
        audit_sink=sink,
    )
    with TestClient(create_gateway_app(settings)) as client:
        readiness = client.get("/readyz")
    assert readiness.status_code == 503
    assert readiness.json()["ready"] is False


def test_gateway_default_delivery_paths_are_restart_stable_and_secret_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    secret = "gateway-token-must-not-enter-path"

    first = build_control_plane_audit_sink(
        "https://control.example.test",
        secret,
        tenant_id="tenant-a",
        source_id="gateway-a",
    )
    second = build_control_plane_audit_sink(
        "https://control.example.test",
        "rotated-token",
        tenant_id="tenant-a",
        source_id="gateway-a",
    )

    first_store = first._delivery_state.store
    second_store = second._delivery_state.store
    assert first_store.spill_path == second_store.spill_path
    assert first_store.dlq_path == second_store.dlq_path
    assert first._session_id == second._session_id
    assert first_store.spill_path.parent == tmp_path / "runtime-audit"
    assert secret not in str(first_store.spill_path)


def test_gateway_governance_emit_does_not_log_hostile_exception_content(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from agent_bom.api import webhook_store

    opaque = "postgresql://audit:secret@db.internal/runtime"

    def fail_emit(**_kwargs: object) -> None:
        raise RuntimeError(f"{opaque} /private/tenant/audit.json")

    monkeypatch.setattr(webhook_store, "emit_governance_event", fail_emit)
    with caplog.at_level(logging.DEBUG):
        _emit_gateway_governance_event(
            "gateway.test",
            tenant_id="tenant-a",
            subject_id="agent-a",
            payload={"safe": True},
        )

    assert opaque not in caplog.text
    assert "/private/tenant/audit.json" not in caplog.text
