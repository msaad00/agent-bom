"""Durable standalone-gateway audit delivery contracts."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

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
    assert [event_id for batch in delivered for event_id in batch] == [
        f"event-{index:04d}" for index in range(501)
    ]
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
    assert readiness.status_code == 200
    assert readiness.json()["ready"] is True
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
