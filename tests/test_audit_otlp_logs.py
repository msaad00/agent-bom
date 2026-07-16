"""Audit-event OTLP-log export.

The governance audit chain already ships as hash-chained records; the SIEM/OTel
layer already exports OTLP *trace spans*. These tests cover the missing half:
exporting the governance/audit log as OTLP **logs** through the pinned
OpenTelemetry logs SDK, honoring the same env-driven config style as the trace
exporter, batched and non-blocking, tenant-scoped, and never leaking secrets.
"""

from __future__ import annotations

import pytest

from agent_bom.api.governance_audit_log import (
    ACTION_IDENTITY_DORMANT_REVOKE,
    ACTION_TOKEN_ROTATION_DUE,
    make_governance_audit_record,
)

pytest.importorskip("opentelemetry.sdk._logs")

from opentelemetry._logs import SeverityNumber  # noqa: E402
from opentelemetry.sdk._logs import LoggerProvider  # noqa: E402
from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor  # noqa: E402

try:  # exporter name churned across otel-sdk releases; support both.
    from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter as _MemLogExporter
except ImportError:  # pragma: no cover - older sdk
    from opentelemetry.sdk._logs.export import InMemoryLogExporter as _MemLogExporter

from agent_bom.siem.otlp_logs import (  # noqa: E402
    AuditLogOtlpExporter,
    audit_record_log_attributes,
    configure_audit_otlp_from_env,
    export_governance_audit_record,
    set_audit_otlp_exporter,
    severity_for_action,
)


def _record(**overrides):
    kwargs = dict(
        tenant_id="tenant-a",
        actor="lifecycle-loop",
        action=ACTION_IDENTITY_DORMANT_REVOKE,
        target_type="agent_identity",
        target_id="id-123",
        reason="dormant 90d",
        before_state="active",
        after_state="revoked",
        observed_at="2026-07-16T00:00:00+00:00",
        window_key="2026-07-16T00:00:00+00:00",
    )
    kwargs.update(overrides)
    return make_governance_audit_record(**kwargs)


def _mem_exporter() -> AuditLogOtlpExporter:
    exporter = _MemLogExporter()
    provider = LoggerProvider()
    provider.add_log_record_processor(SimpleLogRecordProcessor(exporter))
    return AuditLogOtlpExporter(provider=provider), exporter


def _lr(readable):
    """Normalize across otel-sdk shapes: a finished log exposes its record
    either directly or under ``.log_record``."""
    return getattr(readable, "log_record", readable)


# ── attribute mapping ────────────────────────────────────────────────────────


def test_audit_record_maps_to_otlp_attributes():
    rec = _record()
    attrs = audit_record_log_attributes(rec)
    assert attrs["governance.tenant_id"] == "tenant-a"
    assert attrs["governance.actor"] == "lifecycle-loop"
    assert attrs["governance.action"] == ACTION_IDENTITY_DORMANT_REVOKE
    assert attrs["governance.target_type"] == "agent_identity"
    assert attrs["governance.target_id"] == "id-123"
    assert attrs["governance.before_state"] == "active"
    assert attrs["governance.after_state"] == "revoked"
    # The record hash ties the exported log back to the tamper-evident chain.
    assert attrs["governance.record_hash"] == rec.record_hash
    # Every attribute value is a scalar OTLP-safe type (str/int/float/bool).
    for value in attrs.values():
        assert isinstance(value, (str, int, float, bool))


def test_severity_escalates_for_revocation():
    revoke_num, revoke_text = severity_for_action(ACTION_IDENTITY_DORMANT_REVOKE)
    info_num, _ = severity_for_action(ACTION_TOKEN_ROTATION_DUE)
    assert revoke_num == SeverityNumber.WARN
    assert revoke_text == "WARN"
    assert info_num == SeverityNumber.INFO


# ── export round-trip ────────────────────────────────────────────────────────


def test_export_emits_well_formed_log_record():
    exporter, mem = _mem_exporter()
    rec = _record()
    n = exporter.export([rec])
    exporter.force_flush()
    assert n == 1
    logs = mem.get_finished_logs()
    assert len(logs) == 1
    lr = _lr(logs[0])
    assert lr.severity_number == SeverityNumber.WARN
    assert "identity_dormant_auto_revoke" in str(lr.body)
    attrs = dict(lr.attributes)
    assert attrs["governance.tenant_id"] == "tenant-a"
    assert attrs["governance.action"] == ACTION_IDENTITY_DORMANT_REVOKE


def test_export_is_tenant_scoped_and_preserves_each_tenant():
    exporter, mem = _mem_exporter()
    a = _record(tenant_id="tenant-a", target_id="id-a")
    b = _record(tenant_id="tenant-b", target_id="id-b")
    exporter.export([a, b])
    exporter.force_flush()
    logs = mem.get_finished_logs()
    tenants = {dict(_lr(lr).attributes)["governance.tenant_id"] for lr in logs}
    assert tenants == {"tenant-a", "tenant-b"}
    assert len(logs) == 2


def test_export_never_leaks_secret_material():
    # A record whose reason/detail carry a token-shaped string must still export
    # only the declared, secret-free governance attributes.
    exporter, mem = _mem_exporter()
    rec = _record(reason="rotate", detail={"token": "sk-super-secret-value", "note": "ok"})
    exporter.export([rec])
    exporter.force_flush()
    lr = _lr(mem.get_finished_logs()[0])
    blob = str(lr.body) + str(dict(lr.attributes))
    assert "sk-super-secret-value" not in blob


# ── env configuration ────────────────────────────────────────────────────────


def test_configure_from_env_disabled_without_endpoint(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_OTEL_LOGS_ENDPOINT", raising=False)
    assert configure_audit_otlp_from_env() is None


def test_configure_from_env_rejects_disallowed_endpoint(monkeypatch):
    # A private/loopback endpoint is rejected by the outbound URL policy unless
    # egress is explicitly opened — never silently exported.
    monkeypatch.setenv("AGENT_BOM_OTEL_LOGS_ENDPOINT", "http://169.254.169.254/v1/logs")
    monkeypatch.delenv("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", raising=False)
    with pytest.raises(RuntimeError):
        configure_audit_otlp_from_env()


def test_configure_from_env_builds_exporter(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_OTEL_LOGS_ENDPOINT", "https://example.com/v1/logs")
    monkeypatch.setenv("AGENT_BOM_OTEL_LOGS_HEADERS", "authorization=Bearer abc,x-scope=team")
    set_audit_otlp_exporter(None)  # clear any cached singleton
    exporter = configure_audit_otlp_from_env()
    assert isinstance(exporter, AuditLogOtlpExporter)
    # The batch processor exports off the caller's thread — export() returns
    # immediately without blocking on the network.
    n = exporter.export([_record()])
    assert n == 1
    exporter.shutdown()
    set_audit_otlp_exporter(None)


def test_unavailable_exporter_is_attempted_once_not_on_every_append(monkeypatch):
    # Endpoint set but the build returns None (e.g. the `otel` extra is not
    # installed). The build path is where the blocking URL/DNS validation
    # (`validate_url` → `socket.getaddrinfo`) runs under the exporter lock, so it
    # must be attempted exactly once and cached as a no-op — NOT re-run on every
    # audit-append call.
    import agent_bom.siem.otlp_logs as otlp

    monkeypatch.setenv("AGENT_BOM_OTEL_LOGS_ENDPOINT", "https://collector.example.com/v1/logs")
    monkeypatch.delenv("AGENT_BOM_OTEL_LOGS_HEADERS", raising=False)
    set_audit_otlp_exporter(None)  # clear cache + reset attempt sentinel

    calls = {"n": 0}

    def _counting_build(endpoint, headers=None):
        calls["n"] += 1
        return None  # simulate otel-unavailable no-op

    monkeypatch.setattr(otlp, "build_audit_otlp_exporter", _counting_build)
    try:
        results = [export_governance_audit_record(_record()) for _ in range(5)]
        assert results == [False] * 5  # no exporter → not enqueued
        assert calls["n"] == 1  # build/validate attempted at most once
    finally:
        set_audit_otlp_exporter(None)


def test_lifecycle_audit_append_triggers_otlp_export():
    # The single audit-append hook (_emit_audit) must fan the sealed record out
    # to the configured OTLP-log exporter — proving the wiring, not just the unit.
    from agent_bom.api.agent_identity_store import _emit_audit
    from agent_bom.api.governance_audit_log import InMemoryGovernanceAuditLog

    exporter, mem = _mem_exporter()
    # An explicitly-set exporter is honored directly (no env endpoint needed).
    set_audit_otlp_exporter(exporter)
    try:
        _emit_audit(
            {
                "tenant_id": "tenant-a",
                "actor": "cleanup",
                "action": ACTION_IDENTITY_DORMANT_REVOKE,
                "target_type": "agent_identity",
                "target_id": "id-9",
                "reason": "dormant",
                "before_state": "active",
                "after_state": "revoked",
                "observed_at": "2026-07-16T00:00:00+00:00",
                "window_key": "2026-07-16T00:00:00+00:00",
            },
            InMemoryGovernanceAuditLog(),
        )
        exporter.force_flush()
        logs = mem.get_finished_logs()
        assert len(logs) == 1
        assert dict(_lr(logs[0]).attributes)["governance.target_id"] == "id-9"
    finally:
        set_audit_otlp_exporter(None)
