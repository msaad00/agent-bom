"""Audit-event OTLP **log** export.

The platform already ships OTLP *trace spans* (``api/tracing.py``,
``output/prometheus.py``) and a full SIEM/OCSF forwarder set (``siem/__init__``,
``delivery.py``). The one OTLP surface missing was **logs**: exporting the
tamper-evident governance/audit chain (``api/governance_audit_log.py``) as OTLP
``LogRecord``s so a SIEM/observability collector receives every NHI
lifecycle-enforcement action (JIT-grant expiry, dormant-identity revoke, token
rotation-due) as a first-class log stream — not only as trace spans.

Design (mirrors the existing OTLP *trace* exporter):

* **Same env-driven config style** as ``AGENT_BOM_OTEL_TRACES_*`` — an operator
  sets ``AGENT_BOM_OTEL_LOGS_ENDPOINT`` (OTLP/HTTP logs endpoint, e.g. a
  collector's ``/v1/logs``) and optional ``AGENT_BOM_OTEL_LOGS_HEADERS``
  (comma-separated ``key=value`` collector-auth pairs). Unset ⇒ disabled no-op.
* **Batched + non-blocking.** A ``BatchLogRecordProcessor`` enqueues records and
  flushes on a background thread, so ``export`` never blocks the caller's
  (request / cleanup-loop) path — the same read-path offload discipline the rest
  of the codebase follows.
* **Secret-free.** Only the governance record's declared, redacted fields are
  mapped to attributes (the chain itself never holds secret material); the
  free-form ``detail`` dict is deliberately *not* forwarded so an accidental
  secret in a caller-supplied detail can never leave the process.
* **Tenant-scoped.** Every log record carries ``governance.tenant_id`` and the
  record's chain ``record_hash``, so a downstream consumer can attribute and
  verify each event per tenant.

OpenTelemetry is an optional dependency (the ``otel`` extra); every entry point
degrades to a graceful no-op when it is not installed.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from agent_bom.api.governance_audit_log import GovernanceAuditRecord

logger = logging.getLogger(__name__)

# Env config — mirrors the AGENT_BOM_OTEL_TRACES_* convention used for spans.
ENDPOINT_ENV = "AGENT_BOM_OTEL_LOGS_ENDPOINT"
HEADERS_ENV = "AGENT_BOM_OTEL_LOGS_HEADERS"

# Actions that represent a security-relevant revocation/enforcement escalate to
# WARN; routine "due" notices stay INFO. Kept explicit so the mapping is auditable.
_WARN_ACTIONS = frozenset(
    {
        "identity_dormant_auto_revoke",
        "jit_grant_expired",
        "jit_grant_denied_pruned",
    }
)


def severity_for_action(action: str) -> tuple[Any, str]:
    """Map a governance action to an OTLP ``(SeverityNumber, severity_text)``.

    Import of the OTel severity enum is deferred so the mapping table itself
    stays importable without the optional dependency.
    """
    from opentelemetry._logs import SeverityNumber

    if action in _WARN_ACTIONS:
        return SeverityNumber.WARN, "WARN"
    return SeverityNumber.INFO, "INFO"


def audit_record_log_attributes(record: "GovernanceAuditRecord") -> dict[str, Any]:
    """Return the OTLP-safe, secret-free attribute map for one audit record.

    Only the record's declared governance fields are exported. The free-form
    ``detail`` dict is intentionally omitted so a caller-supplied secret can
    never ride out on the log stream.
    """
    return {
        "governance.tenant_id": record.tenant_id,
        "governance.actor": record.actor,
        "governance.action": record.action,
        "governance.target_type": record.target_type,
        "governance.target_id": record.target_id,
        "governance.before_state": record.before_state,
        "governance.after_state": record.after_state,
        "governance.reason": record.reason,
        "governance.observed_at": record.observed_at,
        "governance.action_id": record.action_id,
        "governance.record_hash": record.record_hash,
    }


def _audit_record_body(record: "GovernanceAuditRecord") -> str:
    """A concise human-readable log body (no secrets)."""
    return f"governance {record.action} {record.target_type}:{record.target_id} {record.before_state}->{record.after_state}"


def _iso_to_unix_nanos(observed_at: str) -> int | None:
    from datetime import datetime

    try:
        dt = datetime.fromisoformat(observed_at)
    except (ValueError, TypeError):
        return None
    return int(dt.timestamp() * 1_000_000_000)


class AuditLogOtlpExporter:
    """Export governance audit records as OTLP logs via an injected provider.

    ``provider`` is an OpenTelemetry ``LoggerProvider``. In production it wraps a
    ``BatchLogRecordProcessor`` + OTLP HTTP exporter (see
    :func:`configure_audit_otlp_from_env`); tests inject a provider backed by an
    in-memory exporter. ``export`` only *enqueues* records with the provider —
    the batch processor performs the network flush on its own thread — so it is
    safe to call from a request or the cleanup loop without blocking.
    """

    def __init__(self, provider: Any) -> None:
        self._provider = provider
        self._logger = provider.get_logger("agent_bom.governance_audit")

    def export(self, records: "list[GovernanceAuditRecord]") -> int:
        """Emit each record as an OTLP LogRecord. Returns the count emitted.

        Never raises for a delivery problem — an emit failure is logged and the
        remaining records still attempt to export.
        """
        emitted = 0
        for record in records:
            try:
                severity_number, severity_text = severity_for_action(record.action)
                ts = _iso_to_unix_nanos(record.observed_at)
                self._logger.emit(
                    timestamp=ts,
                    observed_timestamp=ts,
                    severity_number=severity_number,
                    severity_text=severity_text,
                    body=_audit_record_body(record),
                    attributes=audit_record_log_attributes(record),
                    event_name="governance.audit",
                )
                emitted += 1
            except Exception:  # noqa: BLE001 - export must never abort the caller
                logger.warning("audit OTLP log emit failed for action=%s", record.action, exc_info=True)
        return emitted

    def force_flush(self, timeout_millis: int = 5000) -> bool:
        try:
            return bool(self._provider.force_flush(timeout_millis))
        except Exception:  # noqa: BLE001
            return False

    def shutdown(self) -> None:
        try:
            self._provider.shutdown()
        except Exception:  # noqa: BLE001
            pass


def _parse_headers(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for pair in raw.split(","):
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        if key.strip():
            headers[key.strip()] = value.strip()
    return headers


def build_audit_otlp_exporter(endpoint: str, headers: dict[str, str] | None = None) -> AuditLogOtlpExporter | None:
    """Build a batched OTLP-log exporter for ``endpoint``.

    Returns ``None`` when the OpenTelemetry logs packages are unavailable (the
    ``otel`` extra is not installed) — a graceful no-op, matching the trace path.

    Raises ``RuntimeError`` only when ``endpoint`` is rejected by the outbound
    URL policy (an actionable misconfiguration, not a transient failure).
    """
    from agent_bom import __version__
    from agent_bom.security import SecurityError, validate_url

    allow_private = os.environ.get("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", "").strip().lower() in {"1", "true", "yes", "on"}
    try:
        validate_url(endpoint, allowed_schemes=("https", "http") if allow_private else ("https",), allow_private=allow_private)
    except SecurityError as exc:
        raise RuntimeError(f"OTLP logs endpoint rejected by outbound URL policy: {exc}") from exc

    try:
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
        from opentelemetry.sdk._logs import LoggerProvider
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
        from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
    except ImportError:
        logger.warning(
            "%s is set but OpenTelemetry log packages are unavailable. Install with: pip install 'agent-bom[otel]'",
            ENDPOINT_ENV,
        )
        return None

    resource = Resource.create({SERVICE_NAME: "agent-bom", SERVICE_VERSION: __version__})
    provider = LoggerProvider(resource=resource)
    provider.add_log_record_processor(
        BatchLogRecordProcessor(OTLPLogExporter(endpoint=endpoint, headers=headers or None))
    )
    return AuditLogOtlpExporter(provider=provider)


_EXPORTER: AuditLogOtlpExporter | None = None
_EXPORTER_LOCK = threading.Lock()
_CONFIGURED = False


def configure_audit_otlp_from_env() -> AuditLogOtlpExporter | None:
    """Return a process-wide audit OTLP-log exporter from env, or ``None``.

    Reads ``AGENT_BOM_OTEL_LOGS_ENDPOINT`` (+ optional
    ``AGENT_BOM_OTEL_LOGS_HEADERS``). Unset endpoint ⇒ disabled (``None``).
    Cached after the first successful build so the batch processor / background
    exporter is created once per process.
    """
    global _EXPORTER, _CONFIGURED
    endpoint = os.environ.get(ENDPOINT_ENV, "").strip()
    if not endpoint:
        return None
    with _EXPORTER_LOCK:
        if _CONFIGURED and _EXPORTER is not None:
            return _EXPORTER
        headers = _parse_headers(os.environ.get(HEADERS_ENV, "").strip())
        exporter = build_audit_otlp_exporter(endpoint, headers)
        if exporter is not None:
            _EXPORTER = exporter
            _CONFIGURED = True
        return exporter


def set_audit_otlp_exporter(exporter: AuditLogOtlpExporter | None) -> None:
    """Override the process exporter (tests / explicit wiring)."""
    global _EXPORTER, _CONFIGURED
    with _EXPORTER_LOCK:
        _EXPORTER = exporter
        _CONFIGURED = exporter is not None


def export_governance_audit_record(record: "GovernanceAuditRecord") -> bool:
    """Fire-and-forget export of one audit record when OTLP logs are configured.

    Non-blocking and failure-tolerant: returns ``True`` when the record was
    enqueued for export, ``False`` when export is not configured or the emit
    failed. Safe to call from the audit-append hot path.
    """
    # An explicitly-set exporter (programmatic wiring / tests) is used directly;
    # otherwise fall back to the env-configured singleton.
    exporter = _EXPORTER if (_CONFIGURED and _EXPORTER is not None) else configure_audit_otlp_from_env()
    if exporter is None:
        return False
    try:
        return exporter.export([record]) == 1
    except Exception:  # noqa: BLE001
        logger.warning("governance audit OTLP export failed", exc_info=True)
        return False


def audit_otlp_health() -> dict[str, Any]:
    """Operator-facing status of audit OTLP-log export (no secrets)."""
    endpoint = os.environ.get(ENDPOINT_ENV, "").strip()
    headers = os.environ.get(HEADERS_ENV, "").strip()
    if not endpoint:
        state = "disabled"
    elif _CONFIGURED and _EXPORTER is not None:
        state = "configured"
    else:
        state = "pending"
    return {
        "otlp_logs_export": state,
        "otlp_logs_endpoint_configured": bool(endpoint),
        "otlp_logs_headers_configured": bool(headers),
    }


__all__ = [
    "AuditLogOtlpExporter",
    "ENDPOINT_ENV",
    "HEADERS_ENV",
    "audit_otlp_health",
    "audit_record_log_attributes",
    "build_audit_otlp_exporter",
    "configure_audit_otlp_from_env",
    "export_governance_audit_record",
    "set_audit_otlp_exporter",
    "severity_for_action",
]
