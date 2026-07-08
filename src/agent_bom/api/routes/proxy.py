"""Proxy status, runtime production index, alerts, shield, and WebSocket streaming API routes.

Endpoints:
    GET       /v1/proxy/status       proxy metrics summary
    GET       /v1/proxy/alerts       recent proxy alerts (filterable)
    POST      /v1/shield/start       start deep defense protection engine
    GET       /v1/shield/status      shield threat assessment
    POST      /v1/shield/unblock     deactivate kill-switch
    WebSocket /ws/proxy/metrics      live metrics stream (1 Hz)
    WebSocket /ws/proxy/alerts       live alert stream
"""

from __future__ import annotations

import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path as _Path
from threading import Lock
from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket

from agent_bom.api.idempotency_store import IdempotencyConflictError, idempotency_request_fingerprint
from agent_bom.api.tenancy import require_request_tenant_id

if TYPE_CHECKING:
    from agent_bom.runtime.protection import ProtectionEngine

from agent_bom.api.models import ProxyAuditIngestRequest
from agent_bom.api.stores import _get_idempotency_store
from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.security import sanitize_error, sanitize_sensitive_payload

router = APIRouter()
ws_router = APIRouter()

# ── In-process ring buffer for proxy alerts/metrics ──────────────────────────
#
# The proxy (when running in the same process, e.g. via the API) pushes
# records here.  External proxy processes write to the JSONL audit log,
# and these endpoints read it.
#
# _proxy_alerts is a bounded deque (O(1) append/pop from both ends).
# _proxy_alerts_total is a monotonic counter that never decrements —
# WebSocket clients track their position by this counter, not by deque
# index, so they correctly detect new alerts even when old ones are
# evicted from the ring.

_proxy_alerts: deque[dict] = deque(maxlen=1000)
_proxy_alerts_total: int = 0
_proxy_metrics: dict | None = None
_proxy_metrics_by_tenant: dict[str, dict] = {}

# dedupe inbound proxy alerts by event_id over a 24h
# window so a hostile or buggy proxy cannot replay credential-leak alerts and
# inflate detector tallies. Per-(tenant_id, event_id) entries expire after
# AUDIT_DEDUPE_WINDOW_SECONDS.
AUDIT_DEDUPE_WINDOW_SECONDS = 24 * 60 * 60
AUDIT_DEDUPE_MAX_ENTRIES = 50_000
_audit_dedupe: "OrderedDict[tuple[str, str], float]" = OrderedDict()
_audit_dedupe_lock = Lock()


def _purge_expired_dedupe(now: float) -> None:
    cutoff = now - AUDIT_DEDUPE_WINDOW_SECONDS
    while _audit_dedupe:
        key, ts = next(iter(_audit_dedupe.items()))
        if ts >= cutoff:
            break
        _audit_dedupe.popitem(last=False)
    while len(_audit_dedupe) > AUDIT_DEDUPE_MAX_ENTRIES:
        _audit_dedupe.popitem(last=False)


def _claim_audit_event(tenant_id: str, event_id: str) -> bool:
    """Reserve a (tenant, event_id) pair. Returns True if new, False if replay."""
    if not event_id:
        return True
    now = time.time()
    key = (tenant_id or "default", event_id)
    with _audit_dedupe_lock:
        _purge_expired_dedupe(now)
        if key in _audit_dedupe:
            return False
        _audit_dedupe[key] = now
        return True


def _reset_audit_dedupe_for_tests() -> None:
    """Test helper to clear the dedupe table between cases."""
    with _audit_dedupe_lock:
        _audit_dedupe.clear()


def push_proxy_alert(alert: dict) -> None:
    """Called by the proxy to record a runtime alert (in-process path)."""
    global _proxy_alerts_total
    sanitized = sanitize_sensitive_payload(alert)
    safe = redact_for_persistence(sanitized, EvidenceTier.SAFE_TO_STORE)
    _proxy_alerts.append(safe if isinstance(safe, dict) else {})
    _proxy_alerts_total += 1


def push_proxy_metrics(metrics: dict) -> None:
    """Called by the proxy to record latest metrics summary."""
    global _proxy_metrics
    sanitized = sanitize_sensitive_payload(metrics)
    _proxy_metrics = sanitized if isinstance(sanitized, dict) else {}
    _proxy_metrics.setdefault("received_at", datetime.now(timezone.utc).isoformat())
    tenant_id = str(_proxy_metrics.get("tenant_id") or "default")
    _proxy_metrics_by_tenant[tenant_id] = dict(_proxy_metrics)


def _request_tenant_id(request: Request) -> str:
    """Return the authenticated tenant for HTTP proxy endpoints."""
    return require_request_tenant_id(request)


def _alert_visible_to_tenant(alert: dict, tenant_id: str) -> bool:
    """Scope process-wide proxy alerts to the authenticated tenant.

    Historical single-user/local records may not have a tenant tag. Keep those
    visible only to the default tenant so they do not leak into authenticated
    customer tenants on shared deployments.
    """
    alert_tenant = str(alert.get("tenant_id") or "default")
    return alert_tenant == tenant_id


@router.post("/proxy/audit", tags=["proxy"])
async def ingest_proxy_audit(request: Request, body: ProxyAuditIngestRequest) -> dict:
    """Ingest alerts and summary from an external proxy process."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.stores import _get_analytics_store

    actor = getattr(request.state, "api_key_name", "") or "proxy-client"
    tenant_id = require_request_tenant_id(request)
    request_id = getattr(request.state, "request_id", "") or ""
    trace_id = getattr(request.state, "trace_id", "") or ""
    source_id = body.source_id or "unknown"
    session_id = body.session_id or "default"
    analytics_events: list[dict] = []
    request_hash = idempotency_request_fingerprint(body)
    if body.idempotency_key:
        try:
            cached = _get_idempotency_store().get(
                "/v1/proxy/audit",
                tenant_id,
                source_id,
                body.idempotency_key,
                request_hash=request_hash,
            )
        except IdempotencyConflictError as exc:
            raise HTTPException(status_code=409, detail=sanitize_error(exc)) from exc
        if cached is not None:
            cached["idempotent_replay"] = True
            return cached

    from agent_bom.api.stores import _get_firewall_decision_store

    firewall_store = _get_firewall_decision_store()
    duplicate_event_ids: list[str] = []
    accepted_alerts: list[dict] = []
    for alert in body.alerts:
        enriched = dict(alert)
        enriched.setdefault("source_id", source_id)
        enriched.setdefault("session_id", session_id)
        enriched.setdefault("request_id", request_id)
        enriched.setdefault("trace_id", trace_id)
        enriched.setdefault("event_type", enriched.get("action") or enriched.get("type", "runtime_alert"))
        # Force the server-authoritative tenant_id on the in-memory record so
        # per-tenant posture queries (e.g. compliance has_proxy) scope correctly.
        # The ring buffer is process-wide; never honor a client-supplied
        # tenant_id here — setdefault would let a caller pre-tag another tenant
        # and write a cross-tenant alert that surfaces in that tenant's reads.
        enriched["tenant_id"] = tenant_id
        # dedupe by event_id so a buggy or hostile proxy
        # cannot replay credential_leak alerts and inflate per-detector
        # tallies. Empty event_id falls through to keep legacy callers working.
        event_id = str(enriched.get("event_id") or "")
        if event_id and not _claim_audit_event(tenant_id, event_id):
            duplicate_event_ids.append(event_id)
            continue
        accepted_alerts.append(enriched)
        push_proxy_alert(enriched)
        # Tally inter-agent firewall decisions for the runtime-tab dashboard
        # (#982 PR 4). Non-firewall alerts are silently ignored by record().
        try:
            firewall_store.record(tenant_id=tenant_id, event=enriched)
        except Exception:  # noqa: BLE001 — store is best-effort, never block ingest
            pass
        analytics_events.append(
            redact_for_persistence(
                {
                    "event_id": enriched.get("event_id", ""),
                    "event_timestamp": enriched.get("timestamp") or enriched.get("ts"),
                    "tenant_id": tenant_id,
                    "event_type": enriched.get("event_type", enriched.get("type", "runtime_alert")),
                    "detector": enriched.get("detector", ""),
                    "severity": enriched.get("severity", "INFO"),
                    "tool_name": enriched.get("tool_name", enriched.get("tool", "")),
                    "message": enriched.get("message", ""),
                    "agent_name": enriched.get("agent_name", ""),
                    "session_id": enriched.get("session_id", ""),
                    "trace_id": enriched.get("trace_id", ""),
                    "request_id": enriched.get("request_id", ""),
                    "source_id": enriched.get("source_id", ""),
                },
                EvidenceTier.SAFE_TO_STORE,
            )
        )

    if body.summary:
        summary = dict(body.summary)
        summary.setdefault("source_id", source_id)
        summary.setdefault("session_id", session_id)
        summary.setdefault("request_id", request_id)
        summary.setdefault("trace_id", trace_id)
        # Server-authoritative tenant tag — never honor a client-supplied
        # tenant_id, which would route this summary into another tenant's
        # metrics bucket on shared deployments.
        summary["tenant_id"] = tenant_id
        push_proxy_metrics(summary)

    if analytics_events:
        try:
            _get_analytics_store().record_events(analytics_events, tenant_id=tenant_id)
        except Exception:
            pass

    # count both the alerts that crossed the wire and the
    # runtime_alerts surfaced via summary so credential_leak detections always
    # register, regardless of which envelope key the caller used.
    summary_runtime_alerts = 0
    if isinstance(body.summary, dict):
        candidate = body.summary.get("runtime_alerts")
        if isinstance(candidate, int):
            summary_runtime_alerts = max(0, candidate)
        elif isinstance(candidate, list):
            summary_runtime_alerts = len(candidate)
    accepted_count = len(accepted_alerts)
    effective_alert_count = max(accepted_count, summary_runtime_alerts)

    log_action(
        "proxy.audit_ingested",
        actor=actor,
        resource=f"proxy/{source_id}",
        tenant_id=tenant_id,
        session_id=session_id,
        request_id=request_id,
        trace_id=trace_id,
        alert_count=effective_alert_count,
        duplicate_alert_count=len(duplicate_event_ids),
        has_summary=body.summary is not None,
    )
    response = {
        "ingested": True,
        "source_id": source_id,
        "session_id": session_id,
        "alert_count": effective_alert_count,
        "accepted_alert_count": accepted_count,
        "duplicate_alert_count": len(duplicate_event_ids),
        "duplicate_event_ids": duplicate_event_ids,
        "has_summary": body.summary is not None,
    }
    if body.idempotency_key:
        _get_idempotency_store().put(
            "/v1/proxy/audit",
            tenant_id,
            source_id,
            body.idempotency_key,
            response,
            request_hash=request_hash,
        )
    return response


def _get_configured_log_path() -> _Path | None:
    """Return the server-configured audit log path, if set.

    The path is set via the AGENT_BOM_LOG environment variable (server-side
    config only — never from user input).  Returns None when the env var is
    unset or the file doesn't exist.
    """
    import os

    log_env = os.environ.get("AGENT_BOM_LOG")
    if not log_env:
        return None
    path = _Path(log_env).resolve()
    if not path.is_file() or path.suffix != ".jsonl":
        return None
    return path


_MAX_LOG_LINES = 50_000  # Cap log parsing to prevent memory issues


def _read_alerts_from_log(path: _Path) -> list[dict]:
    """Read runtime_alert records from a JSONL audit log."""
    import json as _json

    alerts: list[dict] = []
    try:
        with open(path) as f:
            for i, raw_line in enumerate(f):
                if i >= _MAX_LOG_LINES:
                    break
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = _json.loads(line)
                    if record.get("type") == "runtime_alert":
                        sanitized = sanitize_sensitive_payload(record)
                        if isinstance(sanitized, dict):
                            safe = redact_for_persistence(sanitized, EvidenceTier.SAFE_TO_STORE)
                            if isinstance(safe, dict):
                                alerts.append(safe)
                except (ValueError, KeyError):
                    continue
    except OSError:
        pass
    return alerts


def _load_proxy_alerts(tenant_id: str = "default") -> list[dict]:
    """Return in-memory alerts, or fall back to the configured audit log."""
    log_path = _get_configured_log_path()
    if log_path and not _proxy_alerts:
        alerts = _read_alerts_from_log(log_path)
    else:
        alerts = list(_proxy_alerts)
    return [alert for alert in alerts if _alert_visible_to_tenant(alert, tenant_id)]


def _summarize_proxy_alerts(alerts: list[dict]) -> dict:
    """Build a compact summary for proxy status and alert APIs."""
    severity_counts: Counter[str] = Counter()
    detector_counts: Counter[str] = Counter()
    blocked_alerts = 0
    recent_alerts: list[dict] = []

    for alert in sorted(alerts, key=lambda item: str(item.get("ts", "")), reverse=True):
        severity = str(alert.get("severity", "unknown")).lower()
        detector = str(alert.get("detector", "unknown"))
        severity_counts[severity] += 1
        detector_counts[detector] += 1
        details = alert.get("details", {})
        if isinstance(details, dict) and details.get("action") == "blocked":
            blocked_alerts += 1
        if len(recent_alerts) < 5:
            recent_alerts.append(
                {
                    "ts": alert.get("ts", ""),
                    "detector": detector,
                    "severity": severity,
                    "message": alert.get("message", ""),
                }
            )

    return {
        "total_alerts": len(alerts),
        "blocked_alerts": blocked_alerts,
        "alerts_by_severity": dict(sorted(severity_counts.items())),
        "alerts_by_detector": dict(sorted(detector_counts.items())),
        "latest_alert_at": recent_alerts[0]["ts"] if recent_alerts else "",
        "recent_alerts": recent_alerts,
    }


def _safe_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int | float | str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _safe_float(value: object, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, int | float | str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _numeric_mapping(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, int] = {}
    for raw_key, raw_count in value.items():
        key = str(raw_key or "unknown")
        result[key] = max(0, _safe_int(raw_count))
    return dict(sorted(result.items()))


def _top_items(counts: Counter[str] | dict[str, int], *, limit: int = 10) -> list[dict[str, object]]:
    if isinstance(counts, Counter):
        items = counts.most_common(limit)
    else:
        items = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [{"name": name, "count": count} for name, count in items]


def _timestamp_value(value: object) -> float:
    if isinstance(value, int | float):
        return float(value)
    if not isinstance(value, str) or not value:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _latest_timestamp(values: list[object]) -> str:
    candidates = [value for value in values if value]
    if not candidates:
        return ""
    latest = max(candidates, key=_timestamp_value)
    return str(latest)


def _runtime_retention_posture() -> dict[str, object]:
    return {
        "default_mode": "redacted",
        "modes": {
            "audit_full": "Operator-controlled local JSONL or downstream SIEM retention; not returned by the production index.",
            "redacted": "Safe-to-store runtime alerts after secret sanitization and evidence-tier redaction.",
            "metadata_only": (
                "Counts, tool names, detector names, source IDs, and trace/session references without raw arguments or payloads."
            ),
            "no_persist": "Raw prompts, raw tool arguments, raw responses, credential values, and unredacted screenshots.",
        },
        "event_classes": {
            "proxy_alerts": "redacted",
            "runtime_analytics_events": "metadata_only",
            "production_index": "metadata_only",
            "control_plane_audit_summary": "metadata_only",
            "raw_tool_arguments": "no_persist",
            "raw_tool_responses": "no_persist",
        },
        "guarantees": [
            "tenant-scoped HTTP reads",
            "secret values sanitized before persistence",
            "raw arguments excluded from production-index responses",
            "runtime events correlate by source_id, session_id, request_id, and trace_id when present",
        ],
    }


def _classify_authorization_event(alert: dict) -> str:
    action = str(alert.get("action") or alert.get("event_type") or alert.get("type") or "").lower()
    detector = str(alert.get("detector") or "").lower()
    effective = str(alert.get("effective_decision") or alert.get("decision") or "").lower()
    message = str(alert.get("message") or "").lower()
    haystack = " ".join((action, detector, effective, message))
    if "approval_required" in haystack or "approval required" in haystack or effective == "warn":
        return "approval_required"
    if "data_filter" in haystack or "data filter" in haystack or "redact" in haystack or "mask" in haystack:
        return "data_filter_applied"
    if "block" in haystack or "deny" in haystack or effective == "deny":
        return "blocked"
    if "allow" in haystack or "authorized" in haystack or effective == "allow":
        return "authorized"
    return "observed"


def _authorization_trace(*, allowed_tool_calls: int, blocked_tool_calls: int, alerts: list[dict]) -> dict[str, object]:
    """Return accountable runtime authorization counts without raw arguments."""
    trace_counts: Counter[str] = Counter()
    recent: list[dict[str, object]] = []
    for alert in sorted(alerts, key=lambda item: str(item.get("ts") or item.get("timestamp") or ""), reverse=True):
        trace_class = _classify_authorization_event(alert)
        if trace_class != "observed":
            trace_counts[trace_class] += 1
        if len(recent) < 10:
            recent.append(
                {
                    "ts": alert.get("ts") or alert.get("timestamp") or alert.get("event_timestamp") or "",
                    "trace_class": trace_class,
                    "source_id": alert.get("source_id") or "unknown",
                    "session_id": alert.get("session_id") or "unknown",
                    "tool_name": alert.get("tool_name") or alert.get("tool") or "",
                    "decision": alert.get("effective_decision") or alert.get("decision") or "",
                    "detector": alert.get("detector") or "",
                }
            )
    return {
        "authorized": max(0, allowed_tool_calls + trace_counts["authorized"]),
        "blocked": max(0, blocked_tool_calls + trace_counts["blocked"]),
        "data_filter_applied": trace_counts["data_filter_applied"],
        "approval_required": trace_counts["approval_required"],
        "recent": recent,
        "retention": "metadata_only",
    }


def _runtime_metrics_for_tenant(tenant_id: str) -> dict | None:
    metrics: dict | None = None
    if _proxy_metrics is not None:
        tenant_metrics = _proxy_metrics_by_tenant.get(tenant_id)
        if tenant_metrics is not None:
            metrics = dict(tenant_metrics)
        elif _alert_visible_to_tenant(_proxy_metrics, tenant_id):
            metrics = dict(_proxy_metrics)
    else:
        log_path = _get_configured_log_path()
        if log_path:
            metrics = _read_metrics_from_log(log_path, tenant_id)
            if metrics is not None:
                metrics = dict(metrics)
    return metrics


def _build_runtime_production_index(tenant_id: str, metrics: dict | None, alerts: list[dict]) -> dict[str, object]:
    metrics = dict(metrics or {})
    alert_summary = _summarize_proxy_alerts(alerts)
    calls_by_tool = _numeric_mapping(metrics.get("calls_by_tool"))
    blocked_by_reason = _numeric_mapping(metrics.get("blocked_by_reason"))
    total_tool_calls = max(_safe_int(metrics.get("total_tool_calls")), sum(calls_by_tool.values()))
    total_blocked = max(
        _safe_int(metrics.get("total_blocked")),
        sum(blocked_by_reason.values()),
        _safe_int(alert_summary["blocked_alerts"]),
    )
    allowed_tool_calls = max(0, total_tool_calls - total_blocked)

    source_counts: Counter[str] = Counter()
    session_counts: Counter[str] = Counter()
    gateway_action_counts: Counter[str] = Counter()
    for alert in alerts:
        source_id = str(alert.get("source_id") or "unknown")
        session_id = str(alert.get("session_id") or "unknown")
        action = str(alert.get("action") or alert.get("event_type") or alert.get("type") or "runtime_alert")
        source_counts[source_id] += 1
        session_counts[session_id] += 1
        if action.startswith("gateway."):
            gateway_action_counts[action] += 1

    if metrics.get("source_id"):
        source_counts[str(metrics["source_id"])] += 0
    if metrics.get("session_id"):
        session_counts[str(metrics["session_id"])] += 0

    latest_alert_at = _latest_timestamp([alert.get("ts") or alert.get("timestamp") or alert.get("event_timestamp") for alert in alerts])
    metrics_received_at = str(metrics.get("received_at") or metrics.get("ts") or "")
    block_rate = (total_blocked / total_tool_calls) if total_tool_calls else 0.0
    latency = metrics.get("latency") if isinstance(metrics.get("latency"), dict) else {}

    return {
        "schema_version": "runtime.production_index.v1",
        "tenant_id": tenant_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "ok" if metrics or alerts else "no_runtime_activity",
        "traffic": {
            "total_tool_calls": total_tool_calls,
            "allowed_tool_calls": allowed_tool_calls,
            "blocked_tool_calls": total_blocked,
            "block_rate": round(block_rate, 4),
            "calls_by_tool": calls_by_tool,
            "top_tools": _top_items(calls_by_tool),
            "blocked_by_reason": blocked_by_reason,
            "uptime_seconds": _safe_float(metrics.get("uptime_seconds")),
            "latency_p95_ms": _safe_float(latency.get("p95_ms")) if latency else None,
        },
        "policy_decisions": {
            "allowed": allowed_tool_calls,
            "blocked": total_blocked,
            "gateway_actions": dict(sorted(gateway_action_counts.items())),
        },
        "authorization_trace": _authorization_trace(
            allowed_tool_calls=allowed_tool_calls,
            blocked_tool_calls=total_blocked,
            alerts=alerts,
        ),
        "alerts": {key: value for key, value in alert_summary.items() if key != "recent_alerts"},
        "active_sources": _top_items(source_counts),
        "active_sessions": _top_items(session_counts),
        "freshness": {
            "has_metrics": bool(metrics),
            "has_alerts": bool(alerts),
            "metrics_received_at": metrics_received_at,
            "latest_alert_at": latest_alert_at,
        },
        "retention_posture": _runtime_retention_posture(),
    }


def _read_metrics_from_log(path: _Path, tenant_id: str = "default") -> dict | None:
    """Read the last proxy_summary record from a JSONL audit log."""
    import json as _json

    last_summary = None
    try:
        with open(path) as f:
            for i, raw_line in enumerate(f):
                if i >= _MAX_LOG_LINES:
                    break
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = _json.loads(line)
                    if record.get("type") == "proxy_summary" and _alert_visible_to_tenant(record, tenant_id):
                        last_summary = record
                except (ValueError, KeyError):
                    continue
    except OSError:
        pass
    return last_summary


# ── HTTP endpoints ───────────────────────────────────────────────────────────


@router.get("/proxy/status", tags=["proxy"])
async def proxy_status(request: Request) -> dict:
    """Get runtime proxy metrics.

    Returns the latest proxy metrics summary.  Reads from the in-process
    buffer (populated by ``push_proxy_metrics``) or from the audit log
    configured via the ``AGENT_BOM_LOG`` environment variable.
    """
    tenant_id = _request_tenant_id(request)
    metrics: dict | None = None
    if _proxy_metrics is not None:
        tenant_metrics = _proxy_metrics_by_tenant.get(tenant_id)
        if tenant_metrics is not None:
            metrics = dict(tenant_metrics)
        elif _alert_visible_to_tenant(_proxy_metrics, tenant_id):
            metrics = dict(_proxy_metrics)
    else:
        log_path = _get_configured_log_path()
        if log_path:
            metrics = _read_metrics_from_log(log_path, tenant_id)
            if metrics is not None:
                metrics = dict(metrics)

    if metrics is not None:
        alert_summary = _summarize_proxy_alerts(_load_proxy_alerts(tenant_id))
        metrics["alert_summary"] = {key: value for key, value in alert_summary.items() if key != "recent_alerts"}
        metrics["recent_alerts"] = alert_summary["recent_alerts"]
        return metrics

    return {
        "status": "no_proxy_session",
        "message": "No proxy metrics available. Start a proxy session or set AGENT_BOM_LOG.",
    }


@router.get("/runtime/production-index", tags=["runtime", "proxy"])
async def runtime_production_index(request: Request) -> dict:
    """Return tenant-scoped runtime security observability for proxy/gateway traffic.

    The production index is metadata-only by construction: it summarizes
    tool-call volume, policy decisions, alerts, source/session activity, and
    retention posture without returning raw prompts, raw arguments, raw
    responses, or credential values.
    """
    tenant_id = _request_tenant_id(request)
    metrics = _runtime_metrics_for_tenant(tenant_id)
    alerts = _load_proxy_alerts(tenant_id)
    return _build_runtime_production_index(tenant_id, metrics, alerts)


@router.get("/proxy/alerts", tags=["proxy"])
async def proxy_alerts(
    request: Request,
    severity: str | None = None,
    detector: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000, description="Max alerts to return (1-1000)"),
) -> dict:
    """Get recent runtime proxy alerts.

    Returns alerts from the in-process buffer or the audit log configured
    via the ``AGENT_BOM_LOG`` environment variable.

    Query params:
        severity: Filter by severity (critical, high, medium, low, info).
        detector: Filter by detector name.
        limit: Maximum number of alerts to return (default 100).
    """
    tenant_id = _request_tenant_id(request)
    alerts = _load_proxy_alerts(tenant_id)

    # Apply filters
    if severity:
        alerts = [a for a in alerts if a.get("severity", "").lower() == severity.lower()]
    if detector:
        alerts = [a for a in alerts if a.get("detector", "").lower() == detector.lower()]

    # Newest first, apply limit
    alerts = alerts[-limit:][::-1]

    return {
        "alerts": alerts,
        "count": len(alerts),
        "summary": _summarize_proxy_alerts(alerts),
        "filters": {
            "severity": severity,
            "detector": detector,
            "limit": limit,
        },
    }


# ── WebSocket endpoints ─────────────────────────────────────────────────────


def _ws_header_token(websocket: WebSocket) -> str:
    """Extract non-URL WebSocket auth tokens from headers when present."""
    authorization = websocket.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    for protocol in websocket.headers.get("sec-websocket-protocol", "").split(","):
        value = protocol.strip()
        if value.startswith("agent-bom-token."):
            return value.removeprefix("agent-bom-token.").strip()
    return ""


@dataclass(frozen=True)
class _WebSocketAuthContext:
    tenant_id: str = "default"
    role: str = "admin"
    auth_method: str = "no_auth"


def _role_allows(actual: str, required: str = "viewer") -> bool:
    from agent_bom.rbac import Role, role_rank

    try:
        actual_role = Role(str(actual).strip().lower())
        required_role = Role(required)
    except ValueError:
        return False
    return role_rank(actual_role) >= role_rank(required_role)


def _ws_auth_required() -> bool:
    import os as _os

    from agent_bom.api.oidc import oidc_enabled_from_env

    configured = any(
        (
            _os.environ.get("AGENT_BOM_API_KEY"),
            _os.environ.get("AGENT_BOM_API_KEYS", "").strip(),
            oidc_enabled_from_env(),
            _os.environ.get("AGENT_BOM_SAML_IDP_ENTITY_ID", "").strip(),
            _os.environ.get("AGENT_BOM_SAML_IDP_SSO_URL", "").strip(),
            _os.environ.get("AGENT_BOM_SAML_IDP_X509_CERT", "").strip(),
            _os.environ.get("AGENT_BOM_SAML_SP_ENTITY_ID", "").strip(),
            _os.environ.get("AGENT_BOM_SAML_SP_ACS_URL", "").strip(),
            _os.environ.get("AGENT_BOM_SCIM_BEARER_TOKEN"),
            _os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH", "").strip().lower() in {"1", "true", "yes", "on"},
        )
    )
    if configured:
        return True
    try:
        from agent_bom.api.auth import get_key_store

        return get_key_store().has_keys()
    except Exception:
        return False


def _ws_auth_from_trusted_proxy(websocket: WebSocket) -> _WebSocketAuthContext | None:
    import hmac as _hmac
    import os as _os

    if _os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return None

    secret = _os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "").strip()
    presented_secret = websocket.headers.get("x-agent-bom-proxy-secret", "").strip()
    from agent_bom.api.middleware import _trusted_proxy_secret_is_strong

    if not _trusted_proxy_secret_is_strong(secret):
        return None
    if not secret or not presented_secret or not _hmac.compare_digest(presented_secret, secret):
        return None
    expected_issuer = _os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH_ISSUER", "").strip()
    presented_issuer = websocket.headers.get("x-agent-bom-auth-issuer", "").strip()
    if expected_issuer and not _hmac.compare_digest(presented_issuer, expected_issuer):
        return None
    role = websocket.headers.get("x-agent-bom-role", "").strip().lower()
    if not _role_allows(role, "viewer"):
        return None
    tenant_id = websocket.headers.get("x-agent-bom-tenant-id", "").strip()
    if not tenant_id:
        return None
    from agent_bom.platform_invariants import ReservedTenantIdError, validate_customer_tenant_id

    try:
        tenant_id = validate_customer_tenant_id(tenant_id)
    except ReservedTenantIdError:
        return None
    return _WebSocketAuthContext(tenant_id=tenant_id, role=role, auth_method="proxy_header")


def _ws_auth_from_token(token: str, *, bearer: bool = True) -> _WebSocketAuthContext | None:
    import hmac as _hmac
    import os as _os

    token = str(token or "").strip()
    if not token:
        return None

    static_key = _os.environ.get("AGENT_BOM_API_KEY")
    if static_key and _hmac.compare_digest(token, static_key):
        return _WebSocketAuthContext(tenant_id="default", role="admin", auth_method="static_api_key")

    from agent_bom.api.auth import get_key_store

    store = get_key_store()
    api_key = store.verify(token)
    if api_key is not None and _role_allows(api_key.role.value, "viewer"):
        return _WebSocketAuthContext(tenant_id=api_key.tenant_id, role=api_key.role.value, auth_method="api_key")

    # Direct ASGI imports may configure AGENT_BOM_API_KEYS after module import.
    # Mirror the env key fallback so WebSockets do not bypass RBAC-key auth
    # when the HTTP middleware is protected.
    for item in _os.environ.get("AGENT_BOM_API_KEYS", "").split(","):
        raw_key, sep, role_value = item.strip().partition(":")
        if sep and raw_key and _hmac.compare_digest(token, raw_key.strip()) and _role_allows(role_value, "viewer"):
            return _WebSocketAuthContext(tenant_id="default", role=role_value.strip().lower(), auth_method="api_key")

    if bearer:
        from agent_bom.api.oidc import oidc_enabled_from_env

        if not oidc_enabled_from_env():
            return None
        from agent_bom.api.oidc import OIDCConfig, OIDCError

        oidc_cfg = OIDCConfig.from_env()
        if oidc_cfg is not None and getattr(oidc_cfg, "enabled", False):
            try:
                claims, oidc_role = oidc_cfg.verify(token)
            except OIDCError:
                return None
            if _role_allows(oidc_role, "viewer"):
                return _WebSocketAuthContext(tenant_id=oidc_cfg.resolve_tenant(claims), role=oidc_role, auth_method="oidc")
    return None


async def _ws_accept_and_check_auth(websocket: WebSocket) -> _WebSocketAuthContext | None:
    """Accept the WebSocket only into an authenticated streaming state.

    API keys in query strings are intentionally rejected because URLs are
    commonly captured by browser history, access logs, and reverse proxies.
    Browser callers should send ``{"type":"auth","token":"..."}`` as the first
    message after connect. Non-browser callers may use ``Authorization:
    Bearer`` or ``Sec-WebSocket-Protocol: agent-bom-token.<token>``.
    """
    import asyncio as _asyncio

    auth_required = _ws_auth_required()
    if not auth_required:
        await websocket.accept()
        return _WebSocketAuthContext()  # local dev / single-user mode

    if websocket.query_params.get("token"):
        await websocket.close(code=4001)
        return None

    proxy_context = _ws_auth_from_trusted_proxy(websocket)
    if proxy_context is not None:
        await websocket.accept()
        return proxy_context

    token = _ws_header_token(websocket)
    header_context = _ws_auth_from_token(token, bearer=True)
    if header_context is not None:
        await websocket.accept()
        return header_context

    await websocket.accept()
    try:
        payload = await _asyncio.wait_for(websocket.receive_json(), timeout=5.0)
    except Exception:  # noqa: BLE001 - auth handshake failures all close the stream
        await websocket.close(code=4001)
        return None

    if isinstance(payload, dict) and payload.get("type") == "auth":
        token = str(payload.get("token", ""))
        message_context = _ws_auth_from_token(token, bearer=False)
        if message_context is not None:
            await websocket.send_json({"type": "auth", "status": "ok"})
            return message_context

    await websocket.close(code=4001)
    return None


@ws_router.websocket("/ws/proxy/metrics")
async def ws_proxy_metrics(websocket: WebSocket) -> None:
    """WebSocket endpoint — push proxy metrics every second.

    Connect to ``ws://localhost:8422/ws/proxy/metrics`` to receive a live
    stream of proxy metrics as JSON objects.  Useful for building real-time
    dashboards without polling.

    Authentication: when API auth is configured, send
    ``{"type":"auth","token":"..."}`` as the first message or use an
    Authorization bearer token. API keys in query strings are rejected to keep
    credentials out of URL logs.

    Message format (sent every second):
    ::

        {
          "ts": 1234567890.123,
          "tool_calls": {"read_file": 12, "exec": 3},
          "blocked": {"rate_limit": 1, "policy": 2},
          "alerts_last_60s": 4,
          "latency_p95_ms": 45.2
        }

    Connection is closed cleanly on disconnect.
    """
    import asyncio
    import time as _time

    try:
        from fastapi.websockets import WebSocketDisconnect
    except ImportError:
        from starlette.websockets import WebSocketDisconnect  # type: ignore[no-reattr]

    auth_context = await _ws_accept_and_check_auth(websocket)
    if auth_context is None:
        return
    tenant_id = auth_context.tenant_id

    try:
        while True:
            now = _time.time()
            # Build snapshot from in-process metrics buffer
            metrics_snapshot = _runtime_metrics_for_tenant(tenant_id) or {}

            # Count alerts in last 60 seconds
            cutoff = now - 60
            recent_alerts = [a for a in _proxy_alerts if a.get("ts", 0) > cutoff and _alert_visible_to_tenant(a, tenant_id)]

            await websocket.send_json(
                {
                    "ts": now,
                    "tool_calls": metrics_snapshot.get("calls_by_tool", {}),
                    "blocked": metrics_snapshot.get("blocked_by_reason", {}),
                    "alerts_last_60s": len(recent_alerts),
                    "latency_p95_ms": metrics_snapshot.get("latency", {}).get("p95_ms"),
                    "total_tool_calls": metrics_snapshot.get("total_tool_calls", 0),
                    "total_blocked": metrics_snapshot.get("total_blocked", 0),
                    "uptime_seconds": metrics_snapshot.get("uptime_seconds"),
                }
            )
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        # Client disconnected or error — close quietly
        pass


@ws_router.websocket("/ws/proxy/alerts")
async def ws_proxy_alerts(websocket: WebSocket) -> None:
    """WebSocket endpoint — push new proxy alerts as they arrive.

    Streams new alerts in real time.  Each message is a single alert object.
    Useful for live security dashboards that need immediate notification.

    Authentication: when API auth is configured, send
    ``{"type":"auth","token":"..."}`` as the first message or use an
    Authorization bearer token. API keys in query strings are rejected to keep
    credentials out of URL logs.

    Uses a monotonic total counter (not deque length) to detect new alerts
    correctly even when old entries are evicted from the 1000-entry ring buffer.
    """
    import asyncio

    try:
        from fastapi.websockets import WebSocketDisconnect
    except ImportError:
        from starlette.websockets import WebSocketDisconnect  # type: ignore[no-reattr]

    auth_context = await _ws_accept_and_check_auth(websocket)
    if auth_context is None:
        return
    tenant_id = auth_context.tenant_id

    seen = _proxy_alerts_total  # monotonic — tracks absolute count, not deque position
    try:
        while True:
            current = _proxy_alerts_total
            if current > seen:
                new_count = min(current - seen, len(_proxy_alerts))
                for alert in list(_proxy_alerts)[-new_count:]:
                    if not _alert_visible_to_tenant(alert, tenant_id):
                        continue
                    await websocket.send_json(alert)
                seen = current
            await asyncio.sleep(0.25)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        pass


# ── Shield / Deep Defense endpoints ──────────────────────────────────────────

# Per-tenant, per-session protection engines. Zero trust: one tenant/session's
# CRITICAL threat cannot block or reveal another tenant/session's tool calls.
_ShieldKey = tuple[str, str]
_shield_engines: dict[_ShieldKey, ProtectionEngine] = {}
_MAX_SHIELD_SESSIONS = 64  # bound memory; evict oldest idle session


def _shield_key(tenant_id: str, session_id: str) -> _ShieldKey:
    return (tenant_id or "default", session_id or "default")


def _get_engine(tenant_id: str, session_id: str) -> ProtectionEngine | None:
    return _shield_engines.get(_shield_key(tenant_id, session_id))


@router.post("/shield/start", tags=["shield"])
async def shield_start(request: Request, session_id: str = "default", correlation_window: float = 30.0) -> dict:
    """Start the deep defense protection engine for a session.

    Each session_id gets an isolated engine — zero trust, no cross-session
    threat contamination.

    Query params:
        session_id: Session identifier (default "default").
        correlation_window: Alert correlation window in seconds (default 30).
    """
    from agent_bom.alerts.dispatcher import AlertDispatcher
    from agent_bom.runtime.protection import ProtectionEngine

    tenant_id = _request_tenant_id(request)
    key = _shield_key(tenant_id, session_id)
    existing = _get_engine(tenant_id, session_id)
    if existing is not None and existing.active:
        return {
            "status": "already_active",
            "tenant_id": tenant_id,
            "session_id": session_id,
            **existing.status(),
        }

    # Evict oldest idle session if at capacity
    if len(_shield_engines) >= _MAX_SHIELD_SESSIONS:
        idle = next(
            (candidate_key for candidate_key, eng in _shield_engines.items() if not eng.active),
            next(iter(_shield_engines)),  # fallback: evict oldest
        )
        old = _shield_engines.pop(idle)
        if old.active:
            old.stop()

    dispatcher = AlertDispatcher()
    from agent_bom.api.routes.proxy import push_proxy_alert

    class _RingBufferChannel:
        async def send(self, alert: dict) -> bool:
            push_proxy_alert(alert)
            return True

    dispatcher.add_channel(_RingBufferChannel())

    engine = ProtectionEngine(
        dispatcher=dispatcher,
        shield=True,
        correlation_window=correlation_window,
    )
    engine.start()
    _shield_engines[key] = engine
    return {"status": "started", "tenant_id": tenant_id, "session_id": session_id, **engine.status()}


@router.get("/shield/status", tags=["shield"])
async def shield_status(request: Request, session_id: str = "default") -> dict:
    """Get current shield threat assessment for a session."""
    tenant_id = _request_tenant_id(request)
    engine = _get_engine(tenant_id, session_id)
    if engine is None or not engine.active:
        return {
            "active": False,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "message": "Shield not started. POST /v1/shield/start to activate.",
        }

    assessment = engine.assess_threat()
    return {
        "tenant_id": tenant_id,
        "session_id": session_id,
        **engine.status(),
        "assessment": {
            "threat_level": assessment.threat_level.value,
            "composite_score": assessment.composite_score,
            "detectors_triggered": assessment.detectors_triggered,
            "alert_count_in_window": assessment.alert_count_in_window,
            "blocked": assessment.blocked,
        },
    }


@router.post("/shield/unblock", tags=["shield"])
async def shield_unblock(request: Request, session_id: str = "default") -> dict:
    """Deactivate kill-switch for a session and reset to ELEVATED."""
    tenant_id = _request_tenant_id(request)
    engine = _get_engine(tenant_id, session_id)
    if engine is None or not engine.active:
        return {"status": "not_active", "tenant_id": tenant_id, "session_id": session_id}

    if not engine.is_blocked:
        return {"status": "not_blocked", "tenant_id": tenant_id, "session_id": session_id}

    engine.unblock()
    return {"status": "unblocked", "tenant_id": tenant_id, "session_id": session_id, **engine.status()}


@router.post("/shield/break-glass", tags=["shield"])
async def break_glass(request: Request, session_id: str = "default", reason: str = "") -> dict:
    """Emergency kill-switch override — admin only, audit logged.

    Immediately unblocks all sessions and logs the override for compliance.
    Requires ``admin`` role (set via ``request.state.api_key_role``).
    """
    role = getattr(request.state, "api_key_role", "viewer")
    if role != "admin":
        raise HTTPException(status_code=403, detail="Break-glass requires admin role")

    tenant_id = _request_tenant_id(request)
    engine = _get_engine(tenant_id, session_id)
    if engine is None or not engine.active:
        # A break-glass ATTEMPT is a privileged action and must always be
        # audited — including when there is no active Shield session to
        # override. Record the attempt + outcome before short-circuiting.
        _audit_break_glass(request, role, session_id, reason, was_blocked=False, outcome="not_active")
        return {"status": "not_active", "tenant_id": tenant_id, "session_id": session_id}

    was_blocked = engine.is_blocked
    if was_blocked:
        engine.unblock()

    # Audit log the break-glass event
    _audit_break_glass(request, role, session_id, reason, was_blocked=was_blocked, outcome="break_glass_activated")

    return {
        "status": "break_glass_activated",
        "tenant_id": tenant_id,
        "session_id": session_id,
        "was_blocked": was_blocked,
        "reason": reason,
        **engine.status(),
    }


def _audit_break_glass(
    request: Request,
    role: str,
    session_id: str,
    reason: str,
    *,
    was_blocked: bool,
    outcome: str,
) -> None:
    """Emit an audit event for a break-glass attempt (success or not).

    Audit-log failures must never block an emergency override, so emission is
    best-effort and swallows exceptions.
    """
    try:
        from agent_bom.api.audit_log import log_action

        tenant_id = require_request_tenant_id(request)
        log_action(
            "break_glass",
            actor=getattr(request.state, "actor", "") or getattr(request.state, "api_key_name", "") or role,
            resource=f"shield/{session_id}",
            tenant_id=tenant_id,
            reason=reason,
            was_blocked=was_blocked,
            outcome=outcome,
        )
    except Exception:  # noqa: BLE001
        pass  # audit log failure must not block emergency override
