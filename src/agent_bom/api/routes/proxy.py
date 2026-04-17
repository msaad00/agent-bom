"""Proxy status, alerts, shield, and WebSocket streaming API routes.

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

from collections import Counter, deque
from pathlib import Path as _Path
from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket

if TYPE_CHECKING:
    from agent_bom.runtime.protection import ProtectionEngine

from agent_bom.api.models import ProxyAuditIngestRequest
from agent_bom.api.stores import _get_idempotency_store

router = APIRouter()

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


def push_proxy_alert(alert: dict) -> None:
    """Called by the proxy to record a runtime alert (in-process path)."""
    global _proxy_alerts_total
    _proxy_alerts.append(alert)
    _proxy_alerts_total += 1


def push_proxy_metrics(metrics: dict) -> None:
    """Called by the proxy to record latest metrics summary."""
    global _proxy_metrics
    _proxy_metrics = metrics


@router.post("/v1/proxy/audit", tags=["proxy"])
async def ingest_proxy_audit(request: Request, body: ProxyAuditIngestRequest) -> dict:
    """Ingest alerts and summary from an external proxy process."""
    from agent_bom.api.audit_log import log_action

    actor = getattr(request.state, "api_key_name", "") or "proxy-client"
    tenant_id = getattr(request.state, "tenant_id", "default")
    source_id = body.source_id or "unknown"
    session_id = body.session_id or "default"
    if body.idempotency_key:
        cached = _get_idempotency_store().get("/v1/proxy/audit", tenant_id, source_id, body.idempotency_key)
        if cached is not None:
            cached["idempotent_replay"] = True
            return cached

    for alert in body.alerts:
        enriched = dict(alert)
        enriched.setdefault("source_id", source_id)
        enriched.setdefault("session_id", session_id)
        push_proxy_alert(enriched)

    if body.summary:
        summary = dict(body.summary)
        summary.setdefault("source_id", source_id)
        summary.setdefault("session_id", session_id)
        push_proxy_metrics(summary)

    log_action(
        "proxy.audit_ingested",
        actor=actor,
        resource=f"proxy/{source_id}",
        session_id=session_id,
        alert_count=len(body.alerts),
        has_summary=body.summary is not None,
    )
    response = {
        "ingested": True,
        "source_id": source_id,
        "session_id": session_id,
        "alert_count": len(body.alerts),
        "has_summary": body.summary is not None,
    }
    if body.idempotency_key:
        _get_idempotency_store().put("/v1/proxy/audit", tenant_id, source_id, body.idempotency_key, response)
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
                        alerts.append(record)
                except (ValueError, KeyError):
                    continue
    except OSError:
        pass
    return alerts


def _load_proxy_alerts() -> list[dict]:
    """Return in-memory alerts, or fall back to the configured audit log."""
    log_path = _get_configured_log_path()
    if log_path and not _proxy_alerts:
        return _read_alerts_from_log(log_path)
    return list(_proxy_alerts)


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


def _read_metrics_from_log(path: _Path) -> dict | None:
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
                    if record.get("type") == "proxy_summary":
                        last_summary = record
                except (ValueError, KeyError):
                    continue
    except OSError:
        pass
    return last_summary


# ── HTTP endpoints ───────────────────────────────────────────────────────────


@router.get("/v1/proxy/status", tags=["proxy"])
async def proxy_status() -> dict:
    """Get runtime proxy metrics.

    Returns the latest proxy metrics summary.  Reads from the in-process
    buffer (populated by ``push_proxy_metrics``) or from the audit log
    configured via the ``AGENT_BOM_LOG`` environment variable.
    """
    metrics: dict | None = None
    if _proxy_metrics is not None:
        metrics = dict(_proxy_metrics)
    else:
        log_path = _get_configured_log_path()
        if log_path:
            metrics = _read_metrics_from_log(log_path)
            if metrics is not None:
                metrics = dict(metrics)

    if metrics is not None:
        alert_summary = _summarize_proxy_alerts(_load_proxy_alerts())
        metrics["alert_summary"] = {key: value for key, value in alert_summary.items() if key != "recent_alerts"}
        metrics["recent_alerts"] = alert_summary["recent_alerts"]
        return metrics

    return {
        "status": "no_proxy_session",
        "message": "No proxy metrics available. Start a proxy session or set AGENT_BOM_LOG.",
    }


@router.get("/v1/proxy/alerts", tags=["proxy"])
async def proxy_alerts(
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
    alerts = _load_proxy_alerts()

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


def _ws_check_auth(websocket: WebSocket) -> bool:
    """Return True if the WebSocket connection is authorized.

    When ``AGENT_BOM_API_KEY`` is set, callers must pass ``?token=<key>`` in
    the WebSocket URL.  When the env var is unset the endpoint is open (local
    dev / single-user mode).
    """
    import os as _os

    api_key = _os.environ.get("AGENT_BOM_API_KEY")
    if not api_key:
        return True  # no auth configured — open
    token = websocket.query_params.get("token", "")
    import hmac as _hmac

    return bool(token and _hmac.compare_digest(token, api_key))


@router.websocket("/ws/proxy/metrics")
async def ws_proxy_metrics(websocket: WebSocket) -> None:
    """WebSocket endpoint — push proxy metrics every second.

    Connect to ``ws://localhost:8422/ws/proxy/metrics`` to receive a live
    stream of proxy metrics as JSON objects.  Useful for building real-time
    dashboards without polling.

    Authentication: pass ``?token=<AGENT_BOM_API_KEY>`` when the env var is set.

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

    if not _ws_check_auth(websocket):
        await websocket.close(code=4001)
        return

    await websocket.accept()
    try:
        while True:
            now = _time.time()
            # Build snapshot from in-process metrics buffer
            metrics_snapshot: dict = {}
            if _proxy_metrics is not None:
                metrics_snapshot = dict(_proxy_metrics)
            else:
                log_path = _get_configured_log_path()
                if log_path:
                    m = _read_metrics_from_log(log_path)
                    if m:
                        metrics_snapshot = m

            # Count alerts in last 60 seconds
            cutoff = now - 60
            recent_alerts = [a for a in _proxy_alerts if a.get("ts", 0) > cutoff]

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


@router.websocket("/ws/proxy/alerts")
async def ws_proxy_alerts(websocket: WebSocket) -> None:
    """WebSocket endpoint — push new proxy alerts as they arrive.

    Streams new alerts in real time.  Each message is a single alert object.
    Useful for live security dashboards that need immediate notification.

    Authentication: pass ``?token=<AGENT_BOM_API_KEY>`` when the env var is set.

    Uses a monotonic total counter (not deque length) to detect new alerts
    correctly even when old entries are evicted from the 1000-entry ring buffer.
    """
    import asyncio

    try:
        from fastapi.websockets import WebSocketDisconnect
    except ImportError:
        from starlette.websockets import WebSocketDisconnect  # type: ignore[no-reattr]

    if not _ws_check_auth(websocket):
        await websocket.close(code=4001)
        return

    await websocket.accept()
    seen = _proxy_alerts_total  # monotonic — tracks absolute count, not deque position
    try:
        while True:
            current = _proxy_alerts_total
            if current > seen:
                new_count = min(current - seen, len(_proxy_alerts))
                for alert in list(_proxy_alerts)[-new_count:]:
                    await websocket.send_json(alert)
                seen = current
            await asyncio.sleep(0.25)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        pass


# ── Shield / Deep Defense endpoints ──────────────────────────────────────────

# Per-session protection engines keyed by session_id.
# Zero trust: each session gets its own engine — one session's CRITICAL
# threat cannot block another session's tool calls.
_shield_engines: dict[str, ProtectionEngine] = {}
_MAX_SHIELD_SESSIONS = 64  # bound memory; evict oldest idle session


def _get_engine(session_id: str) -> ProtectionEngine | None:
    return _shield_engines.get(session_id)


@router.post("/v1/shield/start", tags=["shield"])
async def shield_start(session_id: str = "default", correlation_window: float = 30.0) -> dict:
    """Start the deep defense protection engine for a session.

    Each session_id gets an isolated engine — zero trust, no cross-session
    threat contamination.

    Query params:
        session_id: Session identifier (default "default").
        correlation_window: Alert correlation window in seconds (default 30).
    """
    from agent_bom.alerts.dispatcher import AlertDispatcher
    from agent_bom.runtime.protection import ProtectionEngine

    existing = _get_engine(session_id)
    if existing is not None and existing.active:
        return {
            "status": "already_active",
            "session_id": session_id,
            **existing.status(),
        }

    # Evict oldest idle session if at capacity
    if len(_shield_engines) >= _MAX_SHIELD_SESSIONS:
        idle = next(
            (sid for sid, eng in _shield_engines.items() if not eng.active),
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
    _shield_engines[session_id] = engine
    return {"status": "started", "session_id": session_id, **engine.status()}


@router.get("/v1/shield/status", tags=["shield"])
async def shield_status(session_id: str = "default") -> dict:
    """Get current shield threat assessment for a session."""
    engine = _get_engine(session_id)
    if engine is None or not engine.active:
        return {
            "active": False,
            "session_id": session_id,
            "message": "Shield not started. POST /v1/shield/start to activate.",
        }

    assessment = engine.assess_threat()
    return {
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


@router.post("/v1/shield/unblock", tags=["shield"])
async def shield_unblock(session_id: str = "default") -> dict:
    """Deactivate kill-switch for a session and reset to ELEVATED."""
    engine = _get_engine(session_id)
    if engine is None or not engine.active:
        return {"status": "not_active", "session_id": session_id}

    if not engine.is_blocked:
        return {"status": "not_blocked", "session_id": session_id}

    engine.unblock()
    return {"status": "unblocked", "session_id": session_id, **engine.status()}


@router.post("/v1/shield/break-glass", tags=["shield"])
async def break_glass(request: Request, session_id: str = "default", reason: str = "") -> dict:
    """Emergency kill-switch override — admin only, audit logged.

    Immediately unblocks all sessions and logs the override for compliance.
    Requires ``admin`` role (set via ``request.state.api_key_role``).
    """
    role = getattr(request.state, "api_key_role", "viewer")
    if role != "admin":
        raise HTTPException(status_code=403, detail="Break-glass requires admin role")

    engine = _get_engine(session_id)
    if engine is None or not engine.active:
        return {"status": "not_active", "session_id": session_id}

    was_blocked = engine.is_blocked
    if was_blocked:
        engine.unblock()

    # Audit log the break-glass event
    try:
        from agent_bom.api.audit_log import log_action

        log_action(
            "break_glass",
            actor=role,
            resource=f"shield/{session_id}",
            reason=reason,
            was_blocked=was_blocked,
        )
    except Exception:  # noqa: BLE001
        pass  # audit log failure must not block emergency override

    return {
        "status": "break_glass_activated",
        "session_id": session_id,
        "was_blocked": was_blocked,
        "reason": reason,
        **engine.status(),
    }
