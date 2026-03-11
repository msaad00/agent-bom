"""Proxy status, alerts, and WebSocket streaming endpoints."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket

import agent_bom.api.stores as _stores
from agent_bom.api.stores import (
    _get_configured_log_path,
    _read_alerts_from_log,
    _read_metrics_from_log,
)

router = APIRouter()
_logger = logging.getLogger(__name__)


@router.get("/v1/proxy/status", tags=["proxy"])
async def proxy_status() -> dict:
    """Get runtime proxy metrics."""
    if _stores._proxy_metrics is not None:
        return _stores._proxy_metrics

    log_path = _get_configured_log_path()
    if log_path:
        metrics = _read_metrics_from_log(log_path)
        if metrics is not None:
            return metrics

    return {
        "status": "no_proxy_session",
        "message": "No proxy metrics available. Start a proxy session or set AGENT_BOM_LOG.",
    }


@router.get("/v1/proxy/alerts", tags=["proxy"])
async def proxy_alerts(
    severity: str | None = None,
    detector: str | None = None,
    limit: int = 100,
) -> dict:
    """Get recent runtime proxy alerts."""
    log_path = _get_configured_log_path()
    if log_path and not _stores._proxy_alerts:
        alerts = _read_alerts_from_log(log_path)
    else:
        alerts = list(_stores._proxy_alerts)

    if severity:
        alerts = [a for a in alerts if a.get("severity", "").lower() == severity.lower()]
    if detector:
        alerts = [a for a in alerts if a.get("detector", "").lower() == detector.lower()]

    alerts = alerts[-limit:][::-1]

    return {
        "alerts": alerts,
        "count": len(alerts),
        "filters": {
            "severity": severity,
            "detector": detector,
            "limit": limit,
        },
    }


# ─── WebSocket helpers ───────────────────────────────────────────────────────


def _ws_check_auth(websocket: WebSocket) -> bool:
    """Return True if the WebSocket connection is authorized."""
    import os as _os

    api_key = _os.environ.get("AGENT_BOM_API_KEY")
    if not api_key:
        return True
    token = websocket.query_params.get("token", "")
    return bool(token and token == api_key)


@router.websocket("/ws/proxy/metrics")
async def ws_proxy_metrics(websocket: WebSocket) -> None:
    """WebSocket endpoint — push proxy metrics every second."""
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
            metrics_snapshot: dict = {}
            if _stores._proxy_metrics is not None:
                metrics_snapshot = dict(_stores._proxy_metrics)
            else:
                log_path = _get_configured_log_path()
                if log_path:
                    m = _read_metrics_from_log(log_path)
                    if m:
                        metrics_snapshot = m

            cutoff = now - 60
            recent_alerts = [a for a in _stores._proxy_alerts if a.get("ts", 0) > cutoff]

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
        pass


@router.websocket("/ws/proxy/alerts")
async def ws_proxy_alerts(websocket: WebSocket) -> None:
    """WebSocket endpoint — push new proxy alerts as they arrive."""
    try:
        from fastapi.websockets import WebSocketDisconnect
    except ImportError:
        from starlette.websockets import WebSocketDisconnect  # type: ignore[no-reattr]

    if not _ws_check_auth(websocket):
        await websocket.close(code=4001)
        return

    await websocket.accept()
    seen = _stores._proxy_alerts_total
    try:
        while True:
            current = _stores._proxy_alerts_total
            if current > seen:
                new_count = min(current - seen, len(_stores._proxy_alerts))
                for alert in list(_stores._proxy_alerts)[-new_count:]:
                    await websocket.send_json(alert)
                seen = current
            await asyncio.sleep(0.25)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        pass
