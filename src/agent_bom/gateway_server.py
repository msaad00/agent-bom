"""Multi-MCP gateway server (`agent-bom gateway serve`).

One FastAPI service that fronts N upstream MCP servers, applies policy
inline on every JSON-RPC request, and logs every call into the audit
trail. Laptops point at one URL (``/mcp/{server-name}``) instead of
configuring a proxy per MCP.

Design doc: docs/design/MULTI_MCP_GATEWAY.md.

MVP scope:
  * Request/response relay over HTTP (POST). Streamable-HTTP transport
    with bidirectional streaming is a v2 addition — the MVP handles
    the dominant case (``tools/call``, ``tools/list``) where the client
    expects one response per request.
  * Policy evaluation via ``agent_bom.proxy.check_policy`` (reused —
    no new policy engine).
  * Audit events emitted via a caller-supplied sink; in-cluster deploys
    point it at ``/v1/proxy/audit``.
  * Per-upstream static header / bearer auth injection from
    ``UpstreamRegistry``.

Non-goals for MVP (see design doc):
  * stdio upstreams (per-MCP ``agent-bom proxy`` wrapper still handles these)
  * OAuth2 client-credentials token refresh
  * SSE long-poll / Streamable HTTP streaming
"""

from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from agent_bom.api.metrics import record_gateway_relay
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.proxy import check_policy, is_tools_call, parse_jsonrpc

logger = logging.getLogger(__name__)

AuditSink = Callable[[dict[str, Any]], Awaitable[None]]
UpstreamCaller = Callable[[UpstreamConfig, dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]]

# Lazy singleton so disabled deploys don't pay the import cost of the
# visual detector (Pillow/pytesseract). Built on first use when
# ``enable_visual_leak_detection`` is True.
_visual_detector_singleton: Any = None
_visual_detector_lock = threading.Lock()


def _sanitize_for_log(value: Any) -> str:
    """Return a single-line representation safe for plain-text logs."""
    return str(value).replace("\r", "").replace("\n", "")


def _get_visual_leak_detector() -> Any:
    global _visual_detector_singleton
    if _visual_detector_singleton is None:
        with _visual_detector_lock:
            if _visual_detector_singleton is None:
                from agent_bom.runtime.visual_leak_detector import VisualLeakDetector

                _visual_detector_singleton = VisualLeakDetector()
    return _visual_detector_singleton


@dataclass
class GatewaySettings:
    """Runtime configuration the caller wires in."""

    registry: UpstreamRegistry
    policy: dict[str, Any]  # dict passed to check_policy — same shape proxy uses
    audit_sink: AuditSink | None = None
    upstream_caller: UpstreamCaller | None = None  # injectable for tests
    bearer_token: str | None = None
    # Visual-leak detection on image tool responses (closes the screenshot
    # channel that CredentialLeakDetector can't see — #1568). Opt-in
    # because OCR is CPU-heavy; see docs/ENTERPRISE_SECURITY_PLAYBOOK.md §2.2.
    # Set to True AND install `agent-bom[visual]` to enable.
    enable_visual_leak_detection: bool = False
    require_visual_leak_detection_ready: bool = False


def _request_has_expected_token(request: Request, expected_token: str) -> bool:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :].strip() == expected_token
    return request.headers.get("x-api-key", "").strip() == expected_token


async def _default_upstream_caller(
    upstream: UpstreamConfig,
    message: dict[str, Any],
    extra_headers: dict[str, str],
) -> dict[str, Any]:
    """Forward a JSON-RPC message to an upstream MCP server via HTTP POST.

    Resolves per-upstream auth (bearer + OAuth2 client-credentials) via
    ``upstream.resolve_auth_headers`` so OAuth tokens are fetched + cached
    correctly instead of failing at send time.
    """
    import httpx

    auth_headers = await upstream.resolve_auth_headers()
    headers = {"Content-Type": "application/json", **auth_headers, **extra_headers}
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(upstream.url, json=message, headers=headers)
        response.raise_for_status()
        if response.headers.get("content-type", "").startswith("application/json"):
            return response.json()
        # Some upstreams return text/event-stream; MVP treats non-JSON as an opaque
        # body wrapped in a success envelope so policy + audit still fire.
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"raw": response.text}}


def create_gateway_app(settings: GatewaySettings) -> FastAPI:
    """Build the FastAPI app for `agent-bom gateway serve`.

    Separating app construction from CLI entry point keeps the server
    testable end-to-end via ``TestClient(create_gateway_app(settings))``.
    """
    if settings.enable_visual_leak_detection and settings.require_visual_leak_detection_ready:
        from agent_bom.runtime.visual_leak_detector import require_visual_leak_runtime

        require_visual_leak_runtime()

    app = FastAPI(title="agent-bom gateway", version="1")
    upstream_caller = settings.upstream_caller or _default_upstream_caller

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        health: dict[str, Any] = {
            "status": "ok",
            "upstreams": settings.registry.names(),
            "auth": {"incoming_token_required": bool(settings.bearer_token)},
        }
        if settings.enable_visual_leak_detection:
            from agent_bom.runtime.visual_leak_detector import visual_leak_runtime_health

            health["visual_leak_detection"] = {
                **visual_leak_runtime_health(),
                "required": settings.require_visual_leak_detection_ready,
            }
        return health

    @app.get("/metrics")
    async def metrics() -> Response:
        # Prometheus text-exposition format must be plain text, not JSON.
        # Previous JSONResponse wrapped the body in quotes + escaped newlines,
        # which breaks every Prometheus scraper. Serve as `Response` with the
        # exposition media type so scrapers parse it.
        from agent_bom.api.metrics import render_prometheus_lines

        body = "\n".join(render_prometheus_lines()) + "\n"
        return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")

    @app.post("/mcp/{server_name}")
    async def relay(server_name: str, request: Request) -> JSONResponse:
        """Route an MCP JSON-RPC request to the named upstream after policy + audit."""
        if settings.bearer_token and not _request_has_expected_token(request, settings.bearer_token):
            raise HTTPException(status_code=401, detail="gateway authentication required")

        upstream = settings.registry.get(server_name)
        if upstream is None:
            raise HTTPException(
                status_code=404,
                detail=f"unknown upstream {server_name!r}; known: {', '.join(settings.registry.names()) or '(none)'}",
            )

        try:
            body = await request.json()
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"body is not valid JSON: {exc}") from exc

        # Parse the JSON-RPC envelope so check_policy sees the real message shape.
        if isinstance(body, dict) and "jsonrpc" in body:
            message = body
        else:
            raise HTTPException(status_code=400, detail="request must be a JSON-RPC message")

        # Inline policy check — reuse the exact evaluator the per-MCP proxy uses.
        tenant_id = getattr(request.state, "tenant_id", None) or "default"
        if is_tools_call(message):
            params = message.get("params", {}) or {}
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {}) or {}
            allowed, reason = check_policy(settings.policy, tool_name, arguments)
            if not allowed:
                record_gateway_relay(upstream.name, "blocked")
                audit_event: dict[str, Any] = {
                    "action": "gateway.tool_call_blocked",
                    "upstream": upstream.name,
                    "tenant_id": tenant_id,
                    "tool": tool_name,
                    "reason": reason,
                }
                if settings.audit_sink is not None:
                    await settings.audit_sink(audit_event)
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32001,  # Application-defined error
                            "message": "Blocked by agent-bom gateway policy",
                            "data": {"reason": reason},
                        },
                    },
                    status_code=200,
                )

        # Forward to the upstream.
        extra_headers: dict[str, str] = {}
        try:
            upstream_response = await upstream_caller(upstream, message, extra_headers)
        except asyncio.TimeoutError as exc:
            logger.warning("gateway upstream call timed out for %s", upstream.name)
            record_gateway_relay(upstream.name, "upstream_timeout")
            if settings.audit_sink is not None:
                await settings.audit_sink(
                    {
                        "action": "gateway.upstream_error",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "error": "timeout",
                        "reason": "timeout",
                    }
                )
            raise HTTPException(status_code=502, detail="upstream error: timeout") from exc
        except Exception as exc:  # noqa: BLE001
            logger.exception("gateway upstream call failed for %s", upstream.name)
            record_gateway_relay(upstream.name, "upstream_error")
            if settings.audit_sink is not None:
                await settings.audit_sink(
                    {
                        "action": "gateway.upstream_error",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "error": str(exc),
                    }
                )
            raise HTTPException(status_code=502, detail=f"upstream error: {exc}") from exc

        record_gateway_relay(upstream.name, "forwarded")

        # Visual-leak detection on image tool responses. Opt-in because OCR
        # is CPU-heavy; startup can now require the OCR runtime so pilots
        # fail closed instead of silently skipping the screenshot channel.
        if settings.enable_visual_leak_detection and isinstance(upstream_response, dict):
            result = upstream_response.get("result")
            if isinstance(result, dict):
                content = result.get("content")
                if isinstance(content, list) and content:
                    detector = _get_visual_leak_detector()
                    tool_name_for_scan = message.get("params", {}).get("name", "") if is_tools_call(message) else message.get("method", "")
                    safe_tool_name_for_log = _sanitize_for_log(tool_name_for_scan)
                    from agent_bom.runtime.visual_leak_detector import run_visual_leak_check, run_visual_leak_redact

                    try:
                        alerts = await run_visual_leak_check(detector, tool_name_for_scan, content)
                    except asyncio.TimeoutError:
                        logger.warning(
                            "gateway visual leak scan timed out for upstream=%s tool=%s",
                            upstream.name,
                            safe_tool_name_for_log,
                        )
                        alerts = []
                    if alerts:
                        record_gateway_relay(upstream.name, "visual_leak_redacted")
                        if settings.audit_sink is not None:
                            await settings.audit_sink(
                                {
                                    "action": "gateway.visual_leak_blocked",
                                    "upstream": upstream.name,
                                    "tenant_id": tenant_id,
                                    "tool": tool_name_for_scan,
                                    "alert_count": len(alerts),
                                    "leak_types": sorted({a.details.get("leak_type", "") for a in alerts}),
                                }
                            )
                        try:
                            result["content"] = await run_visual_leak_redact(detector, content)
                        except asyncio.TimeoutError:
                            logger.warning(
                                "gateway visual leak redaction timed out for upstream=%s tool=%s",
                                upstream.name,
                                safe_tool_name_for_log,
                            )

        if settings.audit_sink is not None:
            await settings.audit_sink(
                {
                    "action": "gateway.tool_call" if is_tools_call(message) else "gateway.message",
                    "upstream": upstream.name,
                    "tenant_id": tenant_id,
                    "method": message.get("method"),
                    "tool": message.get("params", {}).get("name") if is_tools_call(message) else None,
                }
            )
        return JSONResponse(upstream_response)

    return app


# Re-export the parser for easier test authoring / CLI glue.
__all__ = [
    "GatewaySettings",
    "create_gateway_app",
    "parse_jsonrpc",
]
