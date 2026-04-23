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
import json
import logging
import os
import threading
import time
from contextlib import asynccontextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from agent_bom.api.auth import get_key_store
from agent_bom.api.metrics import record_gateway_relay, record_rate_limit_hit
from agent_bom.api.middleware import InMemoryRateLimitStore, PostgresRateLimitStore
from agent_bom.api.tracing import get_tracer, inject_trace_headers, make_request_trace
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.proxy import check_policy, is_tools_call, parse_jsonrpc

logger = logging.getLogger(__name__)
_GATEWAY_TRACER = get_tracer("agent_bom.gateway")

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
    runtime_rate_limit_per_tenant_per_minute: int = 0
    require_shared_rate_limit: bool = False
    policy_path: Path | None = None
    policy_reload_interval_seconds: int = 0


def _load_policy_file(policy_path: Path) -> dict[str, Any]:
    payload = json.loads(policy_path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("gateway policy file must contain a JSON object")
    return payload


def _gateway_configured_replicas() -> int:
    raw = os.environ.get("AGENT_BOM_GATEWAY_REPLICAS", "").strip()
    if not raw:
        return 1
    try:
        return max(1, int(raw))
    except ValueError:
        logger.warning("Invalid AGENT_BOM_GATEWAY_REPLICAS=%r; defaulting to 1", _sanitize_for_log(raw))
        return 1


def _gateway_shared_rate_limit_required(settings: GatewaySettings) -> bool:
    if settings.require_shared_rate_limit:
        return True
    return _gateway_configured_replicas() > 1


def _build_gateway_rate_limit_store(settings: GatewaySettings):
    if settings.runtime_rate_limit_per_tenant_per_minute <= 0:
        return None
    if os.environ.get("AGENT_BOM_POSTGRES_URL"):
        try:
            return PostgresRateLimitStore(window_seconds=60)
        except Exception as exc:
            raise RuntimeError(
                "Configured Postgres gateway rate limiter could not initialize; refusing to fall back to process-local state"
            ) from exc
    if _gateway_shared_rate_limit_required(settings):
        raise RuntimeError(
            "Shared gateway rate limiting is required for multi-replica or fail-closed deployments. "
            "Configure AGENT_BOM_POSTGRES_URL before starting the gateway."
        )
    return InMemoryRateLimitStore(window_seconds=60)


def _gateway_rate_limit_runtime_status(settings: GatewaySettings) -> dict[str, object]:
    postgres_configured = bool(os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip())
    replicas = _gateway_configured_replicas()
    enabled = settings.runtime_rate_limit_per_tenant_per_minute > 0
    shared_required = _gateway_shared_rate_limit_required(settings) if enabled else False
    backend = "disabled" if not enabled else ("postgres_shared" if postgres_configured else "inmemory_single_process")
    return {
        "enabled": enabled,
        "limit_per_tenant_per_minute": settings.runtime_rate_limit_per_tenant_per_minute,
        "backend": backend,
        "postgres_configured": postgres_configured,
        "configured_gateway_replicas": replicas,
        "shared_required": shared_required,
        "shared_across_replicas": enabled and postgres_configured,
        "fail_closed": (enabled and postgres_configured) or (enabled and shared_required),
        "message": (
            "Gateway runtime rate limiting disabled."
            if not enabled
            else (
                "Gateway runtime rate limiting uses Postgres-backed shared state across replicas."
                if postgres_configured
                else (
                    "Gateway runtime rate limiting is process-local because the gateway is configured "
                    "for a single replica. Multi-replica deployments must configure AGENT_BOM_POSTGRES_URL."
                )
            )
        ),
    }


def _request_has_expected_token(request: Request, expected_token: str) -> bool:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :].strip() == expected_token
    return request.headers.get("x-api-key", "").strip() == expected_token


def _extract_request_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :].strip()
    return request.headers.get("x-api-key", "").strip()


def _gateway_requires_auth(settings: GatewaySettings) -> bool:
    if settings.bearer_token:
        return True
    try:
        return get_key_store().has_keys()
    except Exception:
        return False


def _authenticate_gateway_request(request: Request, settings: GatewaySettings) -> tuple[str, str]:
    raw_token = _extract_request_token(request)
    if settings.bearer_token:
        if not raw_token or not _request_has_expected_token(request, settings.bearer_token):
            raise HTTPException(status_code=401, detail="gateway authentication required")
        return "default", "static_gateway_token"

    try:
        store = get_key_store()
        if store.has_keys():
            api_key = store.verify(raw_token) if raw_token else None
            if api_key is None:
                raise HTTPException(status_code=401, detail="gateway authentication required")
            return api_key.tenant_id or "default", "api_key"
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Gateway key verification unavailable: %s", _sanitize_for_log(exc))

    return "default", "none"


def _inject_jsonrpc_trace_meta(
    message: dict[str, Any],
    *,
    traceparent: str | None,
    tracestate: str | None,
    baggage: str | None,
) -> dict[str, Any]:
    """Return a JSON-RPC message with bounded W3C trace context in `_meta`.

    MCP clients and servers increasingly use `_meta` as the least-surprising
    place to carry end-to-end trace context across JSON-RPC boundaries.
    """
    if not traceparent and not tracestate and not baggage:
        return message

    enriched = dict(message)
    raw_meta = message.get("_meta")
    meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}
    if traceparent:
        meta["traceparent"] = traceparent
    if tracestate:
        meta["tracestate"] = tracestate
    if baggage:
        meta["baggage"] = baggage
    enriched["_meta"] = meta
    return enriched


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

    upstream_caller = settings.upstream_caller or _default_upstream_caller
    rate_limit_store = _build_gateway_rate_limit_store(settings)
    policy_state: dict[str, Any] = {
        "policy": dict(settings.policy),
        "source": str(settings.policy_path) if settings.policy_path else "inline",
        "last_loaded_at": None,
        "last_error": None,
        "last_mtime": None,
    }
    policy_lock = asyncio.Lock()
    reload_task: asyncio.Task[None] | None = None

    async def _reload_policy_if_changed(force: bool = False) -> bool:
        if settings.policy_path is None:
            return False

        async with policy_lock:
            try:
                stat = settings.policy_path.stat()
                mtime = stat.st_mtime
                if not force and policy_state["last_mtime"] == mtime:
                    return False
                next_policy = _load_policy_file(settings.policy_path)
            except FileNotFoundError as exc:
                policy_state["last_error"] = str(exc)
                logger.warning("gateway policy reload failed for %s: %s", settings.policy_path, _sanitize_for_log(exc))
                return False
            except Exception as exc:  # noqa: BLE001
                policy_state["last_error"] = str(exc)
                logger.warning("gateway policy reload failed for %s: %s", settings.policy_path, _sanitize_for_log(exc))
                return False

            policy_state["policy"] = next_policy
            policy_state["last_loaded_at"] = time.time()
            policy_state["last_error"] = None
            policy_state["last_mtime"] = mtime
        logger.info("gateway policy reloaded from %s", settings.policy_path)
        return True

    async def _policy_reload_loop() -> None:
        while True:
            await asyncio.sleep(max(settings.policy_reload_interval_seconds, 1))
            await _reload_policy_if_changed()

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        nonlocal reload_task
        try:
            if settings.policy_path is not None:
                await _reload_policy_if_changed(force=True)
                if settings.policy_reload_interval_seconds > 0:
                    reload_task = asyncio.create_task(_policy_reload_loop())
            yield
        finally:
            if reload_task is not None:
                reload_task.cancel()
                try:
                    await reload_task
                except asyncio.CancelledError:
                    pass
                reload_task = None

    app = FastAPI(title="agent-bom gateway", version="1", lifespan=_lifespan)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        async with policy_lock:
            policy_runtime = {
                "source": policy_state["source"],
                "reload_enabled": bool(settings.policy_path and settings.policy_reload_interval_seconds > 0),
                "reload_interval_seconds": settings.policy_reload_interval_seconds,
                "last_loaded_at": policy_state["last_loaded_at"],
                "last_error": policy_state["last_error"],
            }
        health: dict[str, Any] = {
            "status": "ok",
            "upstreams": settings.registry.names(),
            "auth": {"incoming_token_required": _gateway_requires_auth(settings)},
            "rate_limit_runtime": _gateway_rate_limit_runtime_status(settings),
            "policy_runtime": policy_runtime,
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
        trace_meta = make_request_trace(dict(request.headers))
        tenant_id = "default"
        auth_method = "none"
        if _gateway_requires_auth(settings):
            tenant_id, auth_method = _authenticate_gateway_request(request, settings)
            request.state.tenant_id = tenant_id
            request.state.auth_method = auth_method

        upstream = settings.registry.get(server_name, tenant_id=tenant_id)
        if upstream is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"unknown upstream {server_name!r} for tenant {tenant_id!r}; known: "
                    f"{', '.join(settings.registry.names(tenant_id=tenant_id)) or '(none)'}"
                ),
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
        rate_limit_headers: dict[str, str] = {}
        if rate_limit_store is not None:
            now = time.time()
            bucket = f"gateway:tenant:{tenant_id}"
            hit_count, reset_at = await asyncio.to_thread(rate_limit_store.hit, bucket, now)
            limit = settings.runtime_rate_limit_per_tenant_per_minute
            remaining = max(0, limit - hit_count)
            rate_limit_headers = {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(reset_at),
            }
            if hit_count > limit:
                retry_after = max(int(reset_at - now), 1)
                record_gateway_relay(upstream.name, "rate_limited")
                record_rate_limit_hit("gateway_tenant")
                if settings.audit_sink is not None:
                    await settings.audit_sink(
                        {
                            "action": "gateway.rate_limited",
                            "upstream": upstream.name,
                            "tenant_id": tenant_id,
                            "limit": limit,
                            "bucket": bucket,
                            "reason": "tenant_runtime_rate_limit",
                        }
                    )
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Gateway tenant rate limit exceeded"},
                    headers={
                        **rate_limit_headers,
                        "Retry-After": str(retry_after),
                    },
                )

        if is_tools_call(message):
            params = message.get("params", {}) or {}
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {}) or {}
            async with policy_lock:
                current_policy = dict(policy_state["policy"])
            allowed, reason = check_policy(current_policy, tool_name, arguments)
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
                    headers=rate_limit_headers or None,
                )

        # Forward to the upstream with bounded W3C trace headers and JSON-RPC
        # `_meta` so both HTTP-aware and JSON-RPC-aware upstreams can stitch
        # the same end-to-end trace.
        extra_headers = inject_trace_headers(
            {},
            traceparent=str(trace_meta["traceparent"]),
            tracestate=str(trace_meta["tracestate"]) if trace_meta["tracestate"] else None,
            baggage=str(trace_meta["baggage"]) if trace_meta["baggage"] else None,
        )
        forwarded_message = _inject_jsonrpc_trace_meta(
            message,
            traceparent=str(trace_meta["traceparent"]),
            tracestate=str(trace_meta["tracestate"]) if trace_meta["tracestate"] else None,
            baggage=str(trace_meta["baggage"]) if trace_meta["baggage"] else None,
        )
        span_cm = _GATEWAY_TRACER.start_as_current_span("gateway.relay_upstream") if _GATEWAY_TRACER else nullcontext()
        try:
            with span_cm as span:
                if span is not None:
                    span.set_attribute("agent_bom.gateway.upstream", upstream.name)
                    span.set_attribute("agent_bom.gateway.tenant_id", tenant_id)
                    span.set_attribute("agent_bom.gateway.method", str(message.get("method", "unknown")))
                    span.set_attribute("agent_bom.gateway.trace_id", str(trace_meta["trace_id"]))
                    span.set_attribute("agent_bom.gateway.span_id", str(trace_meta["span_id"]))
                    span.set_attribute("agent_bom.gateway.incoming_traceparent", bool(trace_meta["incoming_traceparent"]))
                    if trace_meta["parent_span_id"]:
                        span.set_attribute("agent_bom.gateway.parent_span_id", str(trace_meta["parent_span_id"]))
                    if trace_meta["tracestate"]:
                        span.set_attribute("agent_bom.gateway.tracestate_present", True)
                    if trace_meta["baggage"]:
                        span.set_attribute("agent_bom.gateway.baggage_present", True)
                upstream_response = await upstream_caller(upstream, forwarded_message, extra_headers)
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
        response_headers = dict(rate_limit_headers)
        response_headers["traceparent"] = str(trace_meta["traceparent"])
        if trace_meta["tracestate"]:
            response_headers["tracestate"] = str(trace_meta["tracestate"])
        if trace_meta["baggage"]:
            response_headers["baggage"] = str(trace_meta["baggage"])
        return JSONResponse(upstream_response, headers=response_headers or None)

    return app


# Re-export the parser for easier test authoring / CLI glue.
__all__ = [
    "GatewaySettings",
    "create_gateway_app",
    "parse_jsonrpc",
]
