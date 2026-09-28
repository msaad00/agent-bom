"""Authorized gateway forwarding, response policy and completion auditing.

Tool execution fails closed when durable admission is unavailable. Once an
upstream outcome exists, audit delivery failure marks it degraded rather than
turning it into an ambiguous retryable 500. Response policy ordering is retained.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from fastapi import HTTPException
from fastapi.responses import JSONResponse

from agent_bom.api.gateway_request import _strip_gateway_identity_metadata
from agent_bom.api.metrics import record_gateway_relay
from agent_bom.api.tracing import inject_trace_headers
from agent_bom.gateway_upstreams import UpstreamConfig
from agent_bom.langfuse_otel import set_langfuse_runtime_attributes
from agent_bom.proxy import extract_tool_name, is_tools_call
from agent_bom.proxy_scanner import ScanConfig, ScanResult
from agent_bom.runtime.gateway_contracts import AuditSink, GatewayAuditDeliveryUnavailableError, UpstreamCaller
from agent_bom.runtime.gateway_events import GatewayRuntimeEventType
from agent_bom.runtime.gateway_relay import GatewayCircuitOpenError
from agent_bom.runtime.trace_metadata import inject_jsonrpc_trace_meta

logger = logging.getLogger(__name__)


class RuntimeEventBuilder(Protocol):
    def __call__(
        self,
        event_type: GatewayRuntimeEventType,
        *,
        decision: str,
        policy_source: str,
        tool: str,
        data_action: str = "",
    ) -> dict[str, Any]: ...


class AuditUnavailableResponse(Protocol):
    def __call__(self, message_id: object, *, headers: dict[str, str] | None = None) -> JSONResponse: ...


@dataclass(frozen=True)
class GatewayForwardContext:
    """Only the authorized request and adapters needed by the forwarding stage."""

    upstream: UpstreamConfig
    message: dict[str, Any]
    tenant_id: str
    source_agent: str
    resolved_policy_source: str
    rate_limit_headers: dict[str, str]
    trace_meta: dict[str, str | bool | None]
    audit_sink: AuditSink | None
    upstream_caller: UpstreamCaller
    runtime_event: RuntimeEventBuilder
    audit_unavailable: AuditUnavailableResponse
    public_error: Callable[[Exception | str], str]
    block_reason: Callable[[str], str]
    visual_enabled: bool
    visual_detector: Callable[[], Any]
    dlp_config: ScanConfig
    response_scanner: Callable[[dict, ScanConfig], tuple[dict, list[ScanResult]]]
    tracer: Any


@dataclass
class CompletionAudit:
    """Request-local delivery status cannot leak into another response."""

    context: GatewayForwardContext
    degraded: bool = False

    async def emit(self, event: dict[str, Any]) -> None:
        if self.context.audit_sink is None:
            return
        try:
            await self.context.audit_sink(event)
        except Exception as exc:  # noqa: BLE001 - preserve an already produced outcome
            self.degraded = True
            record_gateway_relay(self.context.upstream.name, "audit_unavailable")
            logger.error("Gateway post-forward audit degraded (error_type=%s)", type(exc).__name__)

    def headers(self, headers: dict[str, str]) -> dict[str, str]:
        if self.degraded:
            headers["X-Agent-BOM-Audit-Delivery"] = "degraded"
        return headers


async def _admit_tool_execution(context: GatewayForwardContext) -> JSONResponse | None:
    if is_tools_call(context.message) and context.audit_sink is None:
        record_gateway_relay(context.upstream.name, "audit_unavailable")
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": context.message.get("id"),
                "error": {
                    "code": -32003,
                    "message": "Gateway audit persistence unavailable",
                    "data": {
                        "reason": "Tool call was not executed because no durable audit sink is configured",
                        "policy_source": "audit_delivery",
                    },
                },
            },
            status_code=503,
            headers=context.rate_limit_headers or None,
        )
    if is_tools_call(context.message) and context.audit_sink is not None:
        try:
            admission = getattr(context.audit_sink, "admit_before_tool_execution", context.audit_sink)
            await admission(
                {
                    "action": "gateway.tool_call",
                    "upstream": context.upstream.name,
                    "tenant_id": context.tenant_id,
                    "method": context.message.get("method"),
                    "tool": extract_tool_name(context.message),
                    "source_agent": context.source_agent,
                    **context.runtime_event(
                        GatewayRuntimeEventType.TOOL_CALL_ALLOWED,
                        decision="allow",
                        policy_source=context.resolved_policy_source,
                        tool=extract_tool_name(context.message) or "",
                    ),
                }
            )
        except GatewayAuditDeliveryUnavailableError:
            record_gateway_relay(context.upstream.name, "audit_unavailable")
            return context.audit_unavailable(context.message.get("id"), headers=context.rate_limit_headers or None)

    return None


def _trace_request(context: GatewayForwardContext) -> tuple[dict[str, str], dict[str, Any]]:
    extra_headers = inject_trace_headers(
        {},
        traceparent=str(context.trace_meta["traceparent"]),
        tracestate=str(context.trace_meta["tracestate"]) if context.trace_meta["tracestate"] else None,
        baggage=str(context.trace_meta["baggage"]) if context.trace_meta["baggage"] else None,
    )
    forwarded_message = inject_jsonrpc_trace_meta(
        _strip_gateway_identity_metadata(context.message),
        traceparent=str(context.trace_meta["traceparent"]),
        tracestate=str(context.trace_meta["tracestate"]) if context.trace_meta["tracestate"] else None,
        baggage=str(context.trace_meta["baggage"]) if context.trace_meta["baggage"] else None,
    )
    return extra_headers, forwarded_message


def _annotate_span(context: GatewayForwardContext, span: Any) -> None:
    span.set_attribute("agent_bom.gateway.upstream", context.upstream.name)
    span.set_attribute("agent_bom.gateway.tenant_id", context.tenant_id)
    span.set_attribute("agent_bom.gateway.method", str(context.message.get("method", "unknown")))
    span.set_attribute("agent_bom.gateway.trace_id", str(context.trace_meta["trace_id"]))
    span.set_attribute("agent_bom.gateway.span_id", str(context.trace_meta["span_id"]))
    span.set_attribute("agent_bom.gateway.incoming_traceparent", bool(context.trace_meta["incoming_traceparent"]))
    if context.trace_meta["parent_span_id"]:
        span.set_attribute("agent_bom.gateway.parent_span_id", str(context.trace_meta["parent_span_id"]))
    if context.trace_meta["tracestate"]:
        span.set_attribute("agent_bom.gateway.tracestate_present", True)
    if context.trace_meta["baggage"]:
        span.set_attribute("agent_bom.gateway.baggage_present", True)
    set_langfuse_runtime_attributes(
        span,
        surface="gateway",
        tenant_id=context.tenant_id,
        method=str(context.message.get("method", "unknown")),
        tool_name=context.message.get("params", {}).get("name") if is_tools_call(context.message) else None,
        decision="allowed",
        upstream=context.upstream.name,
        trace_id=str(context.trace_meta["trace_id"]),
    )


async def _call_upstream(context: GatewayForwardContext, audit: CompletionAudit) -> dict[str, Any]:
    extra_headers, forwarded_message = _trace_request(context)
    span_cm = context.tracer.start_as_current_span("gateway.relay_upstream") if context.tracer else nullcontext()
    try:
        with span_cm as span:
            if span is not None:
                _annotate_span(context, span)
            upstream_response = await context.upstream_caller(context.upstream, forwarded_message, extra_headers)
    except GatewayCircuitOpenError as exc:
        logger.warning("gateway upstream circuit open for %s", context.upstream.name)
        record_gateway_relay(context.upstream.name, "circuit_open")
        retry_after_header = str(int(exc.retry_after_seconds))
        await audit.emit(
            {
                "action": "gateway.upstream_circuit_open",
                "upstream": context.upstream.name,
                "tenant_id": context.tenant_id,
                "reason": "circuit_open",
                "retry_after_seconds": int(exc.retry_after_seconds),
            }
        )
        raise HTTPException(
            status_code=503,
            detail="upstream circuit open",
            headers=audit.headers({"Retry-After": retry_after_header}),
        ) from exc
    except asyncio.TimeoutError as exc:
        logger.warning("gateway upstream call timed out for %s", context.upstream.name)
        record_gateway_relay(context.upstream.name, "upstream_timeout")
        await audit.emit(
            {
                "action": "gateway.upstream_error",
                "upstream": context.upstream.name,
                "tenant_id": context.tenant_id,
                "error": "timeout",
                "reason": "timeout",
            }
        )
        raise HTTPException(
            status_code=502,
            detail="upstream error: timeout",
            headers=audit.headers({}),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        logger.error("gateway upstream call failed for %s", context.upstream.name)
        record_gateway_relay(context.upstream.name, "upstream_error")
        await audit.emit(
            {
                "action": "gateway.upstream_error",
                "upstream": context.upstream.name,
                "tenant_id": context.tenant_id,
                "error": context.public_error(exc),
            }
        )
        raise HTTPException(
            status_code=502,
            detail=f"upstream error: {context.public_error(exc)}",
            headers=audit.headers({}),
        ) from exc

    return upstream_response


async def _visual_result_unavailable(context: GatewayForwardContext, audit: CompletionAudit, tool: str, reason: str) -> JSONResponse:
    record_gateway_relay(context.upstream.name, "visual_scan_unavailable")
    logger.warning("Gateway visual result withheld (reason=%s)", reason)
    await audit.emit(
        {
            "action": "gateway.visual_scan_unavailable",
            "upstream": context.upstream.name,
            "tenant_id": context.tenant_id,
            "reason": reason,
            "scan_status": "incomplete",
            "execution_status": "upstream_completed",
            **context.runtime_event(
                GatewayRuntimeEventType.DLP_RESULT_BLOCKED,
                decision="deny",
                policy_source="visual_dlp",
                tool=tool,
                data_action="unverified_result_withheld",
            ),
        }
    )
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": context.message.get("id"),
            "error": {
                "code": -32001,
                "message": (
                    "Tool result withheld because visual screening could not complete; do not automatically retry the completed tool call"
                ),
                "data": {
                    "policy_source": "visual_dlp",
                    "reason": reason,
                    "scan_status": "incomplete",
                    "execution_status": "upstream_completed",
                    "retryable": False,
                },
            },
        },
        headers=audit.headers(dict(context.rate_limit_headers)) or None,
    )


async def _apply_visual_policy(
    context: GatewayForwardContext, audit: CompletionAudit, upstream_response: dict[str, Any]
) -> JSONResponse | None:
    if not context.visual_enabled or not isinstance(upstream_response, dict):
        return None
    result = upstream_response.get("result")
    content = result.get("content") if isinstance(result, dict) else None
    if not isinstance(result, dict) or not isinstance(content, list) or not content:
        return None
    tool = str(extract_tool_name(context.message) or context.message.get("method", ""))
    from agent_bom.runtime.visual_leak_detector import run_visual_leak_check, run_visual_leak_redact

    try:
        detector = context.visual_detector()
        alerts = await run_visual_leak_check(detector, tool, content)
        if not alerts:
            return None
        # Success is recorded only after the replacement content exists.
        result["content"] = await run_visual_leak_redact(detector, content)
    except asyncio.TimeoutError:
        return await _visual_result_unavailable(context, audit, tool, "visual_scan_timeout")
    except Exception:  # noqa: BLE001 - fail closed after an already completed tool call
        return await _visual_result_unavailable(context, audit, tool, "visual_scan_failed")
    record_gateway_relay(context.upstream.name, "visual_leak_redacted")
    await audit.emit(
        {
            "action": "gateway.visual_leak_blocked",
            "upstream": context.upstream.name,
            "tenant_id": context.tenant_id,
            "tool": tool,
            "alert_count": len(alerts),
            "leak_types": sorted({a.details.get("leak_type", "") for a in alerts}),
            **context.runtime_event(
                GatewayRuntimeEventType.VISUAL_REDACTED,
                decision="allow",
                policy_source="visual_dlp",
                tool=tool,
                data_action="visual_redacted",
            ),
        }
    )
    return None


async def _apply_response_policy(
    context: GatewayForwardContext,
    audit: CompletionAudit,
    upstream_response: dict[str, Any],
) -> dict[str, Any] | JSONResponse:
    if context.dlp_config.enabled and isinstance(upstream_response, dict):
        tool_name_for_dlp = (
            context.message.get("params", {}).get("name", "") if is_tools_call(context.message) else str(context.message.get("method", ""))
        )
        safe_response, resp_findings = context.response_scanner(upstream_response, context.dlp_config)
        safe_error = safe_response.get("error")
        result_blocked = isinstance(safe_error, dict) and safe_error.get("code") == -32600 and safe_response != upstream_response
        result_redacted = safe_response != upstream_response and not result_blocked
        if resp_findings and context.audit_sink is not None:
            typed_result_event: dict[str, Any] = {}
            if result_blocked:
                typed_result_event = context.runtime_event(
                    GatewayRuntimeEventType.DLP_RESULT_BLOCKED,
                    decision="deny",
                    policy_source="dlp",
                    tool=str(tool_name_for_dlp),
                    data_action="sensitive_result_blocked",
                )
            elif result_redacted:
                typed_result_event = context.runtime_event(
                    GatewayRuntimeEventType.DLP_RESULT_REDACTED,
                    decision="allow",
                    policy_source="dlp",
                    tool=str(tool_name_for_dlp),
                    data_action="pii_redacted",
                )
            await audit.emit(
                {
                    "action": "gateway.dlp_result",
                    "upstream": context.upstream.name,
                    "tenant_id": context.tenant_id,
                    "source_agent": context.source_agent,
                    "tool": tool_name_for_dlp,
                    "findings": sorted({f"{f.scanner}/{f.rule_id}" for f in resp_findings}),
                    "blocked": result_blocked,
                    **typed_result_event,
                }
            )
        if result_blocked:
            record_gateway_relay(context.upstream.name, "blocked")
            first = next((f for f in resp_findings if f.blocked), resp_findings[0])
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": context.message.get("id"),
                    "error": {
                        "code": -32001,
                        "message": "Blocked by agent-bom gateway DLP: sensitive data in tool result",
                        "data": {
                            "reason": context.block_reason("dlp"),
                            "policy_source": "dlp",
                            "rule": f"{first.scanner}/{first.rule_id}",
                        },
                    },
                },
                status_code=200,
                headers=audit.headers(dict(context.rate_limit_headers)) or None,
            )
        upstream_response = safe_response

    return upstream_response


async def forward_authorized_request(context: GatewayForwardContext) -> JSONResponse:
    """Admit before effects, then retain the outcome through response policies."""
    admission_failure = await _admit_tool_execution(context)
    if admission_failure is not None:
        return admission_failure
    audit = CompletionAudit(context)
    upstream_response = await _call_upstream(context, audit)
    record_gateway_relay(context.upstream.name, "forwarded")
    visual_failure = await _apply_visual_policy(context, audit, upstream_response)
    if visual_failure is not None:
        return visual_failure
    response = await _apply_response_policy(context, audit, upstream_response)
    if isinstance(response, JSONResponse):
        return response
    upstream_response = response
    if context.audit_sink is not None and not is_tools_call(context.message):
        forward_audit_event: dict[str, Any] = {
            "action": "gateway.message",
            "upstream": context.upstream.name,
            "tenant_id": context.tenant_id,
            "method": context.message.get("method"),
            "tool": None,
        }
        await audit.emit(forward_audit_event)
    response_headers = dict(context.rate_limit_headers)
    response_headers["traceparent"] = str(context.trace_meta["traceparent"])
    if context.trace_meta["tracestate"]:
        response_headers["tracestate"] = str(context.trace_meta["tracestate"])
    if context.trace_meta["baggage"]:
        response_headers["baggage"] = str(context.trace_meta["baggage"])
    audit.headers(response_headers)
    return JSONResponse(upstream_response, headers=response_headers or None)
