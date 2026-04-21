"""API tracing helpers — W3C trace context plus optional OTLP export."""

from __future__ import annotations

import logging
import os
import re
import secrets
from typing import Any, TypedDict

from agent_bom import __version__

_logger = logging.getLogger(__name__)

_TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_otel_tracing_state = "unconfigured"
_MAX_TRACESTATE_BYTES = 512
_MAX_BAGGAGE_BYTES = 512


class TracingHealthSnapshot(TypedDict):
    w3c_trace_context: bool
    w3c_tracestate: bool
    w3c_baggage: bool
    otlp_export: str
    otlp_endpoint_configured: bool
    otlp_headers_configured: bool


def _random_trace_id() -> str:
    return secrets.token_hex(16)


def _random_span_id() -> str:
    return secrets.token_hex(8)


def parse_traceparent(header_value: str | None) -> dict[str, str] | None:
    """Parse a W3C traceparent header into stable parts."""
    if not header_value:
        return None
    match = _TRACEPARENT_RE.match(header_value.strip())
    if not match:
        return None
    trace_id, parent_span_id, trace_flags = match.groups()
    if trace_id == "0" * 32 or parent_span_id == "0" * 16:
        return None
    return {
        "trace_id": trace_id,
        "parent_span_id": parent_span_id,
        "trace_flags": trace_flags,
    }


def build_traceparent(trace_id: str, span_id: str, trace_flags: str = "01") -> str:
    """Build a W3C traceparent header value."""
    return f"00-{trace_id}-{span_id}-{trace_flags}"


def parse_tracestate(header_value: str | None) -> str | None:
    """Return a normalized tracestate value when present and bounded."""
    if not header_value:
        return None
    value = header_value.strip()
    if not value:
        return None
    return value[:_MAX_TRACESTATE_BYTES]


def parse_baggage(header_value: str | None) -> str | None:
    """Return bounded W3C baggage entries when present."""
    if not header_value:
        return None
    entries = [entry.strip() for entry in header_value.split(",") if entry.strip()]
    if not entries:
        return None
    value = ",".join(entries)
    return value[:_MAX_BAGGAGE_BYTES]


def make_request_trace(headers: dict[str, Any]) -> dict[str, str | bool | None]:
    """Create request trace metadata from incoming headers or fresh IDs."""
    incoming = parse_traceparent(str(headers.get("traceparent", "")))
    tracestate = parse_tracestate(str(headers.get("tracestate", "")))
    baggage = parse_baggage(str(headers.get("baggage", "")))
    trace_id = incoming["trace_id"] if incoming else _random_trace_id()
    parent_span_id = incoming["parent_span_id"] if incoming else None
    trace_flags = incoming["trace_flags"] if incoming else "01"
    span_id = _random_span_id()
    return {
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "trace_flags": trace_flags,
        "traceparent": build_traceparent(trace_id, span_id, trace_flags),
        "tracestate": tracestate,
        "baggage": baggage,
        "incoming_traceparent": bool(incoming),
    }


def inject_trace_headers(
    headers: dict[str, str] | None = None,
    *,
    traceparent: str | None = None,
    tracestate: str | None = None,
    baggage: str | None = None,
) -> dict[str, str]:
    """Return a headers dict with bounded W3C trace headers attached."""
    merged = dict(headers or {})
    if traceparent:
        merged["traceparent"] = traceparent
    if tracestate:
        merged["tracestate"] = tracestate
    if baggage:
        merged["baggage"] = baggage
    return merged


def inject_current_trace_headers(headers: dict[str, str] | None = None) -> dict[str, str]:
    """Inject active OpenTelemetry context into outbound headers when enabled."""
    merged = dict(headers or {})
    if not configure_otel_tracing():
        return merged
    try:
        from opentelemetry.propagate import inject
    except ImportError:
        return merged
    inject(merged)
    if traceparent := parse_traceparent(merged.get("traceparent")):
        merged["traceparent"] = build_traceparent(traceparent["trace_id"], traceparent["parent_span_id"], traceparent["trace_flags"])
    else:
        merged.pop("traceparent", None)
    if tracestate := parse_tracestate(merged.get("tracestate")):
        merged["tracestate"] = tracestate
    else:
        merged.pop("tracestate", None)
    if baggage := parse_baggage(merged.get("baggage")):
        merged["baggage"] = baggage
    else:
        merged.pop("baggage", None)
    return merged


def configure_otel_tracing() -> bool:
    """Enable OTLP trace export when explicitly configured.

    Returns True when OTLP export is active, False otherwise.
    """
    global _otel_tracing_state
    if _otel_tracing_state == "configured":
        return True
    if _otel_tracing_state in {"disabled", "missing_deps"}:
        return False

    endpoint = os.environ.get("AGENT_BOM_OTEL_TRACES_ENDPOINT", "").strip()
    if not endpoint:
        _otel_tracing_state = "disabled"
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        _otel_tracing_state = "missing_deps"
        _logger.warning(
            "AGENT_BOM_OTEL_TRACES_ENDPOINT is set but OpenTelemetry trace packages are unavailable. "
            "Install with: pip install 'agent-bom[otel]'"
        )
        return False

    headers_env = os.environ.get("AGENT_BOM_OTEL_TRACES_HEADERS", "").strip()
    headers: dict[str, str] = {}
    if headers_env:
        for raw_pair in headers_env.split(","):
            if "=" not in raw_pair:
                continue
            key, value = raw_pair.split("=", 1)
            if key.strip():
                headers[key.strip()] = value.strip()

    provider = TracerProvider(
        resource=Resource.create(
            {
                SERVICE_NAME: "agent-bom-api",
                SERVICE_VERSION: __version__,
            }
        )
    )
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, headers=headers or None)))
    trace.set_tracer_provider(provider)
    _otel_tracing_state = "configured"
    _logger.info("OTLP tracing enabled for agent-bom API: %s", endpoint)
    return True


def get_tracer(name: str):
    """Return an OpenTelemetry tracer when OTLP tracing is enabled."""
    if not configure_otel_tracing():
        return None
    try:
        from opentelemetry import trace
    except ImportError:
        return None
    return trace.get_tracer(name)


def get_tracing_health() -> TracingHealthSnapshot:
    """Return stable operator-facing tracing health/status metadata."""
    endpoint = os.environ.get("AGENT_BOM_OTEL_TRACES_ENDPOINT", "").strip()
    headers = os.environ.get("AGENT_BOM_OTEL_TRACES_HEADERS", "").strip()
    state = _otel_tracing_state
    if state == "unconfigured" and not endpoint:
        state = "disabled"
    return {
        "w3c_trace_context": True,
        "w3c_tracestate": True,
        "w3c_baggage": True,
        "otlp_export": state,
        "otlp_endpoint_configured": bool(endpoint),
        "otlp_headers_configured": bool(headers),
    }
