"""API tracing helpers — W3C trace context plus optional OTLP export."""

from __future__ import annotations

import logging
import os
import re
import secrets
from typing import Any

from agent_bom import __version__

_logger = logging.getLogger(__name__)

_TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_otel_tracing_state = "unconfigured"
_MAX_TRACESTATE_BYTES = 512


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


def make_request_trace(headers: dict[str, Any]) -> dict[str, str | bool | None]:
    """Create request trace metadata from incoming headers or fresh IDs."""
    incoming = parse_traceparent(str(headers.get("traceparent", "")))
    tracestate = parse_tracestate(str(headers.get("tracestate", "")))
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
        "incoming_traceparent": bool(incoming),
    }


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
