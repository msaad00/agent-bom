"""Pure JSON-RPC trace metadata copying shared by runtime transports."""

from __future__ import annotations


def inject_jsonrpc_trace_meta(
    message: dict[str, object],
    *,
    traceparent: str | None = None,
    tracestate: str | None = None,
    baggage: str | None = None,
) -> dict[str, object]:
    """Return a JSON-RPC message with bounded W3C trace context in `_meta`."""
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
