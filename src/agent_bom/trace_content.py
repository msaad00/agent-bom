"""Opt-in trace-content screening — run Shield over ingested trace content.

The default trace-ingest path (:mod:`agent_bom.otel_ingest`, the ``/v1/traces``
route) parses span *metadata* only and never stores content, for privacy. This
module adds the **opt-in** content path: when explicitly enabled, it runs
:meth:`agent_bom.shield.Shield.check_response` over the free-text content on
ingested spans and surfaces injection / PII / credential-leak findings on
production traces.

Privacy posture (preserved by design):
- Off by default. Callers gate this behind ``TRACE_CONTENT_SCREENING_ENABLED``
  (or an explicit per-request opt-in). With screening off, no content is parsed.
- Raw content is screened in-memory and never returned or persisted. A
  ``ContentFinding`` carries only the detector, severity, span identity, and a
  Shield-redacted one-line summary — never the offending text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agent_bom.otel_ingest import RESPONSE_CONTENT_CHANNELS, SpanContent, extract_span_content

if TYPE_CHECKING:
    from agent_bom.shield import Shield

_MAX_SUMMARY_CHARS = 240


@dataclass
class ContentFinding:
    """A Shield detection on trace content — privacy-safe (no raw content)."""

    trace_id: str
    span_id: str
    tool_name: str
    channel: str
    detector: str
    severity: str
    message: str  # Shield-redacted, bounded summary — never raw content

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "tool_name": self.tool_name,
            "channel": self.channel,
            "detector": self.detector,
            "severity": self.severity,
            "message": self.message,
        }


def _redacted_summary(shield: "Shield", raw: str) -> str:
    """Redact credentials/PII from an alert message and bound its length."""
    try:
        redacted = shield.redact(str(raw or ""))
    except Exception:  # noqa: BLE001 — never leak raw content on a redaction bug
        redacted = ""
    redacted = redacted.replace("\n", " ").replace("\r", " ").strip()
    return redacted[:_MAX_SUMMARY_CHARS]


def screen_span_contents(
    contents: list[SpanContent],
    *,
    shield: "Shield | None" = None,
) -> list[ContentFinding]:
    """Run Shield.check_response over already-extracted span contents.

    Returns privacy-safe ``ContentFinding`` rows. Never persists or returns the
    raw content. Best-effort per span: a detector failure on one span never
    drops the rest.
    """
    if not contents:
        return []
    if shield is None:
        from agent_bom.shield import Shield

        shield = Shield()

    findings: list[ContentFinding] = []
    for span in contents:
        try:
            alerts = shield.check_response(span.tool_name or "trace", span.content)
        except Exception:  # noqa: BLE001
            continue
        for alert in alerts or []:
            if not isinstance(alert, dict):
                continue
            findings.append(
                ContentFinding(
                    trace_id=span.trace_id,
                    span_id=span.span_id,
                    tool_name=span.tool_name,
                    channel=span.channel,
                    detector=str(alert.get("detector") or alert.get("type") or "shield"),
                    severity=str(alert.get("severity") or "medium").lower(),
                    message=_redacted_summary(shield, alert.get("message", "")),
                )
            )
    return findings


def screen_trace_content(
    trace_data: dict,
    *,
    shield: "Shield | None" = None,
    channels: frozenset[str] | set[str] | None = None,
) -> list[ContentFinding]:
    """Extract response-side span content and screen it with Shield (opt-in).

    Convenience wrapper over :func:`agent_bom.otel_ingest.extract_span_content`
    plus :func:`screen_span_contents`. Callers must only invoke this when
    content screening is explicitly enabled.
    """
    contents = extract_span_content(trace_data, channels=channels or RESPONSE_CONTENT_CHANNELS)
    return screen_span_contents(contents, shield=shield)


__all__ = [
    "ContentFinding",
    "screen_span_contents",
    "screen_trace_content",
]
