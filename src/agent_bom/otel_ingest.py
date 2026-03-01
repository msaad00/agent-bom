"""OpenTelemetry trace ingestion — flag vulnerable tool calls.

Parses OTel JSON traces (e.g. from Google ADK, Datadog, or any OTel-compatible
agent framework) and cross-references tool call spans against scan results to
flag calls to known-vulnerable MCP servers.

Span naming convention: ``adk.tool.<tool_name>`` for Google ADK, or
generic ``tool_call`` with ``tool.name`` attribute.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_ADK_TOOL_RE = re.compile(r"^adk\.tool\.(.+)$")


@dataclass
class ToolCallTrace:
    """A parsed tool call from an OTel span."""

    trace_id: str
    span_id: str
    tool_name: str
    parameters: dict = field(default_factory=dict)
    duration_ms: float = 0.0
    status: str = "ok"


@dataclass
class FlaggedCall:
    """A tool call flagged as potentially risky."""

    trace: ToolCallTrace
    reason: str
    severity: str = "medium"  # medium or high
    matched_cve: str = ""


def parse_otel_traces(trace_data: dict) -> list[ToolCallTrace]:
    """Parse OTel JSON export into tool call traces.

    Supports OTLP JSON format (resourceSpans → scopeSpans → spans) and
    simple flat span arrays.
    """
    traces: list[ToolCallTrace] = []

    # Extract spans from OTLP JSON structure
    spans = []
    for rs in trace_data.get("resourceSpans", []):
        for ss in rs.get("scopeSpans", []):
            spans.extend(ss.get("spans", []))

    # Also support flat "spans" array
    if not spans:
        spans = trace_data.get("spans", [])

    for span in spans:
        name = span.get("name", "")
        tool_name = ""

        # ADK convention: adk.tool.<name>
        m = _ADK_TOOL_RE.match(name)
        if m:
            tool_name = m.group(1)

        # Generic: check attributes for tool.name
        if not tool_name:
            for attr in span.get("attributes", []):
                if attr.get("key") == "tool.name":
                    tool_name = attr.get("value", {}).get("stringValue", "")
                    break

        if not tool_name:
            continue

        # Extract parameters from attributes
        params = {}
        for attr in span.get("attributes", []):
            key = attr.get("key", "")
            if key.startswith("tool.input."):
                param_name = key[len("tool.input.") :]
                val = attr.get("value", {})
                params[param_name] = val.get("stringValue", val.get("intValue", ""))

        # Duration
        start = span.get("startTimeUnixNano", 0)
        end = span.get("endTimeUnixNano", 0)
        duration_ms = (end - start) / 1_000_000 if start and end else 0.0

        # Status
        status_obj = span.get("status", {})
        status = "error" if status_obj.get("code") == 2 else "ok"

        traces.append(
            ToolCallTrace(
                trace_id=span.get("traceId", ""),
                span_id=span.get("spanId", ""),
                tool_name=tool_name,
                parameters=params,
                duration_ms=duration_ms,
                status=status,
            )
        )

    return traces


def flag_vulnerable_tool_calls(
    traces: list[ToolCallTrace],
    vuln_packages: dict[str, list[str]] | None = None,
    vuln_servers: set[str] | None = None,
) -> list[FlaggedCall]:
    """Cross-reference tool calls against known-vulnerable packages/servers.

    Args:
        traces: Parsed tool call traces.
        vuln_packages: Map of package name → list of CVE IDs.
        vuln_servers: Set of server/tool names with known vulnerabilities.
    """
    flagged: list[FlaggedCall] = []
    vuln_packages = vuln_packages or {}
    vuln_servers = vuln_servers or set()

    for trace in traces:
        tool_lower = trace.tool_name.lower()

        # Check against vulnerable server/tool names
        if tool_lower in vuln_servers or trace.tool_name in vuln_servers:
            flagged.append(
                FlaggedCall(
                    trace=trace,
                    reason=f"Tool '{trace.tool_name}' belongs to a server with known vulnerabilities",
                    severity="high",
                )
            )
            continue

        # Check against vulnerable package names (fuzzy: tool name contains package)
        for pkg_name, cves in vuln_packages.items():
            if pkg_name.lower() in tool_lower or tool_lower in pkg_name.lower():
                flagged.append(
                    FlaggedCall(
                        trace=trace,
                        reason=f"Tool '{trace.tool_name}' may be associated with vulnerable package '{pkg_name}'",
                        severity="medium",
                        matched_cve=cves[0] if cves else "",
                    )
                )
                break

    return flagged
