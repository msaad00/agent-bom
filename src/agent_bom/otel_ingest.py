"""OpenTelemetry trace ingestion — flag vulnerable tool calls and ML API provenance.

Parses OTel JSON traces (e.g. from Google ADK, Datadog, or any OTel-compatible
agent framework) and cross-references tool call spans against scan results to
flag calls to known-vulnerable MCP servers.

Also detects ML API spans (OpenAI, Anthropic, Cohere, etc.) using OpenTelemetry
GenAI semantic conventions (``gen_ai.*`` attributes) and extracts model provenance:
provider, model name/version, token usage, and deprecation advisories.

Span naming convention: ``adk.tool.<tool_name>`` for Google ADK, or
generic ``tool_call`` with ``tool.name`` attribute.

GenAI spans: detected via ``gen_ai.system`` attribute or span name patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_ADK_TOOL_RE = re.compile(r"^adk\.tool\.(.+)$")

# Maximum trace file size (50 MB) — prevents OOM on adversarially large files
_MAX_TRACE_FILE_BYTES = 50 * 1024 * 1024

# GenAI span name patterns — instrumentation libraries emit these
_ML_SPAN_PATTERNS = re.compile(
    r"^("
    r"openai\.|"
    r"anthropic\.|"
    r"cohere\.|"
    r"ChatOpenAI|ChatAnthropic|ChatCohere|ChatBedrock|ChatVertexAI|"
    r"llm\.chat|llm\.complete|llm\.stream|"
    r"LLMChain|RetrievalQA|"
    r"gen_ai\.|"
    # LangGraph
    r"langgraph\.|"
    # CrewAI
    r"crewai\.|"
    # AutoGen
    r"autogen\.|"
    # Haystack
    r"haystack\."
    r")",
    re.IGNORECASE,
)

# Instrumentation scope names that indicate ML API usage
_ML_SCOPE_NAMES = {
    "opentelemetry-instrumentation-openai",
    "opentelemetry-instrumentation-anthropic",
    "opentelemetry-instrumentation-cohere",
    "opentelemetry.instrumentation.langchain",
    "opentelemetry.instrumentation.llama_index",
    "traceloop.sdk",
    # Additional framework scopes
    "opentelemetry.instrumentation.crewai",
    "opentelemetry.instrumentation.autogen",
    "haystack.tracing.opentelemetry",
}

# Known deprecated / end-of-life model patterns (prefix match on model_name)
# Maps prefix → (advisory_text, severity)
_DEPRECATED_MODELS: dict[str, tuple[str, str]] = {
    # OpenAI
    "text-davinci-003": ("Deprecated Jan 2024. Migrate to gpt-4o or gpt-4o-mini.", "high"),
    "text-davinci-002": ("Deprecated. Migrate to gpt-4o or gpt-4o-mini.", "high"),
    "text-curie-001": ("Deprecated. Migrate to gpt-4o-mini.", "high"),
    "text-babbage-001": ("Deprecated. Migrate to gpt-4o-mini.", "high"),
    "text-ada-001": ("Deprecated. Migrate to gpt-4o-mini.", "high"),
    "code-davinci-002": ("Deprecated. Migrate to gpt-4o.", "high"),
    "gpt-3.5-turbo-0301": ("Deprecated snapshot. Migrate to gpt-4o-mini.", "high"),
    "gpt-3.5-turbo-0613": ("Deprecated snapshot. Migrate to gpt-4o-mini.", "high"),
    "gpt-3.5-turbo-16k-0613": ("Deprecated snapshot. Migrate to gpt-4o-mini.", "high"),
    "gpt-4-0314": ("Deprecated snapshot. Migrate to gpt-4o.", "medium"),
    "gpt-4-0613": ("Deprecated snapshot. Migrate to gpt-4o.", "medium"),
    # Anthropic
    "claude-1": ("End-of-life. Migrate to Claude 3 or later.", "high"),
    "claude-2.0": ("Deprecated. Migrate to claude-3-5-sonnet or later.", "medium"),
    "claude-2.1": ("Deprecated. Migrate to claude-3-5-sonnet or later.", "medium"),
    "claude-instant-1": ("End-of-life. Migrate to claude-3-haiku.", "high"),
    # Cohere
    "command-nightly": ("Unstable nightly channel. Use command-r or command-r-plus for production.", "medium"),
    "command-light-nightly": ("Unstable nightly channel. Use command-r for production.", "medium"),
}


@dataclass
class ToolCallTrace:
    """A parsed tool call from an OTel span."""

    trace_id: str
    span_id: str
    tool_name: str
    server_name: str = ""
    package_name: str = ""
    parameters: dict = field(default_factory=dict)
    duration_ms: float = 0.0
    status: str = "ok"


@dataclass
class FlaggedCall:
    """A tool call flagged as potentially risky."""

    trace: ToolCallTrace
    reason: str
    severity: str = "medium"  # medium or high
    server: str = ""
    package_name: str = ""
    matched_cve: str = ""
    matched_cves: list[str] = field(default_factory=list)


@dataclass
class LLMAPICall:
    """An ML API call parsed from an OTel GenAI span."""

    trace_id: str
    span_id: str
    parent_span_id: str
    provider: str  # "openai", "anthropic", "cohere", "vertex_ai", etc.
    model_name: str  # "gpt-4o", "claude-3-5-sonnet-20241022", etc.
    model_version: str  # explicit version if present, else ""
    endpoint: str  # "chat.completions", "messages", "generate", etc.
    input_tokens: int
    output_tokens: int
    duration_ms: float
    status: str  # "ok" | "error"


@dataclass
class FlaggedMLCall:
    """An ML API call flagged for deprecation or security advisory."""

    call: LLMAPICall
    reason: str
    severity: str  # "high" | "medium" | "low"
    advisory: str  # human-readable advisory text


def _extract_attr(attributes: list[dict], key: str) -> str:
    """Extract string value from OTel attribute list by key."""
    for attr in attributes:
        if attr.get("key") == key:
            val = attr.get("value", {})
            return val.get("stringValue") or str(val.get("intValue", "")) or str(val.get("doubleValue", "")) or ""
    return ""


def _extract_int_attr(attributes: list[dict], key: str) -> int:
    """Extract integer value from OTel attribute list by key."""
    for attr in attributes:
        if attr.get("key") == key:
            val = attr.get("value", {})
            if "intValue" in val:
                return int(val["intValue"])
            if "doubleValue" in val:
                return int(val["doubleValue"])
            if "stringValue" in val:
                try:
                    return int(val["stringValue"])
                except (ValueError, TypeError):
                    pass
    return 0


def _is_ml_span(span: dict, scope_name: str) -> bool:
    """Return True if this span represents an ML API call."""
    # Check instrumentation scope name
    if scope_name in _ML_SCOPE_NAMES:
        return True
    # Check for gen_ai.system attribute (OTel GenAI semantic conventions)
    attrs = span.get("attributes", [])
    for attr in attrs:
        if attr.get("key") == "gen_ai.system":
            return True
    # Check span name pattern
    name = span.get("name", "")
    if _ML_SPAN_PATTERNS.match(name):
        return True
    return False


def validate_otel_schema(trace_data: dict) -> None:
    """Validate that trace_data conforms to OTLP JSON structure.

    Raises ``ValueError`` with a clear path if the required structure is absent.
    Accepts both ``resourceSpans`` (OTLP standard) and flat ``spans`` arrays.
    """
    if not isinstance(trace_data, dict):
        raise ValueError("OTel trace must be a JSON object, got: " + type(trace_data).__name__)

    has_resource_spans = "resourceSpans" in trace_data
    has_flat_spans = "spans" in trace_data

    if not has_resource_spans and not has_flat_spans:
        raise ValueError(
            "OTel trace missing required key 'resourceSpans' (OTLP format) or 'spans' (flat format). "
            "Ensure the file is a valid OTel JSON export."
        )

    if has_resource_spans and not isinstance(trace_data["resourceSpans"], list):
        raise ValueError("'resourceSpans' must be a JSON array")


def parse_otel_traces(trace_data: dict) -> list[ToolCallTrace]:
    """Parse OTel JSON export into tool call traces.

    Supports OTLP JSON format (resourceSpans → scopeSpans → spans) and
    simple flat span arrays.
    """
    validate_otel_schema(trace_data)
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

        # Extract parameters and common correlation attributes from span attrs.
        attrs = span.get("attributes", [])
        params = {}
        server_name = _extract_attr(attrs, "mcp.server") or _extract_attr(attrs, "server.name") or _extract_attr(attrs, "tool.server")
        package_name = (
            _extract_attr(attrs, "package.name")
            or _extract_attr(attrs, "tool.package")
            or _extract_attr(attrs, "dependency.package")
            or _extract_attr(attrs, "package")
        )
        for attr in attrs:
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
                server_name=server_name,
                package_name=package_name,
                parameters=params,
                duration_ms=duration_ms,
                status=status,
            )
        )

    return traces


def parse_ml_api_spans(trace_data: dict) -> list[LLMAPICall]:
    """Parse OTel JSON export into ML API call records.

    Detects spans representing LLM inference calls using:
    - OpenTelemetry GenAI semantic conventions (``gen_ai.*`` attributes)
    - Instrumentation library scope names (opentelemetry-instrumentation-openai, etc.)
    - Span name patterns (ChatOpenAI, llm.chat, LangGraph, CrewAI, AutoGen, Haystack, etc.)

    Supports OTLP JSON format (resourceSpans → scopeSpans → spans).
    """
    validate_otel_schema(trace_data)
    calls: list[LLMAPICall] = []

    for rs in trace_data.get("resourceSpans", []):
        for ss in rs.get("scopeSpans", []):
            scope_name = ss.get("scope", {}).get("name", "")
            for span in ss.get("spans", []):
                if not _is_ml_span(span, scope_name):
                    continue

                attrs = span.get("attributes", [])

                # Provider: gen_ai.system (OTel convention) or infer from scope
                provider = _extract_attr(attrs, "gen_ai.system")
                if not provider:
                    if "openai" in scope_name.lower():
                        provider = "openai"
                    elif "anthropic" in scope_name.lower():
                        provider = "anthropic"
                    elif "cohere" in scope_name.lower():
                        provider = "cohere"
                    elif "langchain" in scope_name.lower():
                        provider = "langchain"
                    elif "llama" in scope_name.lower():
                        provider = "llama_index"
                    else:
                        provider = "unknown"

                # Model name: prefer gen_ai.response.model (actual model used)
                model_name = (
                    _extract_attr(attrs, "gen_ai.response.model")
                    or _extract_attr(attrs, "gen_ai.request.model")
                    or _extract_attr(attrs, "llm.model")
                    or ""
                )

                # Model version: explicit version attribute or extract from model name
                model_version = _extract_attr(attrs, "gen_ai.request.model_version") or ""

                # Endpoint / operation
                endpoint = _extract_attr(attrs, "gen_ai.operation.name") or _extract_attr(attrs, "llm.request.type") or span.get("name", "")

                # Token counts
                input_tokens = (
                    _extract_int_attr(attrs, "gen_ai.usage.input_tokens")
                    or _extract_int_attr(attrs, "gen_ai.usage.prompt_tokens")
                    or _extract_int_attr(attrs, "llm.usage.prompt_tokens")
                )
                output_tokens = (
                    _extract_int_attr(attrs, "gen_ai.usage.output_tokens")
                    or _extract_int_attr(attrs, "gen_ai.usage.completion_tokens")
                    or _extract_int_attr(attrs, "llm.usage.completion_tokens")
                )

                # Duration
                start = span.get("startTimeUnixNano", 0)
                end = span.get("endTimeUnixNano", 0)
                duration_ms = (end - start) / 1_000_000 if start and end else 0.0

                # Status
                status_obj = span.get("status", {})
                status = "error" if status_obj.get("code") == 2 else "ok"

                calls.append(
                    LLMAPICall(
                        trace_id=span.get("traceId", ""),
                        span_id=span.get("spanId", ""),
                        parent_span_id=span.get("parentSpanId", ""),
                        provider=provider,
                        model_name=model_name,
                        model_version=model_version,
                        endpoint=endpoint,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        duration_ms=duration_ms,
                        status=status,
                    )
                )

    return calls


def flag_deprecated_models(calls: list[LLMAPICall]) -> list[FlaggedMLCall]:
    """Flag ML API calls that use deprecated or end-of-life model versions.

    Matches against a built-in registry of known deprecated model prefixes.
    Returns a list of FlaggedMLCall for any matched calls.
    """
    flagged: list[FlaggedMLCall] = []
    for call in calls:
        model = call.model_name.lower()
        for prefix, (advisory, severity) in _DEPRECATED_MODELS.items():
            if model.startswith(prefix.lower()):
                flagged.append(
                    FlaggedMLCall(
                        call=call,
                        reason=f"Model '{call.model_name}' is deprecated or end-of-life",
                        severity=severity,
                        advisory=advisory,
                    )
                )
                break
    return flagged


def flag_vulnerable_tool_calls(
    traces: list[ToolCallTrace],
    vuln_packages: dict[str, list[str]] | None = None,
    vuln_servers: dict[str, list[str]] | set[str] | None = None,
) -> list[FlaggedCall]:
    """Cross-reference tool calls against known-vulnerable packages/servers.

    Args:
        traces: Parsed tool call traces.
        vuln_packages: Map of package name → list of CVE IDs.
        vuln_servers: Mapping of server/tool name → CVE IDs, or a simple set.
    """
    flagged: list[FlaggedCall] = []
    vuln_packages = vuln_packages or {}
    vuln_server_map: dict[str, list[str]]
    if isinstance(vuln_servers, set):
        vuln_server_map = {name: [] for name in vuln_servers}
    else:
        vuln_server_map = vuln_servers or {}

    def _lookup_name(mapping: dict[str, list[str]], candidate: str) -> tuple[str, list[str]] | None:
        lowered = candidate.lower()
        for name, cves in mapping.items():
            if name.lower() == lowered:
                return name, cves
        return None

    for trace in traces:
        tool_lower = trace.tool_name.lower()
        server_match = None
        package_match = None
        matched_cves: list[str] = []

        for candidate in (trace.server_name, trace.tool_name):
            if not candidate:
                continue
            server_match = _lookup_name(vuln_server_map, candidate)
            if server_match:
                matched_cves.extend(server_match[1])
                break

        # Check against vulnerable package names (prefer explicit package attr, then fuzzy tool-name match)
        for pkg_name, cves in vuln_packages.items():
            explicit_match = trace.package_name and trace.package_name.lower() == pkg_name.lower()
            fuzzy_match = pkg_name.lower() in tool_lower or tool_lower in pkg_name.lower()
            if explicit_match or fuzzy_match:
                package_match = pkg_name
                matched_cves.extend(cves)
                break

        if server_match or package_match:
            deduped_cves = list(dict.fromkeys(cve for cve in matched_cves if cve))
            reason_parts = []
            if server_match:
                reason_parts.append(f"server '{server_match[0]}' has known vulnerabilities")
            if package_match:
                reason_parts.append(f"package '{package_match}' is vulnerable")
            flagged.append(
                FlaggedCall(
                    trace=trace,
                    reason="; ".join(reason_parts),
                    severity="high" if server_match else "medium",
                    server=server_match[0] if server_match else trace.server_name,
                    package_name=package_match or trace.package_name,
                    matched_cve=deduped_cves[0] if deduped_cves else "",
                    matched_cves=deduped_cves,
                )
            )

    return flagged
