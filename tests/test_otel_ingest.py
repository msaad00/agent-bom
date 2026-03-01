"""Tests for OpenTelemetry trace ingestion."""

from agent_bom.otel_ingest import (
    ToolCallTrace,
    flag_vulnerable_tool_calls,
    parse_otel_traces,
)


def _otlp_trace(spans: list[dict]) -> dict:
    return {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "spans": spans,
                    }
                ]
            }
        ]
    }


def test_parse_adk_tool_span():
    data = _otlp_trace(
        [
            {
                "traceId": "abc123",
                "spanId": "span1",
                "name": "adk.tool.web_search",
                "startTimeUnixNano": 1000000000,
                "endTimeUnixNano": 1500000000,
                "attributes": [],
                "status": {},
            }
        ]
    )
    traces = parse_otel_traces(data)
    assert len(traces) == 1
    assert traces[0].tool_name == "web_search"
    assert traces[0].duration_ms == 500.0


def test_parse_generic_tool_name_attribute():
    data = _otlp_trace(
        [
            {
                "traceId": "abc",
                "spanId": "s1",
                "name": "tool_call",
                "attributes": [{"key": "tool.name", "value": {"stringValue": "read_file"}}],
                "status": {},
            }
        ]
    )
    traces = parse_otel_traces(data)
    assert len(traces) == 1
    assert traces[0].tool_name == "read_file"


def test_parse_skips_non_tool_spans():
    data = _otlp_trace(
        [
            {
                "traceId": "abc",
                "spanId": "s1",
                "name": "llm_call",
                "attributes": [],
                "status": {},
            }
        ]
    )
    traces = parse_otel_traces(data)
    assert len(traces) == 0


def test_flag_vulnerable_server():
    traces = [ToolCallTrace(trace_id="t1", span_id="s1", tool_name="evil_tool")]
    flagged = flag_vulnerable_tool_calls(traces, vuln_servers={"evil_tool"})
    assert len(flagged) == 1
    assert flagged[0].severity == "high"


def test_flag_no_match():
    traces = [ToolCallTrace(trace_id="t1", span_id="s1", tool_name="safe_tool")]
    flagged = flag_vulnerable_tool_calls(traces, vuln_servers={"other"})
    assert len(flagged) == 0


def test_flag_vulnerable_package():
    traces = [ToolCallTrace(trace_id="t1", span_id="s1", tool_name="langchain_search")]
    flagged = flag_vulnerable_tool_calls(traces, vuln_packages={"langchain": ["CVE-2025-1"]})
    assert len(flagged) == 1
    assert flagged[0].matched_cve == "CVE-2025-1"


def test_parse_flat_spans_format():
    data = {
        "spans": [
            {
                "traceId": "t",
                "spanId": "s",
                "name": "adk.tool.calc",
                "attributes": [],
                "status": {},
            }
        ]
    }
    traces = parse_otel_traces(data)
    assert len(traces) == 1
    assert traces[0].tool_name == "calc"


def test_malformed_input():
    traces = parse_otel_traces({})
    assert traces == []
    traces = parse_otel_traces({"resourceSpans": []})
    assert traces == []
