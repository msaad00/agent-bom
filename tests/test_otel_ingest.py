"""Tests for OpenTelemetry trace ingestion."""

from agent_bom.otel_ingest import (
    LLMAPICall,
    ToolCallTrace,
    flag_deprecated_models,
    flag_vulnerable_tool_calls,
    parse_ml_api_spans,
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


# ── parse_ml_api_spans ────────────────────────────────────────────────────────


def _ml_otlp(spans: list[dict], scope_name: str = "") -> dict:
    """Build an OTLP trace dict with a single scopeSpan."""
    return {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "scope": {"name": scope_name},
                        "spans": spans,
                    }
                ]
            }
        ]
    }


def _gen_ai_span(
    model: str = "gpt-4o",
    provider: str = "openai",
    input_tokens: int = 100,
    output_tokens: int = 50,
    name: str = "openai.chat.completions",
    start: int = 1_000_000_000,
    end: int = 2_000_000_000,
    status_code: int = 0,
    parent_span_id: str = "",
) -> dict:
    """Helper: build a GenAI OTel span dict."""
    return {
        "traceId": "trace1",
        "spanId": "span1",
        "parentSpanId": parent_span_id,
        "name": name,
        "startTimeUnixNano": start,
        "endTimeUnixNano": end,
        "attributes": [
            {"key": "gen_ai.system", "value": {"stringValue": provider}},
            {"key": "gen_ai.request.model", "value": {"stringValue": model}},
            {"key": "gen_ai.usage.input_tokens", "value": {"intValue": input_tokens}},
            {"key": "gen_ai.usage.output_tokens", "value": {"intValue": output_tokens}},
            {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
        ],
        "status": {"code": status_code},
    }


def test_parse_ml_span_gen_ai_system_attribute():
    """Span with gen_ai.system attribute is detected as ML API call."""
    data = _ml_otlp([_gen_ai_span()])
    calls = parse_ml_api_spans(data)
    assert len(calls) == 1
    assert calls[0].provider == "openai"
    assert calls[0].model_name == "gpt-4o"
    assert calls[0].input_tokens == 100
    assert calls[0].output_tokens == 50
    assert calls[0].duration_ms == 1000.0


def test_parse_ml_span_scope_name_openai():
    """Span detected via instrumentation scope name."""
    span = {
        "traceId": "t",
        "spanId": "s",
        "parentSpanId": "",
        "name": "some_span",
        "attributes": [
            {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-3.5-turbo"}},
        ],
        "status": {},
    }
    data = _ml_otlp([span], scope_name="opentelemetry-instrumentation-openai")
    calls = parse_ml_api_spans(data)
    assert len(calls) == 1
    assert calls[0].provider == "openai"
    assert calls[0].model_name == "gpt-3.5-turbo"


def test_parse_ml_span_anthropic_provider():
    """Anthropic spans extracted correctly."""
    data = _ml_otlp(
        [
            _gen_ai_span(
                model="claude-3-5-sonnet-20241022",
                provider="anthropic",
                name="anthropic.messages",
                input_tokens=200,
                output_tokens=80,
            )
        ]
    )
    calls = parse_ml_api_spans(data)
    assert len(calls) == 1
    assert calls[0].provider == "anthropic"
    assert calls[0].model_name == "claude-3-5-sonnet-20241022"
    assert calls[0].input_tokens == 200


def test_parse_ml_span_langchain_scope():
    """LangChain instrumented spans detected via scope name."""
    span = {
        "traceId": "t",
        "spanId": "s",
        "parentSpanId": "p1",
        "name": "ChatOpenAI",
        "attributes": [
            {"key": "gen_ai.system", "value": {"stringValue": "openai"}},
            {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4"}},
            {"key": "gen_ai.usage.input_tokens", "value": {"intValue": 50}},
            {"key": "gen_ai.usage.output_tokens", "value": {"intValue": 20}},
            {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
        ],
        "status": {},
    }
    data = _ml_otlp([span], scope_name="opentelemetry.instrumentation.langchain")
    calls = parse_ml_api_spans(data)
    assert len(calls) == 1
    assert calls[0].parent_span_id == "p1"


def test_parse_ml_span_error_status():
    """Error status extracted correctly."""
    span = _gen_ai_span(status_code=2)
    data = _ml_otlp([span])
    calls = parse_ml_api_spans(data)
    assert calls[0].status == "error"


def test_parse_ml_span_ok_status():
    """OK status extracted when code != 2."""
    span = _gen_ai_span(status_code=0)
    data = _ml_otlp([span])
    calls = parse_ml_api_spans(data)
    assert calls[0].status == "ok"


def test_parse_ml_span_non_ml_span_skipped():
    """Tool call spans are not parsed as ML API calls."""
    data = _ml_otlp(
        [
            {
                "traceId": "t",
                "spanId": "s",
                "name": "adk.tool.web_search",
                "attributes": [],
                "status": {},
            }
        ]
    )
    calls = parse_ml_api_spans(data)
    assert calls == []


def test_parse_ml_span_no_spans():
    """Empty trace returns empty list."""
    calls = parse_ml_api_spans({})
    assert calls == []


def test_parse_ml_span_multiple_calls():
    """Multiple ML spans parsed independently."""
    spans = [
        _gen_ai_span(model="gpt-4o", input_tokens=10, output_tokens=5),
        {
            "traceId": "t2",
            "spanId": "s2",
            "parentSpanId": "",
            "name": "anthropic.messages",
            "startTimeUnixNano": 1_000_000_000,
            "endTimeUnixNano": 3_000_000_000,
            "attributes": [
                {"key": "gen_ai.system", "value": {"stringValue": "anthropic"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": "claude-3-haiku-20240307"}},
                {"key": "gen_ai.usage.input_tokens", "value": {"intValue": 30}},
                {"key": "gen_ai.usage.output_tokens", "value": {"intValue": 15}},
                {"key": "gen_ai.operation.name", "value": {"stringValue": "messages"}},
            ],
            "status": {},
        },
    ]
    data = _ml_otlp(spans)
    calls = parse_ml_api_spans(data)
    assert len(calls) == 2
    providers = {c.provider for c in calls}
    assert "openai" in providers
    assert "anthropic" in providers


def test_parse_ml_span_completion_tokens_fallback():
    """gen_ai.usage.completion_tokens used when output_tokens not present."""
    span = {
        "traceId": "t",
        "spanId": "s",
        "parentSpanId": "",
        "name": "openai.chat.completions",
        "attributes": [
            {"key": "gen_ai.system", "value": {"stringValue": "openai"}},
            {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4o"}},
            {"key": "gen_ai.usage.prompt_tokens", "value": {"intValue": 40}},
            {"key": "gen_ai.usage.completion_tokens", "value": {"intValue": 25}},
        ],
        "status": {},
    }
    data = _ml_otlp([span])
    calls = parse_ml_api_spans(data)
    assert calls[0].input_tokens == 40
    assert calls[0].output_tokens == 25


# ── flag_deprecated_models ────────────────────────────────────────────────────


def _make_call(model: str, provider: str = "openai") -> LLMAPICall:
    return LLMAPICall(
        trace_id="t",
        span_id="s",
        parent_span_id="",
        provider=provider,
        model_name=model,
        model_version="",
        endpoint="chat",
        input_tokens=0,
        output_tokens=0,
        duration_ms=0.0,
        status="ok",
    )


def test_flag_deprecated_openai_model():
    """text-davinci-003 flagged as high severity."""
    calls = [_make_call("text-davinci-003")]
    flagged = flag_deprecated_models(calls)
    assert len(flagged) == 1
    assert flagged[0].severity == "high"
    assert "deprecated" in flagged[0].reason.lower()
    assert "gpt-4o" in flagged[0].advisory


def test_flag_deprecated_gpt35_snapshot():
    """Deprecated GPT-3.5 snapshot flagged."""
    calls = [_make_call("gpt-3.5-turbo-0301")]
    flagged = flag_deprecated_models(calls)
    assert len(flagged) == 1
    assert flagged[0].severity == "high"


def test_flag_deprecated_anthropic_claude1():
    """claude-1 flagged as end-of-life."""
    calls = [_make_call("claude-1.0", provider="anthropic")]
    flagged = flag_deprecated_models(calls)
    assert len(flagged) == 1
    assert flagged[0].severity == "high"


def test_flag_deprecated_claude2():
    """claude-2.0 and claude-2.1 flagged as deprecated."""
    for model in ["claude-2.0", "claude-2.1"]:
        calls = [_make_call(model, provider="anthropic")]
        flagged = flag_deprecated_models(calls)
        assert len(flagged) == 1, f"{model} should be flagged"
        assert flagged[0].severity == "medium"


def test_flag_deprecated_cohere_nightly():
    """Cohere command-nightly flagged as medium."""
    calls = [_make_call("command-nightly", provider="cohere")]
    flagged = flag_deprecated_models(calls)
    assert len(flagged) == 1
    assert flagged[0].severity == "medium"


def test_flag_current_model_not_flagged():
    """Current models are not flagged."""
    for model in ["gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet-20241022", "claude-3-haiku-20240307"]:
        calls = [_make_call(model)]
        flagged = flag_deprecated_models(calls)
        assert flagged == [], f"{model} should not be flagged"


def test_flag_empty_list():
    """Empty call list returns empty flagged list."""
    assert flag_deprecated_models([]) == []


def test_flag_multiple_deprecated():
    """Multiple deprecated models in one trace all flagged."""
    calls = [
        _make_call("text-davinci-003"),
        _make_call("gpt-4o"),  # current — not flagged
        _make_call("claude-2.0", provider="anthropic"),
    ]
    flagged = flag_deprecated_models(calls)
    assert len(flagged) == 2
    flagged_models = {f.call.model_name for f in flagged}
    assert "text-davinci-003" in flagged_models
    assert "claude-2.0" in flagged_models
