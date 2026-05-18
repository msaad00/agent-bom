from __future__ import annotations

from agent_bom.langfuse_otel import langfuse_runtime_attributes, set_langfuse_runtime_attributes


class _Span:
    def __init__(self) -> None:
        self.attrs: dict[str, object] = {}

    def set_attribute(self, key: str, value: object) -> None:
        self.attrs[key] = value


def test_langfuse_runtime_attributes_emit_safe_trace_metadata() -> None:
    attrs = langfuse_runtime_attributes(
        surface="proxy",
        tenant_id="tenant-a",
        method="tools/call",
        tool_name="read_file",
        decision="allowed",
        agent_id="agent-1",
        trace_id="trace-1",
        arguments={"path": "/tmp/report.txt", "api_token": "secret-value"},
    )

    assert attrs["langfuse.trace.name"] == "agent-bom.proxy"
    assert attrs["langfuse.trace.metadata.tenant_id"] == "tenant-a"
    assert attrs["langfuse.observation.metadata.tool"] == "read_file"
    assert attrs["langfuse.observation.metadata.policy_decision"] == "allowed"
    assert attrs["agent_bom.runtime.argument_count"] == 2
    assert attrs["agent_bom.runtime.argument_keys"] == ["<redacted>", "path"]


def test_langfuse_runtime_attributes_do_not_emit_raw_arguments() -> None:
    attrs = langfuse_runtime_attributes(
        surface="gateway",
        tenant_id="tenant-a",
        method="tools/call",
        tool_name="query",
        arguments={
            "sql": "select * from private_table",
            "password": "super-secret",
            "nested": {"token": "nested-secret"},
        },
    )

    rendered = repr(attrs)
    assert "super-secret" not in rendered
    assert "nested-secret" not in rendered
    assert "select * from private_table" not in rendered
    assert "langfuse.observation.input" not in attrs
    assert "langfuse.observation.output" not in attrs


def test_set_langfuse_runtime_attributes_sets_span_values() -> None:
    span = _Span()

    set_langfuse_runtime_attributes(
        span,
        surface="gateway",
        tenant_id="default",
        method="tools/call",
        tool_name="web_search",
        decision="blocked",
        reason="blocked by read-only policy",
        upstream="search",
    )

    assert span.attrs["langfuse.trace.name"] == "agent-bom.gateway"
    assert span.attrs["langfuse.trace.metadata.upstream"] == "search"
    assert span.attrs["langfuse.observation.metadata.reason_code"] == "blocked by read-only policy"
