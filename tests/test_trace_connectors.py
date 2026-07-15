"""Native Langfuse / LangSmith trace-pull connectors (#3899).

Pulled traces must feed the same ``otel_ingest`` parser and per-span correlation
as pushed OTLP. HTTP is mocked; credentials are used for auth only.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, MCPTool, Package, Severity, Vulnerability
from agent_bom.otel_ingest import parse_otel_traces
from agent_bom.runtime_correlation import correlate_spans_to_attack_paths
from agent_bom.trace_connectors import (
    TraceConnectorError,
    fetch_langfuse_traces,
    fetch_langsmith_traces,
    fetch_traces,
    list_trace_connectors,
)


class _FakeResponse:
    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self) -> Any:
        return self._payload


class _FakeClient:
    """Records the last request and returns a canned payload."""

    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self.payload = payload
        self.status_code = status_code
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        return _FakeResponse(self.payload, self.status_code)


def _blast_radius() -> BlastRadius:
    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2025-7777", summary="x", severity=Severity.HIGH, is_kev=False),
        package=Package(name="requests", version="2.0.0", ecosystem="pypi"),
        affected_servers=[MCPServer(name="shell-mcp")],
        affected_agents=[Agent(name="a", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp")],
        exposed_credentials=["AWS_SECRET_ACCESS_KEY"],
        exposed_tools=[MCPTool(name="run_shell", description="d")],
    )
    br.calculate_risk_score()
    return br


def test_list_trace_connectors_advertises_langfuse_and_langsmith() -> None:
    names = {c["name"] for c in list_trace_connectors()}
    assert {"langfuse", "langsmith"} <= names


def test_langfuse_pull_maps_to_otlp_and_uses_basic_auth() -> None:
    client = _FakeClient({"data": [{"id": "obs-1", "traceId": "tr-1", "name": "run_shell", "metadata": {"server": "shell-mcp"}}]})
    otlp = fetch_langfuse_traces(host="https://cloud.example", public_key="pk", secret_key="sk", client=client)
    # Credentials are passed for auth only.
    assert client.calls[0]["auth"] == ("pk", "sk")
    traces = parse_otel_traces(otlp)
    assert traces[0].tool_name == "run_shell"
    assert traces[0].server_name == "shell-mcp"
    assert traces[0].span_id == "obs-1"


def test_langsmith_pull_maps_to_otlp_and_uses_api_key_header() -> None:
    client = _FakeClient(
        {"runs": [{"id": "run-1", "trace_id": "tr-9", "name": "run_shell", "extra": {"metadata": {"server": "shell-mcp"}}}]}
    )
    otlp = fetch_langsmith_traces(api_key="ls-key", client=client)
    assert client.calls[0]["headers"]["x-api-key"] == "ls-key"
    traces = parse_otel_traces(otlp)
    assert traces[0].tool_name == "run_shell"
    assert traces[0].span_id == "run-1"


def test_pulled_traces_feed_span_correlation() -> None:
    client = _FakeClient({"data": [{"id": "obs-1", "traceId": "tr-1", "name": "run_shell", "metadata": {"server": "shell-mcp"}}]})
    otlp = fetch_traces("langfuse", {"host": "https://c", "public_key": "pk", "secret_key": "sk"}, client=client)
    traces = parse_otel_traces(otlp)
    paths = correlate_spans_to_attack_paths(traces, [_blast_radius()])
    assert len(paths) == 1
    assert paths[0].vulnerability_id == "CVE-2025-7777"
    assert paths[0].span_id == "obs-1"


def test_langfuse_content_only_included_when_opted_in() -> None:
    payload = {"data": [{"id": "o", "traceId": "t", "name": "read_file", "output": "secret AKIAIOSFODNN7EXAMPLE"}]}
    without = fetch_langfuse_traces(host="https://c", public_key="pk", secret_key="sk", client=_FakeClient(payload))
    assert "AKIAIOSFODNN7EXAMPLE" not in repr(without)
    with_content = fetch_langfuse_traces(
        host="https://c", public_key="pk", secret_key="sk", include_content=True, client=_FakeClient(payload)
    )
    assert "AKIAIOSFODNN7EXAMPLE" in repr(with_content)


def test_missing_credentials_and_http_error_raise() -> None:
    with pytest.raises(TraceConnectorError):
        fetch_langfuse_traces(host="https://c", public_key="", secret_key="sk")
    with pytest.raises(TraceConnectorError):
        fetch_langsmith_traces(api_key="k", client=_FakeClient({}, status_code=401))
    with pytest.raises(TraceConnectorError):
        fetch_traces("unknown-provider", {"api_key": "k"})
