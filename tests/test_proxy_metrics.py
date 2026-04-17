"""Tests for ProxyMetricsServer Prometheus metrics rendering."""

from __future__ import annotations

import pytest

from agent_bom.proxy import ProxyMetrics, ProxyMetricsServer


@pytest.fixture
def metrics():
    """Create a ProxyMetrics instance with sample data."""
    m = ProxyMetrics()
    m.record_call("read_file")
    m.record_call("read_file")
    m.record_call("write_file")
    m.record_blocked("policy")
    m.record_latency(10.5)
    m.record_latency(25.0)
    m.record_latency(150.0)
    m.replay_rejections = 2
    m.total_messages_client_to_server = 10
    m.total_messages_server_to_client = 8
    return m


@pytest.fixture
def server(metrics):
    """Create a ProxyMetricsServer."""
    return ProxyMetricsServer(metrics, port=0)  # port 0 = disabled


def test_prometheus_format(server, metrics):
    """Output matches Prometheus text exposition format."""
    # Override port so render_metrics works (rendering doesn't need port)
    server.port = 9999
    output = server.render_metrics()
    assert "# HELP" in output
    assert "# TYPE" in output
    assert output.endswith("\n")


def test_tool_call_counters(server):
    """Per-tool counters appear in output."""
    server.port = 9999
    output = server.render_metrics()
    assert 'agent_bom_proxy_tool_calls_total{tool="read_file"} 2' in output
    assert 'agent_bom_proxy_tool_calls_total{tool="write_file"} 1' in output


def test_blocked_counters(server):
    """Blocked reason counters appear in output."""
    server.port = 9999
    output = server.render_metrics()
    assert 'agent_bom_proxy_blocked_total{reason="policy"} 1' in output


def test_latency_quantiles(server):
    """p50 and p95 quantiles appear in output."""
    server.port = 9999
    output = server.render_metrics()
    assert 'agent_bom_proxy_latency_ms{quantile="0.5"}' in output
    assert 'agent_bom_proxy_latency_ms{quantile="0.95"}' in output


def test_uptime_gauge(server):
    """Uptime seconds gauge is present."""
    server.port = 9999
    output = server.render_metrics()
    assert "agent_bom_proxy_uptime_seconds" in output


def test_replay_rejections(server):
    """Replay rejection counter appears."""
    server.port = 9999
    output = server.render_metrics()
    assert "agent_bom_proxy_replay_rejections_total 2" in output


def test_message_counters(server):
    """Message direction counters appear."""
    server.port = 9999
    output = server.render_metrics()
    assert 'agent_bom_proxy_messages_total{direction="client_to_server"} 10' in output
    assert 'agent_bom_proxy_messages_total{direction="server_to_client"} 8' in output


def test_total_counters(server):
    """Total tool calls and blocked counters appear."""
    server.port = 9999
    output = server.render_metrics()
    assert "agent_bom_proxy_total_tool_calls 3" in output
    assert "agent_bom_proxy_total_blocked 1" in output


def test_control_plane_linkage_metrics(server, metrics):
    """Backpressure and refresh failure metrics are exposed for operators."""
    metrics.set_audit_buffer_bytes(512)
    metrics.set_audit_spillover_bytes(2048)
    metrics.set_audit_dlq_bytes(1024)
    metrics.record_policy_fetch_failure()
    metrics.record_audit_push_failure()
    metrics.set_audit_push_backoff_seconds(45)
    metrics.set_audit_circuit_open(True)
    server.port = 9999
    output = server.render_metrics()
    assert "agent_bom_proxy_audit_buffer_bytes 512" in output
    assert "agent_bom_proxy_audit_spillover_bytes 2048" in output
    assert "agent_bom_proxy_audit_dlq_bytes 1024" in output
    assert "agent_bom_proxy_policy_fetch_failures_total 1" in output
    assert "agent_bom_proxy_audit_push_failures_total 1" in output
    assert "agent_bom_proxy_audit_push_backoff_seconds 45" in output
    assert "agent_bom_proxy_audit_circuit_open 1" in output


@pytest.mark.asyncio
async def test_metrics_server_disabled_when_port_zero():
    """No server starts when port is 0."""
    m = ProxyMetrics()
    server = ProxyMetricsServer(m, port=0)
    await server.start()  # Should be a no-op
    assert server._server is None
    await server.stop()  # Should not raise


def test_empty_metrics():
    """Rendering works with empty metrics (no calls)."""
    m = ProxyMetrics()
    server = ProxyMetricsServer(m, port=9999)
    output = server.render_metrics()
    assert "agent_bom_proxy_total_tool_calls 0" in output
    assert "agent_bom_proxy_total_blocked 0" in output
    # No latency section when no data
    assert 'quantile="0.5"' not in output
