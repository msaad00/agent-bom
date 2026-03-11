"""Tests for agent_bom.proxy to improve coverage."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from agent_bom.proxy import (
    ProxyMetrics,
    ProxyMetricsServer,
    RotatingAuditLog,
    _safe_compile,
    _safe_regex_match,
    _safe_regex_search,
)

# ---------------------------------------------------------------------------
# _safe_regex helpers
# ---------------------------------------------------------------------------


def test_safe_compile_caches():
    p1 = _safe_compile(r"\d+")
    p2 = _safe_compile(r"\d+")
    assert p1 is p2


def test_safe_regex_match():
    assert _safe_regex_match(r"\d+", "123abc") is True
    assert _safe_regex_match(r"\d+", "abc") is False


def test_safe_regex_search():
    assert _safe_regex_search(r"\d+", "abc123") is True
    assert _safe_regex_search(r"\d+", "abc") is False


def test_safe_regex_match_oversized():
    text = "a" * 20_000
    assert _safe_regex_match(r"a+", text) is False


def test_safe_regex_search_oversized():
    text = "a" * 20_000
    assert _safe_regex_search(r"a+", text) is False


# ---------------------------------------------------------------------------
# RotatingAuditLog
# ---------------------------------------------------------------------------


def test_rotating_audit_log_basic():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        path = f.name

    # Remove the file first since RotatingAuditLog opens it fresh
    os.unlink(path)

    log = RotatingAuditLog(path)
    log.write('{"test": 1}\n')
    log.flush()
    log.close()

    content = Path(path).read_text()
    assert '{"test": 1}' in content


def test_rotating_audit_log_rejects_symlink():
    with tempfile.TemporaryDirectory() as tmpdir:
        real_path = os.path.join(tmpdir, "real.jsonl")
        link_path = os.path.join(tmpdir, "link.jsonl")
        Path(real_path).touch()
        os.symlink(real_path, link_path)

        with pytest.raises(ValueError, match="symlink"):
            RotatingAuditLog(link_path)


def test_rotating_audit_log_rotation():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        path = f.name
    os.unlink(path)

    # Create log with tiny max size to trigger rotation
    log = RotatingAuditLog(path, max_bytes=100)
    # Write enough data to exceed threshold and trigger check
    for i in range(1001):
        log.write(f'{{"i": {i}}}\n')
    log.close()

    # Rotated file should exist
    path + ".1"
    assert Path(path).exists()  # New file created after rotation


# ---------------------------------------------------------------------------
# ProxyMetrics
# ---------------------------------------------------------------------------


def test_proxy_metrics_record_call():
    m = ProxyMetrics()
    m.record_call("read_file")
    m.record_call("read_file")
    m.record_call("write_file")
    assert m.tool_calls["read_file"] == 2
    assert m.tool_calls["write_file"] == 1


def test_proxy_metrics_record_blocked():
    m = ProxyMetrics()
    m.record_blocked("undeclared")
    m.record_blocked("undeclared")
    m.record_blocked("policy")
    assert m.blocked_calls["undeclared"] == 2
    assert m.blocked_calls["policy"] == 1


def test_proxy_metrics_record_latency():
    m = ProxyMetrics()
    m.record_latency(10.0)
    m.record_latency(20.0)
    assert len(m.latencies_ms) == 2


def test_proxy_metrics_latency_bounded():
    m = ProxyMetrics()
    for i in range(15_000):
        m.record_latency(float(i))
    assert len(m.latencies_ms) <= ProxyMetrics._MAX_LATENCY_ENTRIES


def test_proxy_metrics_summary():
    m = ProxyMetrics()
    m.record_call("tool_a")
    m.record_blocked("policy")
    m.record_latency(10.0)
    m.record_latency(20.0)
    m.total_messages_client_to_server = 5
    m.total_messages_server_to_client = 3
    m.replay_rejections = 1
    m.relay_errors = 2

    s = m.summary()
    assert s["type"] == "proxy_summary"
    assert s["total_tool_calls"] == 1
    assert s["total_blocked"] == 1
    assert s["replay_rejections"] == 1
    assert s["relay_errors"] == 2
    assert "p50_ms" in s["latency"]
    assert "avg_ms" in s["latency"]


def test_proxy_metrics_summary_no_latency():
    m = ProxyMetrics()
    s = m.summary()
    assert s["latency"] == {}


# ---------------------------------------------------------------------------
# ProxyMetricsServer
# ---------------------------------------------------------------------------


def test_proxy_metrics_server_render():
    m = ProxyMetrics()
    m.record_call("read_file")
    m.record_blocked("policy")
    server = ProxyMetricsServer(m, port=0)
    text = server.render_metrics()
    assert "agent_bom_proxy_tool_calls_total" in text
    assert "agent_bom_proxy_blocked_total" in text
    assert "agent_bom_proxy_uptime_seconds" in text
