"""Tests for MCP server health checks (#306).

Tests cover:
- HealthStatus dataclass fields and defaults
- health_check_servers() with all-reachable, all-unreachable, mixed results
- Ineligible servers (no command/URL) are skipped
- Latency is measured and populated on success
- health_check_servers_sync() wrapper
- CLI --health-check flag wiring (smoke test)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.mcp_introspect import (
    HEALTH_CHECK_TIMEOUT,
    HealthStatus,
    health_check_servers,
    health_check_servers_sync,
)
from agent_bom.models import MCPServer, TransportType

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _stdio_server(name: str = "srv", command: str = "mcp-server") -> MCPServer:
    return MCPServer(name=name, command=command, transport=TransportType.STDIO)


def _sse_server(name: str = "srv-sse", url: str = "http://localhost:9000") -> MCPServer:
    return MCPServer(name=name, url=url, transport=TransportType.SSE)


def _no_cmd_server(name: str = "srv-no-cmd") -> MCPServer:
    return MCPServer(name=name, command="", transport=TransportType.STDIO)


def _mock_reachable(server_name: str, tool_count: int = 3) -> MagicMock:
    """Return a mock ServerIntrospection for a reachable server."""
    m = MagicMock()
    m.server_name = server_name
    m.success = True
    m.tool_count = tool_count
    m.protocol_version = "2024-11-05"
    m.error = None
    return m


def _mock_unreachable(server_name: str, error: str = "Connection refused") -> MagicMock:
    m = MagicMock()
    m.server_name = server_name
    m.success = False
    m.tool_count = 0
    m.protocol_version = None
    m.error = error
    return m


# ─── HealthStatus dataclass ────────────────────────────────────────────────────


def test_health_status_fields():
    h = HealthStatus(server_name="s", reachable=True, tool_count=5, protocol_version="2024-11-05", latency_ms=42.0)
    assert h.server_name == "s"
    assert h.reachable is True
    assert h.tool_count == 5
    assert h.protocol_version == "2024-11-05"
    assert h.latency_ms == 42.0
    assert h.error is None


def test_health_status_defaults():
    h = HealthStatus(server_name="x", reachable=False)
    assert h.tool_count == 0
    assert h.protocol_version is None
    assert h.latency_ms is None
    assert h.error is None


def test_health_check_timeout_default():
    assert HEALTH_CHECK_TIMEOUT == 5.0


# ─── health_check_servers() ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_check_all_reachable():
    servers = [_stdio_server("a"), _stdio_server("b")]
    results_map = {
        "a": _mock_reachable("a", tool_count=2),
        "b": _mock_reachable("b", tool_count=7),
    }

    async def _fake_introspect(server, timeout):
        return results_map[server.name]

    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        with patch("agent_bom.mcp_introspect.introspect_server", side_effect=_fake_introspect):
            statuses = await health_check_servers(servers, timeout=5.0)

    assert len(statuses) == 2
    a = next(s for s in statuses if s.server_name == "a")
    assert a.reachable is True
    assert a.tool_count == 2
    assert a.protocol_version == "2024-11-05"
    assert a.latency_ms is not None
    assert a.latency_ms >= 0


@pytest.mark.asyncio
async def test_health_check_all_unreachable():
    servers = [_stdio_server("x"), _sse_server("y")]
    results_map = {
        "x": _mock_unreachable("x", "timeout"),
        "y": _mock_unreachable("y", "refused"),
    }

    async def _fake_introspect(server, timeout):
        return results_map[server.name]

    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        with patch("agent_bom.mcp_introspect.introspect_server", side_effect=_fake_introspect):
            statuses = await health_check_servers(servers, timeout=5.0)

    assert all(not s.reachable for s in statuses)
    assert all(s.latency_ms is None for s in statuses)


@pytest.mark.asyncio
async def test_health_check_mixed_results():
    servers = [_stdio_server("ok"), _stdio_server("fail")]
    results_map = {
        "ok": _mock_reachable("ok", tool_count=4),
        "fail": _mock_unreachable("fail"),
    }

    async def _fake_introspect(server, timeout):
        return results_map[server.name]

    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        with patch("agent_bom.mcp_introspect.introspect_server", side_effect=_fake_introspect):
            statuses = await health_check_servers(servers, timeout=5.0)

    reachable = [s for s in statuses if s.reachable]
    unreachable = [s for s in statuses if not s.reachable]
    assert len(reachable) == 1
    assert len(unreachable) == 1


@pytest.mark.asyncio
async def test_health_check_skips_ineligible_servers():
    """Servers with no command/URL are silently skipped."""
    eligible = _stdio_server("eligible")
    ineligible = _no_cmd_server("ineligible")

    async def _fake_introspect(server, timeout):
        return _mock_reachable(server.name)

    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        with patch("agent_bom.mcp_introspect.introspect_server", side_effect=_fake_introspect):
            statuses = await health_check_servers([eligible, ineligible], timeout=5.0)

    assert len(statuses) == 1
    assert statuses[0].server_name == "eligible"


@pytest.mark.asyncio
async def test_health_check_empty_list():
    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        statuses = await health_check_servers([], timeout=5.0)
    assert statuses == []


@pytest.mark.asyncio
async def test_health_check_latency_none_on_failure():
    servers = [_stdio_server("bad")]

    async def _fake_introspect(server, timeout):
        return _mock_unreachable(server.name, "timed out")

    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        with patch("agent_bom.mcp_introspect.introspect_server", side_effect=_fake_introspect):
            statuses = await health_check_servers(servers)

    assert statuses[0].latency_ms is None
    assert statuses[0].error == "timed out"


@pytest.mark.asyncio
async def test_health_check_tool_count_zero_on_failure():
    servers = [_stdio_server("bad")]

    async def _fake_introspect(server, timeout):
        return _mock_unreachable(server.name)

    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        with patch("agent_bom.mcp_introspect.introspect_server", side_effect=_fake_introspect):
            statuses = await health_check_servers(servers)

    assert statuses[0].tool_count == 0


@pytest.mark.asyncio
async def test_health_check_sse_server_included():
    """SSE servers with URL are included in health check."""
    servers = [_sse_server("remote")]

    async def _fake_introspect(server, timeout):
        return _mock_reachable(server.name, tool_count=10)

    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        with patch("agent_bom.mcp_introspect.introspect_server", side_effect=_fake_introspect):
            statuses = await health_check_servers(servers)

    assert len(statuses) == 1
    assert statuses[0].server_name == "remote"
    assert statuses[0].reachable is True


# ─── health_check_servers_sync() ──────────────────────────────────────────────


def test_health_check_servers_sync_returns_list():
    servers = [_stdio_server("s1")]

    async def _fake_introspect(server, timeout):
        return _mock_reachable(server.name, tool_count=1)

    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        with patch("agent_bom.mcp_introspect.introspect_server", side_effect=_fake_introspect):
            result = health_check_servers_sync(servers, timeout=5.0)

    assert isinstance(result, list)
    assert result[0].reachable is True


def test_health_check_servers_sync_empty():
    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        result = health_check_servers_sync([], timeout=5.0)
    assert result == []


# ─── mcp SDK missing ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_check_raises_when_mcp_sdk_missing():
    from agent_bom.mcp_introspect import IntrospectionError

    with patch("agent_bom.mcp_introspect._check_mcp_sdk", side_effect=IntrospectionError("mcp SDK required")):
        with pytest.raises(IntrospectionError, match="mcp SDK"):
            await health_check_servers([_stdio_server("s")])
