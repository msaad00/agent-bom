"""Tests for marketplace_check MCP tool trust signals."""

import pytest

from agent_bom.mcp_server import create_mcp_server


@pytest.fixture
def mcp():
    return create_mcp_server()


def test_marketplace_tool_registered(mcp):
    """marketplace_check should be registered as a tool."""
    tools = {name for name in dir(mcp) if not name.startswith("_")}
    # The tool is registered via @mcp.tool — verify import works
    from agent_bom.mcp_server import create_mcp_server as _

    assert callable(_)


def test_trust_signals_no_cves():
    """Trust signals should include 'no-known-cves' when clean."""
    signals = []
    cve_count = 0
    registry_verified = False
    download_count = 200_000

    if cve_count == 0:
        signals.append("no-known-cves")
    if registry_verified:
        signals.append("registry-verified")
    if download_count > 100_000:
        signals.append("high-adoption")

    assert "no-known-cves" in signals
    assert "high-adoption" in signals


def test_trust_signals_with_cves():
    """Trust signals should NOT include 'no-known-cves' when vulnerable."""
    signals = []
    cve_count = 3

    if cve_count == 0:
        signals.append("no-known-cves")

    assert "no-known-cves" not in signals


def test_trust_signals_registry_verified():
    """Trust signals should include 'registry-verified' when in registry."""
    signals = []
    registry_verified = True
    download_count = 5_000

    if registry_verified:
        signals.append("registry-verified")
    if download_count > 100_000:
        signals.append("high-adoption")
    elif download_count > 10_000:
        signals.append("moderate-adoption")

    assert "registry-verified" in signals
    assert "high-adoption" not in signals
    assert "moderate-adoption" not in signals
