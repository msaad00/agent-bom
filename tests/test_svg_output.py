"""Tests for static SVG graph output."""

from __future__ import annotations

import re

import pytest

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output.svg import to_svg


def _large_package_report(count: int = 90) -> AIBOMReport:
    packages = [Package(name=f"pkg-{idx:03d}", version="1.0.0", ecosystem="npm") for idx in range(count)]
    server = MCPServer(name="registry", command="npx", packages=packages)
    agent = Agent(
        name="analyst-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude_desktop_config.json",
        mcp_servers=[server],
    )
    return AIBOMReport(agents=[agent])


def _svg_height(svg: str) -> int:
    match = re.search(r'height="(\d+)"', svg)
    assert match is not None
    return int(match.group(1))


def test_svg_output_bounds_large_package_columns_by_default() -> None:
    svg = to_svg(_large_package_report(), [])

    assert _svg_height(svg) <= 3600
    assert "1 agents | 1 servers | 90 packages | 0 CVEs" in svg
    assert "pkg-000@1.0.0" in svg
    assert "pkg-089@1.0.0" not in svg
    assert "more packages omitted" in svg
    assert "Bounded view:" in svg
    assert "export JSON/DOT/GraphML/Cypher for full graph" in svg
    assert "<metadata>Bounded SVG export:" in svg
    assert 'preserveAspectRatio="xMinYMin meet"' in svg


def test_svg_output_can_render_full_graph_when_requested() -> None:
    svg = to_svg(_large_package_report(), [], max_rows_per_column=None)

    assert "pkg-089@1.0.0" in svg
    assert "more packages omitted" not in svg
    assert "Bounded view:" not in svg


def test_svg_output_rejects_unreadable_row_limit() -> None:
    with pytest.raises(ValueError, match="max_rows_per_column"):
        to_svg(_large_package_report(), [], max_rows_per_column=1)
