"""Only application-shaped evidence mints ASPM application nodes.

A package, agent, or MCP server finding has no application identity of its own.
Falling back to its asset name typed ``pyyaml`` and ``project:sampleapp`` as
applications, and treating an MCP launch command as a source path labelled an
application ``npx -y @modelcontextprotocol/...``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.graph.aspm_overlay import apply_aspm_overlay
from agent_bom.graph.container import UnifiedGraph

NOW = datetime(2026, 9, 26, tzinfo=timezone.utc)


def _finding(*, asset_type: str, name: str, location: str | None, source: str = "MCP_SCAN") -> dict:
    return {
        "source": source,
        "severity": "critical",
        "effective_severity": "critical",
        "cve_id": "CVE-2025-7783",
        "title": "CVE-2025-7783",
        "finding_type": "CVE",
        "asset": {"name": name, "asset_type": asset_type, "location": location, "stable_id": f"{asset_type}:{name}"},
    }


def _applications(findings: list[dict]) -> list[str]:
    graph = UnifiedGraph(scan_id="s1")
    apply_aspm_overlay(graph, {"findings": findings}, NOW)
    return sorted(node.label for node in graph.nodes.values() if node.id.startswith("application:"))


def test_mcp_launch_command_is_not_an_application() -> None:
    assert _applications([_finding(asset_type="mcp_server", name="github", location="npx -y @modelcontextprotocol/server-github")]) == []


def test_package_name_is_not_an_application() -> None:
    assert _applications([_finding(asset_type="package", name="pyyaml", location=None)]) == []


def test_agent_name_is_not_an_application() -> None:
    assert _applications([_finding(asset_type="agent", name="project:sampleapp", location=None, source="GRAPH_ANALYSIS")]) == []


def test_real_source_paths_and_resource_names_still_derive_applications() -> None:
    assert _applications(
        [
            _finding(asset_type="package", name="pyyaml", location="services/billing/requirements.txt", source="SBOM"),
            _finding(asset_type="cloud_resource", name="payments-api", location=None, source="CLOUD_CIS"),
        ]
    ) == ["payments-api", "services/billing"]
