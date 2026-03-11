"""Tests for agent_bom.output.prometheus to improve coverage."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.output.prometheus import _label, _labels, _metric, to_prometheus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report(agents=None, blast_radii=None):
    return AIBOMReport(
        agents=agents or [],
        blast_radii=blast_radii or [],
        generated_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# _label / _labels / _metric
# ---------------------------------------------------------------------------


def test_label_basic():
    assert _label("name", "value") == 'name="value"'


def test_label_escape():
    result = _label("name", 'val"ue')
    assert '\\"' in result


def test_labels_empty():
    assert _labels() == ""


def test_labels_multiple():
    result = _labels(("a", "1"), ("b", "2"))
    assert "a=" in result
    assert "b=" in result


def test_metric():
    result = _metric("total_agents", 5)
    assert "agent_bom_total_agents 5" in result


def test_metric_with_labels():
    result = _metric("vulns", 3, ("severity", "critical"))
    assert "severity=" in result


# ---------------------------------------------------------------------------
# to_prometheus
# ---------------------------------------------------------------------------


def test_to_prometheus_empty():
    report = _make_report()
    text = to_prometheus(report, [])
    assert "agent_bom" in text


def test_to_prometheus_with_agents():
    vuln = Vulnerability(id="CVE-2025-0001", severity=Severity.HIGH, summary="test", fixed_version="2.0")
    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm", vulnerabilities=[vuln])
    srv = MCPServer(name="srv", command="node", transport=TransportType.STDIO, packages=[pkg])
    agent = Agent(
        name="agent1",
        agent_type=AgentType.CUSTOM,
        config_path="/test",
        mcp_servers=[srv],
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_agents=[agent],
        affected_servers=[srv],
        exposed_credentials=["KEY"],
        exposed_tools=[],
    )
    report = _make_report(agents=[agent], blast_radii=[br])
    text = to_prometheus(report, [br])
    assert "agent_bom" in text


def test_to_prometheus_with_critical():
    vuln = Vulnerability(id="CVE-1", severity=Severity.CRITICAL, summary="test")
    pkg = Package(name="pkg", version="1.0", ecosystem="pypi", vulnerabilities=[vuln])
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_agents=[],
        affected_servers=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    report = _make_report(blast_radii=[br])
    text = to_prometheus(report, [br])
    assert "critical" in text.lower() or "CRITICAL" in text
