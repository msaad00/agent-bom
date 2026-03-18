"""Tests for output/prometheus.py — coverage expansion."""

from __future__ import annotations

import os
import tempfile
from unittest.mock import MagicMock, patch

import httpx
import pytest

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
from agent_bom.output.prometheus import (
    PushgatewayError,
    _label,
    _labels,
    _metric,
    export_prometheus,
    push_to_gateway,
    to_prometheus,
)


def _make_report_with_blast_radii():
    """Create a minimal report with blast radius data for testing."""
    pkg = Package(name="express", version="4.17.0", ecosystem="npm")
    vuln = Vulnerability(
        id="CVE-2024-1234",
        summary="Test vuln",
        severity=Severity.HIGH,
        cvss_score=7.5,
        epss_score=0.3,
        fixed_version="4.18.2",
        is_kev=True,
    )
    server = MCPServer(name="test-server", transport=TransportType.STDIO, packages=[pkg])
    agent = Agent(name="test-agent", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/test", mcp_servers=[server])
    report = AIBOMReport(agents=[agent])

    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        risk_score=8.5,
        affected_agents=[agent],
        affected_servers=[server],
        exposed_credentials=[],
        exposed_tools=[],
    )
    return report, [br]


class TestHelpers:
    def test_label(self):
        result = _label("key", "value")
        assert result == 'key="value"'

    def test_label_escapes(self):
        result = _label("key", 'val"ue')
        assert '\\"' in result

    def test_labels_empty(self):
        assert _labels() == ""

    def test_labels_multiple(self):
        result = _labels(("a", "1"), ("b", "2"))
        assert 'a="1"' in result
        assert 'b="2"' in result

    def test_metric(self):
        result = _metric("test_metric", 42, ("label", "value"))
        assert "agent_bom_test_metric" in result
        assert "42" in result


class TestToPrometheus:
    def test_basic_report(self):
        report = AIBOMReport(agents=[])
        text = to_prometheus(report)
        assert "agent_bom_info" in text
        assert "agent_bom_agents_total" in text
        assert "agent_bom_packages_total" in text

    def test_with_blast_radii(self):
        report, brs = _make_report_with_blast_radii()
        text = to_prometheus(report, brs)
        assert "agent_bom_blast_radius_score" in text
        assert "CVE-2024-1234" in text
        assert "agent_bom_kev_findings_total" in text
        assert "agent_bom_vulnerability_epss_score" in text
        assert "agent_bom_vulnerability_cvss_score" in text

    def test_per_agent_breakdowns(self):
        report, brs = _make_report_with_blast_radii()
        text = to_prometheus(report, brs)
        assert "agent_bom_agent_vulnerabilities_total" in text
        assert "test-agent" in text

    def test_credentials_exposed(self):
        server = MCPServer(name="s1", transport=TransportType.STDIO, env={"API_KEY": "xxx", "DB_SECRET": "yyy"})
        agent = Agent(name="agent1", agent_type=AgentType.CUSTOM, config_path="/test", mcp_servers=[server])
        report = AIBOMReport(agents=[agent])
        text = to_prometheus(report)
        assert "agent_bom_credentials_exposed_total" in text


class TestExportPrometheus:
    def test_writes_file(self):
        report = AIBOMReport(agents=[])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".prom", delete=False) as f:
            path = f.name
        try:
            export_prometheus(report, path)
            with open(path) as f:
                content = f.read()
            assert "agent_bom_info" in content
        finally:
            os.unlink(path)


class TestPushToGateway:
    def test_invalid_scheme_raises(self):
        report = AIBOMReport(agents=[])
        with pytest.raises(PushgatewayError, match="http"):
            push_to_gateway("ftp://localhost:9091", report)

    def test_successful_push(self):
        report = AIBOMReport(agents=[])
        mock_resp = httpx.Response(
            status_code=200,
            request=httpx.Request("POST", "http://localhost:9091/metrics/job/agent-bom"),
        )
        with patch("agent_bom.http_client.sync_request_with_retry", return_value=mock_resp):
            with patch("agent_bom.http_client.create_sync_client") as mock_client_factory:
                mock_client_factory.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_client_factory.return_value.__exit__ = MagicMock(return_value=False)
                push_to_gateway("http://localhost:9091", report, job="test")

    def test_with_instance(self):
        report = AIBOMReport(agents=[])
        mock_resp = httpx.Response(
            status_code=200,
            request=httpx.Request("POST", "http://localhost:9091/metrics/job/agent-bom/instance/host1"),
        )
        with patch("agent_bom.http_client.sync_request_with_retry", return_value=mock_resp):
            with patch("agent_bom.http_client.create_sync_client") as mock_client_factory:
                mock_client_factory.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_client_factory.return_value.__exit__ = MagicMock(return_value=False)
                push_to_gateway("http://localhost:9091", report, instance="host1")

    def test_http_error_raises(self):
        report = AIBOMReport(agents=[])
        mock_resp = httpx.Response(
            status_code=500,
            text="Server Error",
            request=httpx.Request("POST", "http://localhost:9091/metrics/job/agent-bom"),
        )
        with patch("agent_bom.http_client.sync_request_with_retry", return_value=mock_resp):
            with patch("agent_bom.http_client.create_sync_client") as mock_client_factory:
                mock_client_factory.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_client_factory.return_value.__exit__ = MagicMock(return_value=False)
                with pytest.raises(PushgatewayError):
                    push_to_gateway("http://localhost:9091", report)

    def test_url_error_raises(self):
        report = AIBOMReport(agents=[])
        with patch("agent_bom.http_client.sync_request_with_retry", return_value=None):
            with patch("agent_bom.http_client.create_sync_client") as mock_client_factory:
                mock_client_factory.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_client_factory.return_value.__exit__ = MagicMock(return_value=False)
                with pytest.raises(PushgatewayError):
                    push_to_gateway("http://localhost:9091", report)


# ── Unique tests from cov2 ──────────────────────────────────────────────────


class TestMetricWithLabels:
    def test_metric_with_labels(self):
        result = _metric("vulns", 3, ("severity", "critical"))
        assert "severity=" in result


class TestToPrometheusCritical:
    def test_with_critical(self):
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
        report = AIBOMReport(agents=[], blast_radii=[br])
        text = to_prometheus(report, [br])
        assert "critical" in text.lower() or "CRITICAL" in text
