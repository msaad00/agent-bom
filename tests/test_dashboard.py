"""Tests for the Streamlit dashboard data extraction helpers."""

from __future__ import annotations

import pytest


@pytest.fixture()
def sample_report() -> dict:
    """Minimal agent-bom JSON report for testing."""
    return {
        "document_type": "AI-BOM",
        "spec_version": "1.0",
        "ai_bom_version": "0.54.0",
        "generated_at": "2026-03-05T12:00:00Z",
        "summary": {
            "total_agents": 1,
            "total_mcp_servers": 1,
            "total_packages": 3,
            "total_vulnerabilities": 2,
            "critical_findings": 1,
        },
        "agents": [
            {
                "name": "test-agent",
                "type": "custom",
                "config_path": "/tmp/test",
                "source": "local",
                "status": "configured",
                "mcp_servers": [
                    {
                        "name": "test-server",
                        "command": "node server.js",
                        "args": [],
                        "transport": "stdio",
                        "url": None,
                        "mcp_version": None,
                        "has_credentials": True,
                        "credential_env_vars": ["API_KEY"],
                        "tools": [{"name": "search", "description": "Search"}],
                        "packages": [
                            {
                                "name": "express",
                                "version": "4.17.1",
                                "ecosystem": "npm",
                                "purl": "pkg:npm/express@4.17.1",
                                "is_direct": True,
                                "license": "MIT",
                                "vulnerabilities": [
                                    {
                                        "id": "CVE-2024-1234",
                                        "summary": "Test vuln",
                                        "severity": "critical",
                                        "cvss_score": 9.8,
                                        "epss_score": 0.95,
                                        "is_kev": True,
                                        "fixed_version": "4.18.0",
                                    },
                                    {
                                        "id": "CVE-2024-5678",
                                        "summary": "Another vuln",
                                        "severity": "high",
                                        "cvss_score": 7.5,
                                        "epss_score": 0.3,
                                        "is_kev": False,
                                        "fixed_version": "4.18.0",
                                    },
                                ],
                            },
                            {
                                "name": "lodash",
                                "version": "4.17.21",
                                "ecosystem": "npm",
                                "purl": "pkg:npm/lodash@4.17.21",
                                "is_direct": True,
                                "license": "MIT",
                                "vulnerabilities": [],
                            },
                            {
                                "name": "requests",
                                "version": "2.28.0",
                                "ecosystem": "pypi",
                                "purl": "pkg:pypi/requests@2.28.0",
                                "is_direct": True,
                                "license": "Apache-2.0",
                                "vulnerabilities": [],
                            },
                        ],
                        "permission_profile": None,
                    }
                ],
            }
        ],
        "blast_radius": [
            {
                "risk_score": 9.5,
                "vulnerability_id": "CVE-2024-1234",
                "severity": "critical",
                "cvss_score": 9.8,
                "epss_score": 0.95,
                "is_kev": True,
                "package": "express@4.17.1",
                "ecosystem": "npm",
                "affected_agents": ["test-agent"],
                "affected_servers": ["test-server"],
                "exposed_credentials": ["API_KEY"],
                "exposed_tools": ["search"],
                "fixed_version": "4.18.0",
                "owasp_tags": ["LLM06"],
                "atlas_tags": ["AML.T0040"],
            },
        ],
        "threat_framework_summary": {
            "owasp_llm_top10": {
                "overall_score": 75,
                "overall_status": "warning",
                "controls": [
                    {"id": "LLM01", "name": "Prompt Injection", "status": "pass", "score": 100},
                    {"id": "LLM06", "name": "Sensitive Info", "status": "fail", "score": 0},
                ],
            },
        },
        "posture_scorecard": {
            "grade": "B",
            "score": 78,
            "summary": "Good with some issues",
            "dimensions": {
                "vulnerability_management": {"score": 60},
                "credential_hygiene": {"score": 80},
                "supply_chain": {"score": 90},
            },
        },
    }


class TestExtractPackages:
    def test_extracts_all_packages(self, sample_report):
        from dashboard.data import extract_packages

        df = extract_packages(sample_report)
        # express has 2 vulns + lodash (0 vulns) + requests (0 vulns) = 4 rows
        assert len(df) == 4

    def test_vuln_fields(self, sample_report):
        from dashboard.data import extract_packages

        df = extract_packages(sample_report)
        critical = df[df["vuln_id"] == "CVE-2024-1234"]
        assert len(critical) == 1
        assert critical.iloc[0]["severity"] == "critical"
        assert critical.iloc[0]["cvss"] == 9.8
        assert bool(critical.iloc[0]["is_kev"]) is True

    def test_clean_packages(self, sample_report):
        from dashboard.data import extract_packages

        df = extract_packages(sample_report)
        clean = df[df["vuln_id"] == ""]
        assert len(clean) == 2  # lodash + requests

    def test_empty_report(self):
        from dashboard.data import extract_packages

        df = extract_packages({})
        assert df.empty

    def test_ecosystems(self, sample_report):
        from dashboard.data import extract_packages

        df = extract_packages(sample_report)
        ecosystems = set(df["ecosystem"].unique())
        assert "npm" in ecosystems
        assert "pypi" in ecosystems


class TestExtractBlastRadius:
    def test_extracts_blast_radius(self, sample_report):
        from dashboard.data import extract_blast_radius

        df = extract_blast_radius(sample_report)
        assert len(df) == 1
        assert df.iloc[0]["vuln_id"] == "CVE-2024-1234"
        assert df.iloc[0]["risk_score"] == 9.5

    def test_exposed_credentials(self, sample_report):
        from dashboard.data import extract_blast_radius

        df = extract_blast_radius(sample_report)
        assert "API_KEY" in df.iloc[0]["exposed_creds"]

    def test_affected_agents(self, sample_report):
        from dashboard.data import extract_blast_radius

        df = extract_blast_radius(sample_report)
        assert "test-agent" in df.iloc[0]["affected_agents"]

    def test_empty_report(self):
        from dashboard.data import extract_blast_radius

        df = extract_blast_radius({})
        assert df.empty

    def test_compliance_tags(self, sample_report):
        from dashboard.data import extract_blast_radius

        df = extract_blast_radius(sample_report)
        assert "LLM06" in df.iloc[0]["owasp_tags"]
