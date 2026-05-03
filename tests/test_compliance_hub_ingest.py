"""Tests for hub-driven finding classification + SARIF ingestion (#1044 PR B).

Two contracts to lock in:

1. **Native generators call the hub** — `blast_radius_to_finding` and
   `mcp_blocklist.blocklist_findings_for_agents` produce findings whose
   `applicable_frameworks` matches `select_frameworks(...)` for that
   source/asset/finding-type. Any future generator that bypasses the hub
   is a bug — the hub is the single source of truth.

2. **External SARIF flows through the same hub** — a SARIF result lands
   as a `Finding(source=EXTERNAL)` with the same framework-selection
   semantics. CWE tags lift from rule properties; severity coerces from
   `security-severity` (preferred) or `level` (fallback). Rule-id and
   message text drive finding-type inference (CREDENTIAL_EXPOSURE,
   INJECTION, etc.) so the hub's finding-type refinements kick in.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.compliance_hub import (
    FRAMEWORK_ATLAS,
    FRAMEWORK_ISO_27001,
    FRAMEWORK_NIST_AI_RMF,
    FRAMEWORK_NIST_CSF,
    FRAMEWORK_OWASP_AGENTIC,
    FRAMEWORK_OWASP_LLM,
    FRAMEWORK_OWASP_MCP,
    FRAMEWORK_SOC2,
    select_frameworks,
)
from agent_bom.compliance_hub_ingest import ingest_sarif_findings
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.mcp_blocklist import blocklist_findings_for_agents
from agent_bom.models import (
    Agent,
    AgentStatus,
    AgentType,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)

# ─── Native-generator wiring ──────────────────────────────────────────────────


def _make_agent_with_blocklisted_server(name: str = "claude") -> Agent:
    server = MCPServer(
        name="evil-mcp-server",
        command="npx",
        args=["evil-mcp-server"],
        transport=TransportType.STDIO,
        registry_id="evil-mcp-server",
    )
    return Agent(
        name=name,
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test.json",
        mcp_servers=[server],
        status=AgentStatus.CONFIGURED,
    )


def test_blocklist_findings_carry_hub_framework_classification():
    """An MCP_BLOCKLIST finding must carry the AI framework set the hub
    selects for source=MCP_SCAN + asset_type=mcp_server."""
    agent = _make_agent_with_blocklisted_server()
    blocklist = {
        "version": "1",
        "entries": [
            {
                "id": "test-entry-001",
                "names": ["evil-mcp-server"],
                "severity": "high",
                "title": "Test malicious server",
                "description": "Test entry",
                "source": "test",
            }
        ],
    }
    findings = blocklist_findings_for_agents([agent], blocklist=blocklist)
    assert findings, "blocklist match should produce a finding"

    expected = set(
        select_frameworks(
            FindingSource.MCP_SCAN,
            asset_type="mcp_server",
            finding_type=FindingType.MCP_BLOCKLIST,
        )
    )
    actual = set(findings[0].applicable_frameworks)
    assert expected.issubset(actual), f"blocklist finding missing frameworks {sorted(expected - actual)} (got {sorted(actual)})"
    # AI frameworks must be present (this is an MCP server finding)
    assert FRAMEWORK_OWASP_LLM in actual
    assert FRAMEWORK_OWASP_MCP in actual
    assert FRAMEWORK_ATLAS in actual


def test_blast_radius_to_finding_carries_hub_classification():
    pkg = Package(name="left-pad", version="1.0.0", ecosystem="npm")
    server = MCPServer(name="srv", command="npx", args=["srv"], transport=TransportType.STDIO, packages=[pkg])
    vuln = Vulnerability(
        id="CVE-2025-0000",
        summary="test cve",
        severity=Severity.HIGH,
    )
    br = BlastRadius(
        package=pkg,
        vulnerability=vuln,
        affected_servers=[server],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )

    from agent_bom.finding import blast_radius_to_finding

    finding = blast_radius_to_finding(br)
    assert finding.source == FindingSource.MCP_SCAN
    assert finding.asset.asset_type == "mcp_server"
    expected = set(
        select_frameworks(
            FindingSource.MCP_SCAN,
            asset_type="mcp_server",
            finding_type=FindingType.CVE,
        )
    )
    assert expected.issubset(set(finding.applicable_frameworks))


def test_finding_to_dict_emits_applicable_frameworks():
    """The serialised payload must surface the new field so API/UI
    consumers can render the framework set without reaching back into
    the hub."""
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="srv", asset_type="mcp_server"),
        severity="high",
        applicable_frameworks=["owasp-llm", "atlas"],
    )
    payload = finding.to_dict()
    assert payload["applicable_frameworks"] == ["owasp-llm", "atlas"]


# ─── SARIF ingestion ──────────────────────────────────────────────────────────


@pytest.fixture
def sarif_with_secret_finding(tmp_path: Path) -> Path:
    """A minimal SARIF 2.1.0 doc carrying a secret-scanner result."""
    doc = {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "external-secret-scanner",
                        "rules": [
                            {
                                "id": "SECRET-AWS-ACCESS-KEY",
                                "shortDescription": {"text": "AWS access key in source"},
                                "properties": {"tags": ["security", "secret", "CWE-798"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "SECRET-AWS-ACCESS-KEY",
                        "level": "error",
                        "message": {"text": "Hardcoded AWS access key"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/config.py"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                        "properties": {"security-severity": "9.5"},
                    }
                ],
            }
        ],
    }
    target = tmp_path / "secrets.sarif"
    target.write_text(json.dumps(doc), encoding="utf-8")
    return target


def test_sarif_ingest_produces_external_finding(sarif_with_secret_finding: Path):
    findings = ingest_sarif_findings(sarif_with_secret_finding)
    assert len(findings) == 1
    f = findings[0]
    assert f.source == FindingSource.EXTERNAL
    assert f.evidence["external_tool"] == "external-secret-scanner"
    assert f.evidence["rule_id"] == "SECRET-AWS-ACCESS-KEY"
    assert f.severity == "critical"  # security-severity 9.5 → critical
    assert f.cwe_ids == ["CWE-798"]
    assert f.asset.location == "src/config.py"
    assert f.asset.name == "src/config.py:42"


def test_sarif_secret_finding_pulls_in_enterprise_audit_frameworks(sarif_with_secret_finding: Path):
    """Rule id contains 'SECRET' → finding_type=CREDENTIAL_EXPOSURE → hub
    refinement adds NIST CSF / ISO 27001 / SOC 2 even though the source
    is EXTERNAL."""
    findings = ingest_sarif_findings(sarif_with_secret_finding)
    f = findings[0]
    assert f.finding_type == FindingType.CREDENTIAL_EXPOSURE
    for fw in (FRAMEWORK_NIST_CSF, FRAMEWORK_ISO_27001, FRAMEWORK_SOC2):
        assert fw in f.applicable_frameworks, f"CREDENTIAL_EXPOSURE must include {fw}; got {f.applicable_frameworks}"


def test_sarif_injection_rule_lights_up_ai_frameworks(tmp_path: Path):
    """A SARIF result whose rule mentions 'injection' must surface AI
    frameworks via the hub's finding-type refinement, even though the
    source is EXTERNAL and could otherwise be anything."""
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "semgrep",
                        "rules": [
                            {"id": "prompt-injection-detector", "shortDescription": {"text": "Prompt injection"}},
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "prompt-injection-detector",
                        "level": "error",
                        "message": {"text": "Possible prompt injection"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "agent.py"}}}],
                    }
                ],
            }
        ],
    }
    sarif = tmp_path / "injection.sarif"
    sarif.write_text(json.dumps(doc), encoding="utf-8")
    findings = ingest_sarif_findings(sarif)
    assert findings
    f = findings[0]
    assert f.finding_type == FindingType.INJECTION
    for fw in (FRAMEWORK_OWASP_LLM, FRAMEWORK_OWASP_AGENTIC, FRAMEWORK_ATLAS, FRAMEWORK_NIST_AI_RMF):
        assert fw in f.applicable_frameworks


def test_sarif_severity_falls_back_to_level_when_no_security_severity(tmp_path: Path):
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "x", "rules": []}},
                "results": [
                    {
                        "ruleId": "R1",
                        "level": "warning",
                        "message": {"text": "minor issue"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}],
                    }
                ],
            }
        ],
    }
    sarif = tmp_path / "level.sarif"
    sarif.write_text(json.dumps(doc), encoding="utf-8")
    findings = ingest_sarif_findings(sarif)
    assert findings[0].severity == "medium"  # warning → medium


def test_sarif_missing_file_returns_empty_list(tmp_path: Path):
    findings = ingest_sarif_findings(tmp_path / "does-not-exist.sarif")
    assert findings == []


def test_sarif_malformed_json_returns_empty_list_no_crash(tmp_path: Path):
    bad = tmp_path / "bad.sarif"
    bad.write_text("not json {", encoding="utf-8")
    assert ingest_sarif_findings(bad) == []


def test_sarif_zero_runs_zero_results_does_not_crash(tmp_path: Path):
    sarif = tmp_path / "empty.sarif"
    sarif.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")
    assert ingest_sarif_findings(sarif) == []


def test_sarif_finding_serialises_with_applicable_frameworks(sarif_with_secret_finding: Path):
    findings = ingest_sarif_findings(sarif_with_secret_finding)
    payload = findings[0].to_dict()
    assert "applicable_frameworks" in payload
    assert FRAMEWORK_NIST_CSF in payload["applicable_frameworks"]
