"""Tests for CMMC/FedRAMP compliance evidence export."""

import json
import zipfile
from pathlib import Path

from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.output import export_compliance_bundle


def _make_report(with_vulns: bool = True) -> AIBOMReport:
    agents = [Agent(name="claude", agent_type=AgentType.CLAUDE_CODE, config_path="/tmp")]
    blast_radii = []
    if with_vulns:
        vuln = Vulnerability(id="CVE-2025-1", summary="test", severity=Severity.HIGH, fixed_version="2.0")
        pkg = Package(name="openai", version="1.0", ecosystem="pypi")
        br = BlastRadius(
            vulnerability=vuln,
            package=pkg,
            affected_servers=[MCPServer(name="s1")],
            affected_agents=agents,
            exposed_credentials=[],
            exposed_tools=[],
            risk_score=6.0,
        )
        blast_radii.append(br)
    return AIBOMReport(agents=agents, blast_radii=blast_radii)


def test_zip_structure(tmp_path: Path):
    report = _make_report()
    out = tmp_path / "evidence.zip"
    result = export_compliance_bundle(report, "cmmc", str(out))
    assert Path(result).exists()
    with zipfile.ZipFile(result) as zf:
        names = zf.namelist()
        assert "sbom.cdx.json" in names
        assert "vulnerability_report.json" in names
        assert "policy_results.json" in names
        assert "compliance_mapping.json" in names
        assert "summary.txt" in names


def test_control_mapping_keys(tmp_path: Path):
    report = _make_report()
    out = tmp_path / "evidence.zip"
    export_compliance_bundle(report, "cmmc", str(out))
    with zipfile.ZipFile(str(out)) as zf:
        mapping = json.loads(zf.read("compliance_mapping.json"))
    assert "CM-8" in mapping
    assert "SI-2" in mapping
    assert "SR-3" in mapping
    assert "RA-3" in mapping
    assert "AU-2" in mapping


def test_vulnerability_report_content(tmp_path: Path):
    report = _make_report()
    out = tmp_path / "evidence.zip"
    export_compliance_bundle(report, "cmmc", str(out))
    with zipfile.ZipFile(str(out)) as zf:
        vulns = json.loads(zf.read("vulnerability_report.json"))
    assert len(vulns) == 1
    assert vulns[0]["id"] == "CVE-2025-1"
    assert vulns[0]["severity"] == "high"


def test_clean_report_produces_pass(tmp_path: Path):
    report = _make_report(with_vulns=False)
    out = tmp_path / "evidence.zip"
    export_compliance_bundle(report, "fedramp", str(out))
    with zipfile.ZipFile(str(out)) as zf:
        mapping = json.loads(zf.read("compliance_mapping.json"))
    for ctrl in mapping.values():
        assert ctrl["status"] == "pass"


def test_summary_text(tmp_path: Path):
    report = _make_report()
    out = tmp_path / "evidence.zip"
    export_compliance_bundle(report, "nist-ai-rmf", str(out))
    with zipfile.ZipFile(str(out)) as zf:
        summary = zf.read("summary.txt").decode()
    assert "NIST-AI-RMF" in summary
    assert "Vulnerabilities found:" in summary
