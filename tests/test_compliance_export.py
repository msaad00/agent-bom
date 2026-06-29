"""Tests for CMMC/FedRAMP compliance evidence export."""

import json
import zipfile
from pathlib import Path

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
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
        br.cmmc_tags = ["RA.L2-3.11.2"]
        br.fedramp_tags = ["RA-5"]
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
        assert "manifest.json" in names
        assert "summary.txt" in names


def test_control_mapping_keys(tmp_path: Path):
    report = _make_report()
    out = tmp_path / "evidence.zip"
    export_compliance_bundle(report, "cmmc", str(out))
    with zipfile.ZipFile(str(out)) as zf:
        mapping = json.loads(zf.read("compliance_mapping.json"))
    assert "RA.L2-3.11.2" in mapping
    assert "SI.L2-3.14.1" in mapping
    assert "CM.L2-3.4.3" in mapping
    assert mapping["RA.L2-3.11.2"]["status"] == "fail"
    assert mapping["RA.L2-3.11.2"]["evidence_count"] == 1


def test_framework_specific_controls_are_not_cmmc_for_fedramp(tmp_path: Path):
    report = _make_report()
    out = tmp_path / "evidence.zip"
    export_compliance_bundle(report, "fedramp", str(out))
    with zipfile.ZipFile(str(out)) as zf:
        mapping = json.loads(zf.read("compliance_mapping.json"))
        policy = json.loads(zf.read("policy_results.json"))
    assert policy["framework"] == "fedramp"
    assert "RA-5" in mapping
    assert "RA.L2-3.11.2" not in mapping
    assert mapping["RA-5"]["status"] == "fail"
    assert mapping["RA-5"]["evidence_count"] == 1


def test_vulnerability_report_content(tmp_path: Path):
    report = _make_report()
    out = tmp_path / "evidence.zip"
    export_compliance_bundle(report, "cmmc", str(out))
    with zipfile.ZipFile(str(out)) as zf:
        vulns = json.loads(zf.read("vulnerability_report.json"))
    assert len(vulns) == 1
    assert vulns[0]["id"] == "CVE-2025-1"
    assert vulns[0]["severity"] == "high"


def test_empty_report_is_incomplete_not_pass(tmp_path: Path):
    report = _make_report(with_vulns=False)
    report.agents = []
    out = tmp_path / "evidence.zip"
    export_compliance_bundle(report, "fedramp", str(out))
    with zipfile.ZipFile(str(out)) as zf:
        mapping = json.loads(zf.read("compliance_mapping.json"))
        policy = json.loads(zf.read("policy_results.json"))
        manifest = json.loads(zf.read("manifest.json"))
    assert policy["evidence_completeness"] == "incomplete"
    assert manifest["evidence_completeness"] == "incomplete"
    assert all(ctrl["status"] == "not_evaluated" for ctrl in mapping.values())


def test_partial_report_without_framework_evidence_is_not_evaluated(tmp_path: Path):
    report = _make_report(with_vulns=False)
    out = tmp_path / "evidence.zip"
    export_compliance_bundle(report, "fedramp", str(out))
    with zipfile.ZipFile(str(out)) as zf:
        mapping = json.loads(zf.read("compliance_mapping.json"))
        policy = json.loads(zf.read("policy_results.json"))
    assert policy["evidence_completeness"] == "not_evaluated"
    assert all(ctrl["status"] == "not_evaluated" for ctrl in mapping.values())


def test_summary_text(tmp_path: Path):
    report = _make_report()
    out = tmp_path / "evidence.zip"
    export_compliance_bundle(report, "nist-ai-rmf", str(out))
    with zipfile.ZipFile(str(out)) as zf:
        summary = zf.read("summary.txt").decode()
    assert "NIST AI RMF" in summary
    assert "Vulnerabilities found:" in summary
    assert "Evidence completeness:" in summary


def test_unified_findings_populate_vulnerability_report(tmp_path: Path):
    report = _make_report(with_vulns=False)
    report.findings = [
        Finding(
            finding_type=FindingType.CVE,
            source=FindingSource.SBOM,
            asset=Asset(name="openai", asset_type="package", identifier="pkg:pypi/openai@1.0"),
            severity="high",
            cve_id="CVE-2026-0001",
            fixed_version="2.0",
            risk_score=6.0,
            affected_agents=["claude"],
            affected_servers=["s1"],
            evidence={"package_name": "openai", "package_version": "1.0", "ecosystem": "pypi"},
        )
    ]
    out = tmp_path / "evidence.zip"

    export_compliance_bundle(report, "cmmc", str(out))

    with zipfile.ZipFile(str(out)) as zf:
        vulns = json.loads(zf.read("vulnerability_report.json"))
    assert vulns == [
        {
            "id": "CVE-2026-0001",
            "severity": "high",
            "package": "openai",
            "version": "1.0",
            "fixed_version": "2.0",
            "risk_score": 6.0,
            "affected_agents": ["claude"],
            "affected_servers": ["s1"],
        }
    ]


def test_manifest_has_digests_and_unsigned_status(tmp_path: Path):
    report = _make_report()
    out = tmp_path / "evidence.zip"

    export_compliance_bundle(report, "cmmc", str(out))

    with zipfile.ZipFile(str(out)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        names = zf.namelist()

    assert "signature.json" not in names
    assert manifest["schema_version"] == "agent-bom.compliance_cli_bundle/v1"
    assert manifest["signature"]["status"] == "unsigned_local_bundle"
    assert manifest["files"]["compliance_mapping.json"]["sha256"]
    assert manifest["mapped_evidence_count"] == 1


def test_hmac_signature_when_key_is_set(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY", "test-local-key")
    report = _make_report()
    out = tmp_path / "evidence.zip"

    export_compliance_bundle(report, "cmmc", str(out))

    with zipfile.ZipFile(str(out)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        signature = json.loads(zf.read("signature.json"))

    assert manifest["signature"]["status"] == "signed"
    assert signature["algorithm"] == "HMAC-SHA256"
    assert signature["signature"]


def test_unknown_framework_is_rejected(tmp_path: Path):
    report = _make_report()
    out = tmp_path / "evidence.zip"

    try:
        export_compliance_bundle(report, "fake-framework", str(out))
    except ValueError as exc:
        assert "unsupported compliance framework" in str(exc)
    else:
        raise AssertionError("unsupported compliance framework should fail")
