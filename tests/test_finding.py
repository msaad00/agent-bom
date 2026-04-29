"""Tests for the unified Finding model (issue #566, Phase 1)."""

import json

import pytest

from agent_bom.finding import (
    Asset,
    Finding,
    FindingSource,
    FindingType,
    blast_radius_to_finding,
)
from agent_bom.models import (
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    PackageOccurrence,
    Severity,
    TransportType,
    Vulnerability,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_vuln(
    vuln_id="CVE-2024-9999",
    severity=Severity.HIGH,
    cvss_score=7.5,
    fixed_version="1.2.3",
    is_kev=False,
) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        summary="Test vulnerability",
        severity=severity,
        cvss_score=cvss_score,
        fixed_version=fixed_version,
        is_kev=is_kev,
    )


def _make_package(name="requests", version="2.0.0", ecosystem="pypi") -> Package:
    return Package(name=name, version=version, ecosystem=ecosystem)


def _make_server(name="test-server") -> MCPServer:
    return MCPServer(
        name=name,
        command="npx test-server",
        transport=TransportType.STDIO,
    )


_SENTINEL = object()


def _make_blast_radius(
    vuln_id="CVE-2024-9999",
    severity=Severity.HIGH,
    servers=_SENTINEL,
    credentials=None,
) -> BlastRadius:
    servers = [_make_server()] if servers is _SENTINEL else servers
    credentials = credentials or ["OPENAI_API_KEY"]
    return BlastRadius(
        vulnerability=_make_vuln(vuln_id=vuln_id, severity=severity),
        package=_make_package(),
        affected_servers=servers,
        affected_agents=[],
        exposed_credentials=credentials,
        exposed_tools=[],
        risk_score=7.0,
        owasp_tags=["LLM05"],
        atlas_tags=["AML.T0010"],
        attack_tags=["T1190"],
        nist_ai_rmf_tags=["MAP-3.5"],
        owasp_mcp_tags=["MCP04"],
        owasp_agentic_tags=["ASI04"],
        eu_ai_act_tags=["ART-15"],
        nist_csf_tags=["ID.RA-01"],
        iso_27001_tags=["A.8.8"],
        soc2_tags=["CC7.1"],
        cis_tags=["CIS-07.1"],
    )


# ---------------------------------------------------------------------------
# FindingType and FindingSource enums
# ---------------------------------------------------------------------------


def test_finding_type_values():
    assert FindingType.CVE == "CVE"
    assert FindingType.CIS_FAIL == "CIS_FAIL"
    assert FindingType.TOOL_DRIFT == "TOOL_DRIFT"


def test_finding_source_values():
    assert FindingSource.MCP_SCAN == "MCP_SCAN"
    assert FindingSource.PROXY == "PROXY"
    assert FindingSource.EXTERNAL == "EXTERNAL"


# ---------------------------------------------------------------------------
# Asset dataclass
# ---------------------------------------------------------------------------


def test_asset_minimal():
    asset = Asset(name="test-server", asset_type="mcp_server")
    assert asset.name == "test-server"
    assert asset.asset_type == "mcp_server"
    assert asset.identifier is None
    assert asset.location is None


def test_asset_full():
    asset = Asset(
        name="requests",
        asset_type="package",
        identifier="pkg:pypi/requests@2.0.0",
        location="/path/to/requirements.txt",
    )
    assert asset.identifier == "pkg:pypi/requests@2.0.0"


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


def test_finding_auto_id():
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="pkg", asset_type="package"),
        severity="HIGH",
    )
    assert finding.id  # auto-generated UUID
    assert len(finding.id) == 36  # UUID4 format


def test_finding_same_content_produces_same_id():
    """IDs are now deterministic — same content always yields same ID."""
    f1 = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="pkg", asset_type="package"),
        severity="HIGH",
    )
    f2 = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="pkg", asset_type="package"),
        severity="HIGH",
    )
    assert f1.id == f2.id


def test_finding_different_assets_produce_different_ids():
    """Different assets → different Finding IDs even with same CVE."""
    f1 = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="pkg-a", asset_type="package"),
        severity="HIGH",
    )
    f2 = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="pkg-b", asset_type="package"),
        severity="HIGH",
    )
    assert f1.id != f2.id


def test_finding_effective_severity_vendor_wins():
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="pkg", asset_type="package"),
        severity="MEDIUM",
        vendor_severity="HIGH",
        cvss_severity="LOW",
    )
    assert finding.effective_severity() == "HIGH"


def test_finding_effective_severity_cvss_fallback():
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="pkg", asset_type="package"),
        severity="MEDIUM",
        vendor_severity=None,
        cvss_severity="LOW",
    )
    assert finding.effective_severity() == "LOW"


def test_finding_effective_severity_base_fallback():
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="pkg", asset_type="package"),
        severity="HIGH",
    )
    assert finding.effective_severity() == "HIGH"


def test_finding_all_compliance_tags_deduplicates():
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="pkg", asset_type="package"),
        severity="HIGH",
        owasp_tags=["LLM05"],
        compliance_tags=["LLM05"],  # duplicate
        atlas_tags=["AML.T0010"],
    )
    tags = finding.all_compliance_tags()
    assert tags.count("LLM05") == 1
    assert "AML.T0010" in tags


# ---------------------------------------------------------------------------
# blast_radius_to_finding
# ---------------------------------------------------------------------------


def test_blast_radius_to_finding_type_error():
    with pytest.raises(TypeError, match="Expected BlastRadius"):
        blast_radius_to_finding("not a blast radius")


def test_blast_radius_to_finding_cve_type():
    br = _make_blast_radius()
    finding = blast_radius_to_finding(br)
    assert finding.finding_type == FindingType.CVE
    assert finding.source == FindingSource.MCP_SCAN


def test_blast_radius_to_finding_severity_mapped():
    br = _make_blast_radius(severity=Severity.CRITICAL)
    finding = blast_radius_to_finding(br)
    assert finding.severity == "critical"


def test_blast_radius_to_finding_cve_id():
    br = _make_blast_radius(vuln_id="CVE-2024-1234")
    finding = blast_radius_to_finding(br)
    assert finding.cve_id == "CVE-2024-1234"


def test_blast_radius_to_finding_asset_uses_server():
    br = _make_blast_radius(servers=[_make_server("my-mcp-server")])
    finding = blast_radius_to_finding(br)
    assert finding.asset.name == "my-mcp-server"
    assert finding.asset.asset_type == "mcp_server"


def test_blast_radius_to_finding_asset_uses_package_when_no_servers():
    br = _make_blast_radius(servers=[])
    finding = blast_radius_to_finding(br)
    assert finding.asset.asset_type == "package"
    assert finding.asset.name == "requests"


def test_blast_radius_to_finding_compliance_tags_carried():
    br = _make_blast_radius()
    finding = blast_radius_to_finding(br)
    assert finding.owasp_tags == ["LLM05"]
    assert finding.atlas_tags == ["AML.T0010"]
    assert finding.nist_csf_tags == ["ID.RA-01"]
    assert finding.soc2_tags == ["CC7.1"]


def test_blast_radius_to_finding_risk_score():
    br = _make_blast_radius()
    finding = blast_radius_to_finding(br)
    assert finding.risk_score == 7.0


def test_blast_radius_to_finding_kev():
    br = _make_blast_radius()
    br.vulnerability.is_kev = True
    finding = blast_radius_to_finding(br)
    assert finding.is_kev is True


def test_blast_radius_to_finding_evidence_has_package_info():
    br = _make_blast_radius()
    finding = blast_radius_to_finding(br)
    assert finding.evidence["package_name"] == "requests"
    assert finding.evidence["package_version"] == "2.0.0"
    assert finding.evidence["exposed_credential_count"] == 1


def test_blast_radius_to_finding_preserves_sanitized_reachability_evidence():
    raw_github_token = "ghp_" + "abcdefghijklmnopqrstuvwxyz" + "1234567890"
    raw_slack_token = "xoxb-" + "1234567890-" + "1234567890-" + "abcdefghijklmnopqrstuv"
    br = _make_blast_radius()
    br.hop_depth = 3
    br.delegation_chain = [f"test-server -> {raw_slack_token} -> delegated-agent"]
    br.transitive_agents = [
        {
            "name": "delegated-agent",
            "hop": 2,
            "token": raw_github_token,
            "config_path": "/Users/alice/.config/agent-bom/private-agent.json",
        }
    ]
    br.transitive_servers = [
        {
            "name": "delegated-server",
            "url": "https://user:" + "password@example.com/mcp?token=raw",
        }
    ]
    br.transitive_packages = [
        {
            "name": "transitive-lib",
            "version": "1.0.0",
            "download_url": "https://user:" + "password@registry.example.com/transitive-lib.tgz?token=raw",
        }
    ]
    br.transitive_credentials = ["AWS_SECRET_ACCESS_KEY"]
    br.transitive_risk_score = 4.2
    br.graph_reachable = True
    br.graph_min_hop_distance = 2
    br.graph_reachable_from_agents = ["delegated-agent"]

    finding = blast_radius_to_finding(br)

    assert finding.evidence["hop_depth"] == 3
    assert finding.evidence["delegation_chain"] == ["test-server -> <redacted> -> delegated-agent"]
    assert finding.evidence["transitive_agents"][0]["name"] == "delegated-agent"
    assert finding.evidence["transitive_agents"][0]["hop"] == 2
    assert finding.evidence["transitive_agents"][0]["token"] == "***REDACTED***"
    assert finding.evidence["transitive_agents"][0]["config_path"] == "<path:private-agent.json>"
    assert finding.evidence["transitive_servers"][0]["name"] == "delegated-server"
    assert finding.evidence["transitive_servers"][0]["url"] == "https://example.com/mcp"
    assert finding.evidence["transitive_packages"][0]["name"] == "transitive-lib"
    assert finding.evidence["transitive_packages"][0]["download_url"] == "https://registry.example.com/transitive-lib.tgz"
    assert finding.evidence["transitive_credential_count"] == 1
    assert finding.evidence["transitive_risk_score"] == 4.2
    assert finding.evidence["graph_reachable"] is True
    assert finding.evidence["graph_min_hop_distance"] == 2
    assert finding.evidence["graph_reachable_from_agents"] == ["delegated-agent"]

    serialized = json.dumps(finding.evidence, sort_keys=True)
    assert raw_github_token not in serialized
    assert raw_slack_token not in serialized
    assert "user:password" not in serialized
    assert "/Users/alice/.config/agent-bom/private-agent.json" not in serialized


def test_report_to_findings_preserves_sanitized_layer_attribution_evidence():
    raw_token = "ghp_" + "abcdefghijklmnopqrstuvwxyz" + "1234567890"
    pkg = _make_package()
    pkg.is_direct = False
    pkg.parent_package = "top-level"
    pkg.dependency_depth = 2
    pkg.dependency_scope = "runtime"
    pkg.reachability_evidence = "lockfile"
    pkg.occurrences = [
        PackageOccurrence(
            layer_index=7,
            layer_id="sha256:layer7",
            layer_path="/var/lib/docker/overlay2/sensitive-layer",
            package_path="/Users/alice/work/private/package-lock.json",
            created_by=f"RUN npm config set //registry.npmjs.org/:_authToken={raw_token}",
            dockerfile_instruction=f"RUN npm install --token={raw_token}",
        )
    ]
    br = _make_blast_radius()
    br.package = pkg
    br.graph_reachable = False
    report = AIBOMReport(agents=[], blast_radii=[br])

    finding = report.to_findings()[0]

    assert finding.evidence["package_is_direct"] is False
    assert finding.evidence["package_parent"] == "top-level"
    assert finding.evidence["package_dependency_depth"] == 2
    assert finding.evidence["package_dependency_scope"] == "runtime"
    assert finding.evidence["package_reachability_evidence"] == "lockfile"
    assert finding.evidence["graph_reachable"] is False
    assert finding.evidence["layer_attribution"] == [
        {
            "layer_index": 7,
            "layer_id": "sha256:layer7",
            "layer_path": "<path:sensitive-layer>",
            "package_path": "<path:package-lock.json>",
            "created_by": "RUN npm config set //registry.npmjs.org/:_authToken=<redacted>",
            "dockerfile_instruction": "RUN npm install --token=<redacted>",
        }
    ]

    serialized = json.dumps(finding.evidence, sort_keys=True)
    assert raw_token not in serialized
    assert "/Users/alice/work/private/package-lock.json" not in serialized


# ---------------------------------------------------------------------------
# AIBOMReport.to_findings() and cve_findings()
# ---------------------------------------------------------------------------


def _make_report_with_blast_radii(n=3) -> AIBOMReport:
    brs = [_make_blast_radius(vuln_id=f"CVE-2024-{i:04d}") for i in range(n)]
    return AIBOMReport(agents=[], blast_radii=brs)


def test_report_to_findings_converts_blast_radii():
    report = _make_report_with_blast_radii(3)
    findings = report.to_findings()
    assert len(findings) == 3
    assert all(f.finding_type == FindingType.CVE for f in findings)


def test_report_to_findings_returns_existing_when_populated():
    """If findings already populated (dual-write path), return as-is."""
    pre_existing = [
        Finding(
            finding_type=FindingType.CIS_FAIL,
            source=FindingSource.CLOUD_CIS,
            asset=Asset(name="my-bucket", asset_type="cloud_resource"),
            severity="HIGH",
        )
    ]
    report = AIBOMReport(agents=[], blast_radii=[], findings=pre_existing)
    result = report.to_findings()
    assert len(result) == 1
    assert result[0].finding_type == FindingType.CIS_FAIL


def test_report_cve_findings_filters_by_type():
    report = _make_report_with_blast_radii(2)
    # Add a non-CVE finding manually
    report.findings = report.to_findings() + [
        Finding(
            finding_type=FindingType.CIS_FAIL,
            source=FindingSource.CLOUD_CIS,
            asset=Asset(name="bucket", asset_type="cloud_resource"),
            severity="MEDIUM",
        )
    ]
    cve_findings = report.cve_findings()
    assert len(cve_findings) == 2
    assert all(f.finding_type == FindingType.CVE for f in cve_findings)


def test_report_to_findings_empty_report():
    report = AIBOMReport(agents=[], blast_radii=[])
    assert report.to_findings() == []


# ---------------------------------------------------------------------------
# Dual-write integration: cli dual-write populates findings
# ---------------------------------------------------------------------------


def test_report_dual_write_findings_field():
    """Simulate the CLI dual-write: findings populated alongside blast_radii."""
    from agent_bom.finding import blast_radius_to_finding

    brs = [_make_blast_radius()]
    findings = [blast_radius_to_finding(br) for br in brs]
    report = AIBOMReport(agents=[], blast_radii=brs, findings=findings)

    # findings stream is populated
    assert len(report.findings) == 1
    # blast_radii still accessible (backward compat)
    assert len(report.blast_radii) == 1
    # to_findings() returns the already-populated list
    assert len(report.to_findings()) == 1
    assert report.to_findings()[0].cve_id == "CVE-2024-9999"  # vuln_id maps to cve_id
