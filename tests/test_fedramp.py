"""Tests for FedRAMP compliance framework tagging."""

from agent_bom.fedramp import (
    FEDRAMP_HIGH,
    FEDRAMP_LOW,
    FEDRAMP_MODERATE,
    tag_blast_radius,
)
from agent_bom.models import (
    Agent,
    AgentType,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    Vulnerability,
)


def _br(
    *,
    severity=Severity.HIGH,
    pkg_name="flask",
    tools=None,
    creds=None,
    fixed_version=None,
    is_kev=False,
    num_agents=1,
) -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2025-9999",
        summary="test",
        severity=severity,
        fixed_version=fixed_version,
        is_kev=is_kev,
    )
    pkg = Package(name=pkg_name, version="1.0.0", ecosystem="pypi")
    agents = [Agent(name=f"a{i}", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp") for i in range(num_agents)]
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[MCPServer(name="srv")],
        affected_agents=agents,
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )


def test_baselines_are_hierarchical():
    assert FEDRAMP_LOW <= FEDRAMP_MODERATE
    assert FEDRAMP_MODERATE <= FEDRAMP_HIGH


def test_tags_are_fedramp_prefixed():
    tags = tag_blast_radius(_br())
    assert all(t.startswith("FedRAMP-") for t in tags)


def test_universal_tags_present_moderate():
    tags = tag_blast_radius(_br(severity=Severity.LOW))
    # RA-5, SI-2, CM-8 are in LOW baseline (and moderate), always tagged
    assert "FedRAMP-RA-5" in tags
    assert "FedRAMP-SI-2" in tags
    assert "FedRAMP-CM-8" in tags


def test_moderate_includes_sr3():
    # SR-3 is in moderate but not low
    tags_mod = tag_blast_radius(_br(severity=Severity.LOW), baseline="moderate")
    assert "FedRAMP-SR-3" in tags_mod

    tags_low = tag_blast_radius(_br(severity=Severity.LOW), baseline="low")
    assert "FedRAMP-SR-3" not in tags_low


def test_high_baseline_includes_supply_chain_provenance():
    # SR-4 is only in high baseline
    tags_high = tag_blast_radius(_br(pkg_name="langchain"), baseline="high")
    assert "FedRAMP-SR-4" in tags_high

    tags_mod = tag_blast_radius(_br(pkg_name="langchain"), baseline="moderate")
    assert "FedRAMP-SR-4" not in tags_mod


def test_kev_triggers_fedramp_ir6():
    tags = tag_blast_radius(_br(is_kev=True), baseline="moderate")
    assert "FedRAMP-IR-6" in tags
    assert "FedRAMP-SI-5" in tags


def test_credentials_trigger_fedramp_access_controls():
    tags = tag_blast_radius(_br(creds=["API_KEY"]), baseline="moderate")
    assert "FedRAMP-AC-3" in tags
    assert "FedRAMP-AC-6" in tags
    assert "FedRAMP-IA-5" in tags


def test_low_baseline_filters_out_moderate_controls():
    # IR-5 is in moderate, not low
    tags = tag_blast_radius(_br(severity=Severity.CRITICAL), baseline="low")
    assert "FedRAMP-IR-5" not in tags

    tags_mod = tag_blast_radius(_br(severity=Severity.CRITICAL), baseline="moderate")
    assert "FedRAMP-IR-5" in tags_mod


def test_default_baseline_is_moderate():
    tags_default = tag_blast_radius(_br())
    tags_moderate = tag_blast_radius(_br(), baseline="moderate")
    assert tags_default == tags_moderate


def test_vuln_compliance_returns_both_keys():
    from agent_bom.vuln_compliance import tag_vulnerability

    vuln = Vulnerability(id="CVE-2025-0001", summary="test", severity=Severity.HIGH)
    pkg = Package(name="flask", version="1.0.0", ecosystem="pypi")
    result = tag_vulnerability(vuln, pkg)
    assert "nist_800_53" in result
    assert "fedramp" in result
    assert all(t.startswith("FedRAMP-") for t in result["fedramp"])
