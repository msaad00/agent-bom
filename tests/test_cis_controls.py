"""Tests for CIS Controls v8 tagging."""

from agent_bom.cis_controls import (
    CIS_CONTROLS,
    cis_label,
    cis_labels,
    tag_blast_radius,
)
from agent_bom.models import (
    Agent,
    AgentType,
    BlastRadius,
    MCPServer,
    MCPTool,
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


def test_catalog_has_ten_safeguards():
    assert len(CIS_CONTROLS) == 10


def test_detective_safeguards_are_never_tagged_onto_a_finding():
    """CIS-02.1 / 07.1 / 07.5 are implemented BY this scan, not failed by it.

    Tagging a finding onto them made every CVE fail the inventory and
    vulnerability-management safeguards that producing the finding proves are
    operating. They are scored from scan freshness instead
    (see agent_bom.compliance_control_modes).
    """
    tags = tag_blast_radius(_br())
    assert "CIS-02.1" not in tags
    assert "CIS-07.1" not in tags
    assert "CIS-07.5" not in tags


def test_high_severity_triggers_unauthorized_software():
    tags = tag_blast_radius(_br(severity=Severity.CRITICAL))
    assert "CIS-02.3" in tags
    tags_low = tag_blast_radius(_br(severity=Severity.LOW))
    assert "CIS-02.3" not in tags_low


def test_ai_package_triggers_library_allowlist():
    tags = tag_blast_radius(_br(pkg_name="openai"))
    assert "CIS-02.7" in tags
    tags_normal = tag_blast_radius(_br(pkg_name="flask"))
    assert "CIS-02.7" not in tags_normal


def test_fixable_triggers_patch_management():
    tags = tag_blast_radius(_br(fixed_version="2.0.0"))
    assert "CIS-07.4" in tags
    tags_no = tag_blast_radius(_br())
    assert "CIS-07.4" not in tags_no


def test_multi_agent_triggers_public_facing_scans():
    tags = tag_blast_radius(_br(num_agents=3))
    assert "CIS-07.6" in tags
    tags_single = tag_blast_radius(_br(num_agents=1))
    assert "CIS-07.6" not in tags_single


def test_creds_trigger_secure_development():
    tags = tag_blast_radius(_br(creds=["API_KEY"]))
    assert "CIS-16.1" in tags
    tags_no = tag_blast_radius(_br())
    assert "CIS-16.1" not in tags_no


def test_exec_tools_trigger_hardening():
    tags = tag_blast_radius(_br(tools=[MCPTool(name="exec", description="execute shell command")]))
    assert "CIS-16.11" in tags


def test_kev_triggers_code_security():
    tags = tag_blast_radius(_br(is_kev=True))
    assert "CIS-16.12" in tags
    tags_no = tag_blast_radius(_br())
    assert "CIS-16.12" not in tags_no


def test_label_functions():
    # agent-bom's own descriptor, not the copyrighted CIS Controls v8 title.
    lbl = cis_label("CIS-07.1")
    assert lbl == "CIS-07.1 Vulnerability-management program"
    labels = cis_labels(["CIS-02.1", "CIS-07.1"])
    assert len(labels) == 2


def test_minimal_finding_tags_no_safeguard():
    """A LOW CVE in an ordinary package is evidence against no CIS safeguard.

    It used to emit the three detective safeguards unconditionally, which is
    what made every finding look like three extra control failures.
    """
    tags = tag_blast_radius(_br(severity=Severity.LOW, pkg_name="requests"))
    assert tags == []
