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


def test_always_applied_tags():
    tags = tag_blast_radius(_br())
    assert "CIS-02.1" in tags
    assert "CIS-07.1" in tags
    assert "CIS-07.5" in tags


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
    lbl = cis_label("CIS-07.1")
    assert lbl == "CIS-07.1 Establish and maintain a vulnerability management process"
    labels = cis_labels(["CIS-02.1", "CIS-07.1"])
    assert len(labels) == 2


def test_minimal_finding_gets_base_tags_only():
    tags = tag_blast_radius(_br(severity=Severity.LOW, pkg_name="requests"))
    assert tags == ["CIS-02.1", "CIS-07.1", "CIS-07.5"]
