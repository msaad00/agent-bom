"""Tests for CMMC 2.0 Level 2 tagging."""

from agent_bom.cmmc import (
    CMMC_PRACTICES,
    cmmc_label,
    cmmc_labels,
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


def test_catalog_has_seventeen_practices():
    assert len(CMMC_PRACTICES) == 17


def test_always_applied_tags():
    tags = tag_blast_radius(_br())
    assert "RA.L2-3.11.2" in tags
    assert "SI.L2-3.14.1" in tags
    assert "CM.L2-3.4.3" in tags


def test_fixable_triggers_remediate_vulnerabilities():
    tags = tag_blast_radius(_br(fixed_version="2.0.0"))
    assert "RA.L2-3.11.3" in tags
    tags_no = tag_blast_radius(_br())
    assert "RA.L2-3.11.3" not in tags_no


def test_high_severity_triggers_malicious_code_protection():
    tags = tag_blast_radius(_br(severity=Severity.CRITICAL))
    assert "SI.L2-3.14.2" in tags
    tags_low = tag_blast_radius(_br(severity=Severity.LOW))
    assert "SI.L2-3.14.2" not in tags_low


def test_kev_triggers_security_alerts():
    tags = tag_blast_radius(_br(is_kev=True))
    assert "SI.L2-3.14.3" in tags
    tags_no = tag_blast_radius(_br())
    assert "SI.L2-3.14.3" not in tags_no


def test_multi_agent_triggers_monitor_comms():
    tags = tag_blast_radius(_br(num_agents=3))
    assert "SI.L2-3.14.6" in tags
    tags_single = tag_blast_radius(_br(num_agents=1))
    assert "SI.L2-3.14.6" not in tags_single


def test_ai_package_triggers_unauthorized_use():
    tags = tag_blast_radius(_br(pkg_name="openai"))
    assert "SI.L2-3.14.7" in tags
    tags_normal = tag_blast_radius(_br(pkg_name="flask"))
    assert "SI.L2-3.14.7" not in tags_normal


def test_exec_tools_trigger_boundary_monitoring():
    tags = tag_blast_radius(_br(tools=[MCPTool(name="exec", description="execute shell command")]))
    assert "SC.L2-3.13.1" in tags
    assert "AC.L2-3.1.2" in tags


def test_creds_and_exec_trigger_architectural_security():
    tags = tag_blast_radius(
        _br(
            creds=["API_KEY"],
            tools=[MCPTool(name="exec", description="execute shell command")],
        )
    )
    assert "SC.L2-3.13.2" in tags
    assert "AC.L2-3.1.7" in tags


def test_multi_agent_with_tools_triggers_subnetwork_isolation():
    tags = tag_blast_radius(
        _br(
            num_agents=3,
            tools=[MCPTool(name="read", description="read file")],
        )
    )
    assert "SC.L2-3.13.5" in tags


def test_ai_package_triggers_baseline_config():
    tags = tag_blast_radius(_br(pkg_name="langchain"))
    assert "CM.L2-3.4.1" in tags


def test_high_with_creds_triggers_enforce_security_configs():
    tags = tag_blast_radius(_br(severity=Severity.HIGH, creds=["SECRET"]))
    assert "CM.L2-3.4.2" in tags
    tags_low = tag_blast_radius(_br(severity=Severity.LOW, creds=["SECRET"]))
    assert "CM.L2-3.4.2" not in tags_low


def test_creds_trigger_access_control():
    tags = tag_blast_radius(_br(creds=["API_KEY"]))
    assert "AC.L2-3.1.1" in tags
    tags_no = tag_blast_radius(_br())
    assert "AC.L2-3.1.1" not in tags_no


def test_creds_multi_agent_triggers_mfa():
    tags = tag_blast_radius(_br(creds=["KEY"], num_agents=2))
    assert "IA.L2-3.5.3" in tags
    tags_no = tag_blast_radius(_br(creds=["KEY"], num_agents=1))
    assert "IA.L2-3.5.3" not in tags_no


def test_label_functions():
    lbl = cmmc_label("RA.L2-3.11.2")
    assert lbl == "RA.L2-3.11.2 Vulnerability scanning"
    labels = cmmc_labels(["RA.L2-3.11.2", "SI.L2-3.14.1"])
    assert len(labels) == 2


def test_minimal_finding_gets_base_tags_only():
    tags = tag_blast_radius(_br(severity=Severity.LOW, pkg_name="requests"))
    assert tags == ["CM.L2-3.4.3", "RA.L2-3.11.2", "SI.L2-3.14.1"]


def test_results_are_sorted():
    tags = tag_blast_radius(
        _br(
            severity=Severity.CRITICAL,
            is_kev=True,
            fixed_version="2.0.0",
            creds=["KEY"],
            tools=[MCPTool(name="exec", description="execute shell command")],
            num_agents=3,
            pkg_name="openai",
        )
    )
    assert tags == sorted(tags)
    # Verify a rich set of tags is returned
    assert len(tags) >= 12
