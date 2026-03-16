"""Tests for HIPAA Security Rule tagging."""

from agent_bom.hipaa import (
    HIPAA_SAFEGUARDS,
    hipaa_label,
    hipaa_labels,
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


def test_catalog_has_nineteen_safeguards():
    assert len(HIPAA_SAFEGUARDS) == 19


def test_always_applied_tags():
    tags = tag_blast_radius(_br())
    assert "164.308(a)(1)(ii)(A)" in tags
    assert "164.308(a)(1)(ii)(B)" in tags
    assert "164.308(a)(8)" in tags
    assert "164.312(b)" in tags


def test_high_severity_triggers_malicious_software_and_integrity():
    tags = tag_blast_radius(_br(severity=Severity.CRITICAL))
    assert "164.308(a)(5)(ii)(B)" in tags
    assert "164.312(c)(1)" in tags
    tags_low = tag_blast_radius(_br(severity=Severity.LOW))
    assert "164.308(a)(5)(ii)(B)" not in tags_low
    assert "164.312(c)(1)" not in tags_low


def test_kev_triggers_security_reminders_and_incident_response():
    tags = tag_blast_radius(_br(is_kev=True))
    assert "164.308(a)(5)(ii)(A)" in tags
    assert "164.308(a)(6)(ii)" in tags
    tags_no = tag_blast_radius(_br())
    assert "164.308(a)(5)(ii)(A)" not in tags_no
    assert "164.308(a)(6)(ii)" not in tags_no


def test_creds_trigger_access_control_and_encryption():
    tags = tag_blast_radius(_br(creds=["API_KEY"]))
    assert "164.312(a)(1)" in tags
    assert "164.312(a)(2)(iv)" in tags
    assert "164.312(e)(2)(ii)" in tags
    assert "164.308(a)(4)(ii)(B)" in tags
    tags_no = tag_blast_radius(_br())
    assert "164.312(a)(1)" not in tags_no


def test_exec_tools_trigger_authorization():
    tags = tag_blast_radius(_br(tools=[MCPTool(name="exec", description="execute shell command")]))
    assert "164.308(a)(3)(ii)(A)" in tags


def test_creds_and_exec_trigger_ephi_authentication():
    tags = tag_blast_radius(
        _br(
            creds=["SECRET"],
            tools=[MCPTool(name="exec", description="execute shell command")],
        )
    )
    assert "164.312(c)(2)" in tags


def test_multi_agent_triggers_activity_review():
    tags = tag_blast_radius(_br(num_agents=3))
    assert "164.308(a)(1)(ii)(D)" in tags
    tags_single = tag_blast_radius(_br(num_agents=1))
    assert "164.308(a)(1)(ii)(D)" not in tags_single


def test_multi_agent_with_tools_triggers_transmission_security():
    tags = tag_blast_radius(
        _br(
            num_agents=2,
            tools=[MCPTool(name="read", description="read file")],
        )
    )
    assert "164.312(e)(1)" in tags


def test_creds_multi_agent_triggers_entity_authentication():
    tags = tag_blast_radius(_br(creds=["KEY"], num_agents=2))
    assert "164.312(d)" in tags
    tags_no = tag_blast_radius(_br(creds=["KEY"], num_agents=1))
    assert "164.312(d)" not in tags_no


def test_high_with_creds_triggers_data_backup():
    tags = tag_blast_radius(_br(severity=Severity.HIGH, creds=["SECRET"]))
    assert "164.308(a)(7)(ii)(A)" in tags
    tags_low = tag_blast_radius(_br(severity=Severity.LOW, creds=["SECRET"]))
    assert "164.308(a)(7)(ii)(A)" not in tags_low


def test_ai_package_triggers_device_media_controls():
    tags = tag_blast_radius(_br(pkg_name="openai"))
    assert "164.310(d)(1)" in tags
    tags_normal = tag_blast_radius(_br(pkg_name="flask"))
    assert "164.310(d)(1)" not in tags_normal


def test_label_functions():
    lbl = hipaa_label("164.312(a)(1)")
    assert lbl == "164.312(a)(1) Access control"
    labels = hipaa_labels(["164.308(a)(1)(ii)(A)", "164.312(b)"])
    assert len(labels) == 2


def test_minimal_finding_gets_base_tags_only():
    tags = tag_blast_radius(_br(severity=Severity.LOW, pkg_name="requests"))
    assert tags == sorted(["164.308(a)(1)(ii)(A)", "164.308(a)(1)(ii)(B)", "164.308(a)(8)", "164.312(b)"])


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
    assert len(tags) >= 14
