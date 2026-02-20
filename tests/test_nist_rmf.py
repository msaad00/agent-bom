"""Tests for NIST AI RMF mapping."""

from agent_bom.models import (
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.nist_ai_rmf import NIST_AI_RMF, nist_label, nist_labels, tag_blast_radius


def _make_br(
    pkg_name="express",
    severity=Severity.MEDIUM,
    creds=None,
    tools=None,
    fixed="4.19.0",
    is_kev=False,
):
    """Helper to build a BlastRadius for testing."""
    vuln = Vulnerability(
        id="CVE-2024-0001",
        summary="Test vuln",
        severity=severity,
        fixed_version=fixed,
        is_kev=is_kev,
    )
    pkg = Package(name=pkg_name, version="1.0.0", ecosystem="pypi")
    server = MCPServer(
        name="test-server",
        command="node",
        env={"API_KEY": "xxx"} if creds else {},
        tools=tools or [],
    )
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[],
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )


# ─── Always-applied tags ──────────────────────────────────────────────────────


def test_always_tags():
    """Any finding should always get GOVERN-1.7 and MAP-3.5."""
    br = _make_br()
    tags = tag_blast_radius(br)
    assert "GOVERN-1.7" in tags
    assert "MAP-3.5" in tags


# ─── Credential exposure → MANAGE-2.2 + MANAGE-4.1 ──────────────────────────


def test_credentials_trigger_manage_2_2():
    br = _make_br(creds=["API_KEY"])
    tags = tag_blast_radius(br)
    assert "MANAGE-2.2" in tags


def test_credentials_and_tools_trigger_manage_4_1():
    tools = [MCPTool(name="exec_cmd", description="Run a shell command")]
    br = _make_br(creds=["API_KEY"], tools=tools)
    tags = tag_blast_radius(br)
    assert "MANAGE-4.1" in tags


def test_no_creds_no_manage_2_2():
    br = _make_br(creds=[])
    tags = tag_blast_radius(br)
    assert "MANAGE-2.2" not in tags


# ─── Tool surface → MAP-1.6, MAP-5.2, GOVERN-6.1 ───────────────────────────


def test_broad_tool_surface_triggers_map_1_6():
    """More than 3 tools → MAP-1.6 (interfaces need mapping)."""
    tools = [MCPTool(name=f"tool_{i}", description="") for i in range(5)]
    br = _make_br(tools=tools)
    tags = tag_blast_radius(br)
    assert "MAP-1.6" in tags


def test_few_tools_no_map_1_6():
    tools = [MCPTool(name=f"tool_{i}", description="") for i in range(2)]
    br = _make_br(tools=tools)
    tags = tag_blast_radius(br)
    assert "MAP-1.6" not in tags


def test_exec_tools_trigger_govern_6_1():
    tools = [MCPTool(name="run_command", description="Execute shell commands")]
    br = _make_br(tools=tools)
    tags = tag_blast_radius(br)
    assert "GOVERN-6.1" in tags


def test_data_tools_trigger_map_5_2():
    tools = [MCPTool(name="read_file", description="Read a file from disk")]
    br = _make_br(tools=tools)
    tags = tag_blast_radius(br)
    assert "MAP-5.2" in tags


# ─── AI framework + severity → MEASURE-2.5 ──────────────────────────────────


def test_ai_framework_high_triggers_measure_2_5():
    br = _make_br(pkg_name="langchain", severity=Severity.HIGH)
    tags = tag_blast_radius(br)
    assert "MEASURE-2.5" in tags


def test_ai_framework_medium_no_measure_2_5():
    br = _make_br(pkg_name="langchain", severity=Severity.MEDIUM)
    tags = tag_blast_radius(br)
    assert "MEASURE-2.5" not in tags


def test_non_ai_package_no_measure_2_5():
    br = _make_br(pkg_name="express", severity=Severity.CRITICAL)
    tags = tag_blast_radius(br)
    assert "MEASURE-2.5" not in tags


# ─── AI + creds + HIGH → GOVERN-6.2, MANAGE-2.4 ────────────────────────────


def test_ai_creds_high_triggers_govern_6_2():
    br = _make_br(pkg_name="openai", severity=Severity.CRITICAL, creds=["OPENAI_API_KEY"])
    tags = tag_blast_radius(br)
    assert "GOVERN-6.2" in tags
    assert "MANAGE-2.4" in tags


def test_ai_no_creds_no_govern_6_2():
    br = _make_br(pkg_name="openai", severity=Severity.CRITICAL)
    tags = tag_blast_radius(br)
    assert "GOVERN-6.2" not in tags
    assert "MANAGE-2.4" not in tags


# ─── Fix available → MEASURE-2.9 ────────────────────────────────────────────


def test_fix_available_triggers_measure_2_9():
    br = _make_br(fixed="2.0.0")
    tags = tag_blast_radius(br)
    assert "MEASURE-2.9" in tags


def test_no_fix_no_measure_2_9():
    br = _make_br(fixed=None)
    tags = tag_blast_radius(br)
    assert "MEASURE-2.9" not in tags


# ─── KEV → MANAGE-1.3 ───────────────────────────────────────────────────────


def test_kev_triggers_manage_1_3():
    br = _make_br(is_kev=True)
    tags = tag_blast_radius(br)
    assert "MANAGE-1.3" in tags


def test_no_kev_no_manage_1_3():
    br = _make_br(is_kev=False)
    tags = tag_blast_radius(br)
    assert "MANAGE-1.3" not in tags


# ─── Tags are sorted ────────────────────────────────────────────────────────


def test_tags_are_sorted():
    """Tags should be returned in sorted order."""
    tools = [MCPTool(name="execute_shell", description="shell")] * 5
    br = _make_br(
        pkg_name="langchain",
        severity=Severity.CRITICAL,
        creds=["OPENAI_API_KEY"],
        tools=tools,
        is_kev=True,
    )
    tags = tag_blast_radius(br)
    assert tags == sorted(tags)
    # Should have many tags triggered
    assert len(tags) >= 6


# ─── Full scenario: AI framework + creds + tools + KEV ──────────────────────


def test_full_scenario_all_tags():
    """Maximum-risk scenario should trigger most subcategories."""
    tools = [
        MCPTool(name="execute_command", description="Run shell commands"),
        MCPTool(name="read_database", description="Query SQL database"),
        MCPTool(name="write_file", description=""),
        MCPTool(name="deploy_model", description=""),
        MCPTool(name="send_email", description=""),
    ]
    br = _make_br(
        pkg_name="transformers",
        severity=Severity.CRITICAL,
        creds=["HF_TOKEN", "AWS_SECRET_KEY"],
        tools=tools,
        fixed="4.36.0",
        is_kev=True,
    )
    tags = tag_blast_radius(br)

    # All expected tags
    assert "GOVERN-1.7" in tags  # always
    assert "MAP-3.5" in tags     # always
    assert "GOVERN-6.1" in tags  # exec tools
    assert "GOVERN-6.2" in tags  # AI + creds + HIGH
    assert "MAP-1.6" in tags     # >3 tools
    assert "MAP-5.2" in tags     # data tools
    assert "MEASURE-2.5" in tags # AI + HIGH
    assert "MEASURE-2.9" in tags # fix available
    assert "MANAGE-1.3" in tags  # KEV
    assert "MANAGE-2.2" in tags  # credentials
    assert "MANAGE-2.4" in tags  # AI + creds + HIGH
    assert "MANAGE-4.1" in tags  # creds + tools


# ─── Catalog + labels ───────────────────────────────────────────────────────


def test_catalog_has_all_functions():
    """Catalog should have entries from all four NIST AI RMF functions."""
    functions = {k.split("-")[0] for k in NIST_AI_RMF}
    assert "GOVERN" in functions
    assert "MAP" in functions
    assert "MEASURE" in functions
    assert "MANAGE" in functions


def test_nist_label():
    label = nist_label("MAP-3.5")
    assert label == "MAP-3.5 AI supply chain risks assessed"


def test_nist_labels():
    labels = nist_labels(["MAP-3.5", "GOVERN-1.7"])
    assert len(labels) == 2
    assert "MAP-3.5" in labels[0]
    assert "GOVERN-1.7" in labels[1]


def test_nist_label_unknown():
    label = nist_label("FAKE-99")
    assert "Unknown" in label
