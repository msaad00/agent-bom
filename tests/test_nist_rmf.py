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
    """GOVERN-6.1 and MAP-4.1 apply when AI-relevant context is present.

    A MEDIUM vuln in a non-AI package with no credentials or tools
    should NOT get these tags (noise reduction). They apply when:
    - Package is an AI framework, OR
    - Credentials or tools are exposed, OR
    - Severity is HIGH+
    """
    br = _make_br()
    tags = tag_blast_radius(br)
    assert "GOVERN-6.1" not in tags
    assert "MAP-4.1" not in tags

    tags_high = tag_blast_radius(_make_br(severity=Severity.HIGH))
    assert "GOVERN-6.1" in tags_high
    assert "MAP-4.1" in tags_high

    tags_creds = tag_blast_radius(_make_br(creds=["API_KEY"]))
    assert "GOVERN-6.1" in tags_creds
    assert "MAP-4.1" in tags_creds


# ─── Credential exposure → MANAGE-4.1 ───────────────────────────────────────


def test_credentials_alone_do_not_claim_a_manage_subcategory():
    br = _make_br(creds=["API_KEY"], fixed=None)
    tags = tag_blast_radius(br)
    assert not any(tag.startswith("MANAGE-") for tag in tags)


def test_credentials_and_tools_trigger_manage_4_1():
    tools = [MCPTool(name="exec_cmd", description="Run a shell command")]
    br = _make_br(creds=["API_KEY"], tools=tools)
    tags = tag_blast_radius(br)
    assert "MANAGE-4.1" in tags


# ─── Tool surface → MAP-3.5 (human oversight), MAP-5.1 (impact) ────────────


def test_broad_tool_surface_alone_adds_no_map_subcategory():
    """Tool count alone has no AI RMF subcategory; only GOVERN-6.1/MAP-4.1 apply."""
    tools = [MCPTool(name=f"tool_{i}", description="") for i in range(5)]
    tags = tag_blast_radius(_make_br(tools=tools))
    assert {t for t in tags if t.startswith("MAP-")} == {"MAP-4.1"}


def test_exec_tools_trigger_human_oversight_map_3_5():
    tools = [MCPTool(name="run_command", description="Execute shell commands")]
    tags = tag_blast_radius(_make_br(tools=tools))
    assert "MAP-3.5" in tags


def test_data_tools_trigger_map_5_1():
    tools = [MCPTool(name="read_file", description="Read a file from disk")]
    tags = tag_blast_radius(_make_br(tools=tools))
    assert "MAP-5.1" in tags
    assert "MAP-3.5" not in tags


# ─── AI framework + severity → MEASURE-2.7 ──────────────────────────────────


def test_ai_framework_high_triggers_measure_2_7():
    tags = tag_blast_radius(_make_br(pkg_name="langchain", severity=Severity.HIGH))
    assert "MEASURE-2.7" in tags


def test_ai_framework_medium_no_measure_2_7():
    tags = tag_blast_radius(_make_br(pkg_name="langchain", severity=Severity.MEDIUM))
    assert "MEASURE-2.7" not in tags


def test_non_ai_package_no_measure_2_7():
    tags = tag_blast_radius(_make_br(pkg_name="express", severity=Severity.CRITICAL))
    assert "MEASURE-2.7" not in tags


# ─── AI + creds + HIGH → GOVERN-6.2 ─────────────────────────────────────────


def test_ai_creds_high_triggers_govern_6_2():
    br = _make_br(pkg_name="openai", severity=Severity.CRITICAL, creds=["OPENAI_API_KEY"])
    assert "GOVERN-6.2" in tag_blast_radius(br)


def test_ai_no_creds_no_govern_6_2():
    br = _make_br(pkg_name="openai", severity=Severity.CRITICAL)
    assert "GOVERN-6.2" not in tag_blast_radius(br)


# ─── Fix available or KEV → MANAGE-1.3 ──────────────────────────────────────


def test_fix_available_triggers_manage_1_3():
    assert "MANAGE-1.3" in tag_blast_radius(_make_br(fixed="2.0.0"))


def test_kev_triggers_manage_1_3():
    assert "MANAGE-1.3" in tag_blast_radius(_make_br(is_kev=True, fixed=None))


def test_no_kev_no_fix_no_manage_1_3():
    assert "MANAGE-1.3" not in tag_blast_radius(_make_br(is_kev=False, fixed=None))


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
    assert len(tags) >= 6


# ─── Full scenario: AI framework + creds + tools + KEV ──────────────────────


def test_full_scenario_all_tags():
    """Maximum-risk scenario triggers every rule, and only catalog subcategories."""
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
    assert set(tags) == {
        "GOVERN-6.1",  # third-party component risk
        "MAP-4.1",  # component / supply-chain risk mapped
        "MAP-3.5",  # exec tools → human oversight
        "MAP-5.1",  # data tools → impact
        "MEASURE-2.7",  # AI + HIGH → security evaluation
        "MANAGE-1.3",  # fix available / KEV → risk response
        "MANAGE-4.1",  # creds + tools → post-deployment monitoring
        "GOVERN-6.2",  # AI + creds + HIGH → contingency
    }
    assert set(tags) <= set(NIST_AI_RMF)


# ─── Catalog + labels ───────────────────────────────────────────────────────


def test_catalog_has_all_functions():
    """Catalog should have entries from all four NIST AI RMF functions."""
    functions = {k.split("-")[0] for k in NIST_AI_RMF}
    assert "GOVERN" in functions
    assert "MAP" in functions
    assert "MEASURE" in functions
    assert "MANAGE" in functions


def test_nist_label():
    label = nist_label("MAP-4.1")
    assert label == "MAP-4.1 Technology and legal risks of AI components, including third-party software, mapped"


def test_nist_labels():
    labels = nist_labels(["MAP-4.1", "GOVERN-6.1"])
    assert len(labels) == 2
    assert "MAP-4.1" in labels[0]
    assert "GOVERN-6.1" in labels[1]


def test_nist_label_unknown():
    label = nist_label("FAKE-99")
    assert "Unknown" in label
