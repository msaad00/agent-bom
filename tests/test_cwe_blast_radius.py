"""End-to-end tests for CWE-aware blast radius credential filtering.

Verifies that the same package with different vulnerability CWE types
produces different exposed_credentials on each BlastRadius — an RCE
shows full credential exposure while a client-side XSS does not.
"""

from __future__ import annotations

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


def _make_blast_radius(
    cwe_ids: list[str],
    severity: Severity = Severity.HIGH,
    creds: list[str] | None = None,
    tools: list[MCPTool] | None = None,
) -> BlastRadius:
    """Helper to build a BlastRadius with CWE-aware filtering applied."""
    from agent_bom.cwe_impact import (
        build_attack_vector_summary,
        classify_cwe_impact,
        filter_credentials_by_impact,
        filter_tools_by_impact,
    )

    vuln = Vulnerability(
        id="CVE-2024-TEST",
        summary="Test vulnerability",
        severity=severity,
        cwe_ids=cwe_ids,
    )
    pkg = Package(name="test-pkg", version="1.0.0", ecosystem="npm")
    server = MCPServer(name="test-server", command="node")
    agent = Agent(
        name="test-agent",
        agent_type=AgentType.CURSOR,
        config_path="/test",
    )

    all_creds = creds or ["DATABASE_URL", "GITHUB_TOKEN", "SLACK_WEBHOOK"]
    all_tools = tools or [
        MCPTool(name="run_query", description=""),
        MCPTool(name="send_message", description=""),
        MCPTool(name="read_file", description=""),
    ]

    impact_cat = classify_cwe_impact(cwe_ids)
    filtered_creds = filter_credentials_by_impact(impact_cat, all_creds)
    filtered_tools = filter_tools_by_impact(impact_cat, all_tools)
    attack_summary = build_attack_vector_summary(
        cwe_ids=cwe_ids,
        category=impact_cat,
        filtered_creds=filtered_creds,
        filtered_tools=filtered_tools,
    )

    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=filtered_creds,
        exposed_tools=filtered_tools,
        impact_category=impact_cat,
        all_server_credentials=list(all_creds),
        all_server_tools=list(all_tools),
        attack_vector_summary=attack_summary,
    )
    br.calculate_risk_score()
    return br


# ── Impact category assignment ───────────────────────────────────────────────


def test_rce_gets_code_execution_category():
    br = _make_blast_radius(["CWE-94"])
    assert br.impact_category == "code-execution"


def test_xss_gets_client_side_category():
    br = _make_blast_radius(["CWE-79"])
    assert br.impact_category == "client-side"


def test_dos_gets_availability_category():
    br = _make_blast_radius(["CWE-400"])
    assert br.impact_category == "availability"


def test_sqli_gets_injection_category():
    br = _make_blast_radius(["CWE-89"])
    assert br.impact_category == "injection"


def test_no_cwe_defaults_to_code_execution():
    br = _make_blast_radius([])
    assert br.impact_category == "code-execution"


# ── Credential filtering per CWE type ───────────────────────────────────────


def test_rce_exposes_all_credentials():
    br = _make_blast_radius(["CWE-94"])
    assert set(br.exposed_credentials) == {"DATABASE_URL", "GITHUB_TOKEN", "SLACK_WEBHOOK"}


def test_xss_exposes_no_credentials():
    br = _make_blast_radius(["CWE-79"])
    assert br.exposed_credentials == []


def test_dos_exposes_no_credentials():
    br = _make_blast_radius(["CWE-400"])
    assert br.exposed_credentials == []


def test_sqli_exposes_only_db_credentials():
    br = _make_blast_radius(["CWE-89"])
    assert "DATABASE_URL" in br.exposed_credentials
    assert "GITHUB_TOKEN" not in br.exposed_credentials
    assert "SLACK_WEBHOOK" not in br.exposed_credentials


def test_path_traversal_exposes_all_credentials():
    """File access can read .env files — all credentials potentially exposed."""
    br = _make_blast_radius(["CWE-22"])
    assert set(br.exposed_credentials) == {"DATABASE_URL", "GITHUB_TOKEN", "SLACK_WEBHOOK"}


# ── Tool filtering per CWE type ──────────────────────────────────────────────


def test_rce_exposes_all_tools():
    br = _make_blast_radius(["CWE-94"])
    assert len(br.exposed_tools) == 3


def test_xss_exposes_no_tools():
    br = _make_blast_radius(["CWE-79"])
    assert br.exposed_tools == []


def test_dos_exposes_no_tools():
    br = _make_blast_radius(["CWE-400"])
    assert br.exposed_tools == []


def test_sqli_exposes_only_query_tools():
    br = _make_blast_radius(["CWE-89"])
    tool_names = [t.name for t in br.exposed_tools]
    assert "run_query" in tool_names
    assert "send_message" not in tool_names


# ── all_server_credentials preserves full set ────────────────────────────────


def test_xss_preserves_all_server_credentials():
    """Even when exposed_credentials is filtered, all_server_credentials keeps the full set."""
    br = _make_blast_radius(["CWE-79"])
    assert br.exposed_credentials == []
    assert set(br.all_server_credentials) == {"DATABASE_URL", "GITHUB_TOKEN", "SLACK_WEBHOOK"}


def test_dos_preserves_all_server_credentials():
    br = _make_blast_radius(["CWE-400"])
    assert br.exposed_credentials == []
    assert len(br.all_server_credentials) == 3


# ── Risk score varies by CWE type ───────────────────────────────────────────


def test_rce_has_higher_risk_than_xss():
    """RCE with credentials should score higher than XSS without."""
    rce = _make_blast_radius(["CWE-94"], severity=Severity.HIGH)
    xss = _make_blast_radius(["CWE-79"], severity=Severity.HIGH)
    assert rce.risk_score > xss.risk_score


def test_rce_has_higher_risk_than_dos():
    rce = _make_blast_radius(["CWE-94"], severity=Severity.HIGH)
    dos = _make_blast_radius(["CWE-400"], severity=Severity.HIGH)
    assert rce.risk_score > dos.risk_score


def test_dos_same_severity_lower_risk_due_to_no_creds():
    """Same severity, but DoS has no credential factor → lower score."""
    rce = _make_blast_radius(["CWE-94"], severity=Severity.MEDIUM)
    dos = _make_blast_radius(["CWE-400"], severity=Severity.MEDIUM)
    assert rce.risk_score > dos.risk_score


# ── Attack vector summary ────────────────────────────────────────────────────


def test_rce_summary_mentions_credentials():
    br = _make_blast_radius(["CWE-94"])
    assert "credential" in br.attack_vector_summary.lower()


def test_xss_summary_says_no_server_credentials():
    br = _make_blast_radius(["CWE-79"])
    assert "does not expose server-side credentials" in br.attack_vector_summary.lower()


def test_dos_summary_says_no_credentials():
    br = _make_blast_radius(["CWE-400"])
    assert "does not expose credentials" in br.attack_vector_summary.lower()


# ── Reachability and actionability ───────────────────────────────────────────


def test_rce_is_confirmed_reachability():
    br = _make_blast_radius(["CWE-94"])
    assert br.reachability == "confirmed"


def test_xss_is_not_confirmed_reachability():
    """XSS with no credentials/tools should not be 'confirmed'."""
    br = _make_blast_radius(["CWE-79"])
    assert br.reachability != "confirmed"


def test_dos_low_is_not_actionable():
    """LOW DoS in a transitive dep with no credentials should not be actionable."""
    br = _make_blast_radius(["CWE-400"], severity=Severity.LOW)
    br.package.is_direct = False
    assert not br.is_actionable
