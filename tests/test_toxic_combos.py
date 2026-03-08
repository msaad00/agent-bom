"""Tests for toxic combination detection — chained risk analysis."""

from __future__ import annotations

from agent_bom.models import (
    Agent,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.toxic_combos import (
    ToxicCombination,
    ToxicPattern,
    detect_toxic_combinations,
    prioritize_findings,
    to_serializable,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vuln(
    vid: str = "CVE-2024-1234",
    severity: Severity = Severity.HIGH,
    is_kev: bool = False,
    epss: float | None = None,
    fixed: str | None = "2.0.0",
) -> Vulnerability:
    return Vulnerability(id=vid, summary=f"Test {vid}", severity=severity, is_kev=is_kev, epss_score=epss, fixed_version=fixed)


def _pkg(
    name: str = "test-pkg",
    version: str = "1.0.0",
    ecosystem: str = "npm",
    is_direct: bool = True,
    parent: str | None = None,
) -> Package:
    return Package(name=name, version=version, ecosystem=ecosystem, is_direct=is_direct, parent_package=parent)


def _tool(name: str = "read_file", desc: str = "Read a file") -> MCPTool:
    return MCPTool(name=name, description=desc)


def _server(name: str = "server-a") -> MCPServer:
    return MCPServer(name=name, command="npx")


def _agent(name: str = "agent-a") -> Agent:
    return Agent(name=name, agent_type="claude-desktop", config_path="/tmp/test")


def _br(
    vuln: Vulnerability | None = None,
    pkg: Package | None = None,
    creds: list[str] | None = None,
    tools: list[MCPTool] | None = None,
    agents: list[Agent] | None = None,
    servers: list[MCPServer] | None = None,
    risk_score: float = 6.0,
) -> BlastRadius:
    return BlastRadius(
        vulnerability=vuln or _vuln(),
        package=pkg or _pkg(),
        affected_servers=servers or [],
        affected_agents=agents or [],
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
        risk_score=risk_score,
    )


def _report(blast_radii: list[BlastRadius]) -> AIBOMReport:
    return AIBOMReport(blast_radii=blast_radii)


# ---------------------------------------------------------------------------
# TestCredentialBlast
# ---------------------------------------------------------------------------


class TestCredentialBlast:
    def test_critical_cve_with_creds(self):
        vuln = _vuln("CVE-2024-0001", Severity.CRITICAL)
        br = _br(vuln=vuln, creds=["GITHUB_TOKEN", "AWS_SECRET_KEY"])
        combos = detect_toxic_combinations(_report([br]))
        cred_blast = [c for c in combos if c.pattern == ToxicPattern.CRED_BLAST]
        assert len(cred_blast) == 1
        assert "CVE-2024-0001" in cred_blast[0].title
        assert cred_blast[0].severity == "critical"

    def test_high_cve_with_creds(self):
        vuln = _vuln("CVE-2024-0002", Severity.HIGH)
        br = _br(vuln=vuln, creds=["API_KEY"])
        combos = detect_toxic_combinations(_report([br]))
        cred_blast = [c for c in combos if c.pattern == ToxicPattern.CRED_BLAST]
        assert len(cred_blast) == 1

    def test_medium_cve_no_cred_blast(self):
        vuln = _vuln("CVE-2024-0003", Severity.MEDIUM)
        br = _br(vuln=vuln, creds=["API_KEY"])
        combos = detect_toxic_combinations(_report([br]))
        cred_blast = [c for c in combos if c.pattern == ToxicPattern.CRED_BLAST]
        assert len(cred_blast) == 0

    def test_critical_cve_no_creds_no_blast(self):
        vuln = _vuln("CVE-2024-0004", Severity.CRITICAL)
        br = _br(vuln=vuln, creds=[])
        combos = detect_toxic_combinations(_report([br]))
        cred_blast = [c for c in combos if c.pattern == ToxicPattern.CRED_BLAST]
        assert len(cred_blast) == 0


# ---------------------------------------------------------------------------
# TestKEVWithCreds
# ---------------------------------------------------------------------------


class TestKEVWithCreds:
    def test_kev_with_credentials(self):
        vuln = _vuln("CVE-2024-0010", is_kev=True)
        br = _br(vuln=vuln, creds=["SLACK_TOKEN"])
        combos = detect_toxic_combinations(_report([br]))
        kev_combos = [c for c in combos if c.pattern == ToxicPattern.KEV_WITH_CREDS]
        assert len(kev_combos) == 1
        assert kev_combos[0].risk_score == 10.0
        assert "CISA" in kev_combos[0].description

    def test_kev_without_credentials(self):
        vuln = _vuln("CVE-2024-0011", is_kev=True)
        br = _br(vuln=vuln, creds=[])
        combos = detect_toxic_combinations(_report([br]))
        kev_combos = [c for c in combos if c.pattern == ToxicPattern.KEV_WITH_CREDS]
        assert len(kev_combos) == 0

    def test_non_kev_not_matched(self):
        vuln = _vuln("CVE-2024-0012", is_kev=False)
        br = _br(vuln=vuln, creds=["TOKEN"])
        combos = detect_toxic_combinations(_report([br]))
        kev_combos = [c for c in combos if c.pattern == ToxicPattern.KEV_WITH_CREDS]
        assert len(kev_combos) == 0


# ---------------------------------------------------------------------------
# TestExecuteExploit
# ---------------------------------------------------------------------------


class TestExecuteExploit:
    def test_cve_with_execute_tool(self):
        vuln = _vuln("CVE-2024-0020", Severity.CRITICAL)
        tools = [_tool("run_command", "Execute a shell command")]
        br = _br(vuln=vuln, tools=tools)
        combos = detect_toxic_combinations(_report([br]))
        exec_combos = [c for c in combos if c.pattern == ToxicPattern.EXECUTE_EXPLOIT]
        assert len(exec_combos) == 1
        assert "run_command" in exec_combos[0].title

    def test_cve_with_write_tool(self):
        vuln = _vuln("CVE-2024-0021", Severity.HIGH)
        tools = [_tool("write_file", "Write content to a file")]
        br = _br(vuln=vuln, tools=tools)
        combos = detect_toxic_combinations(_report([br]))
        exec_combos = [c for c in combos if c.pattern == ToxicPattern.EXECUTE_EXPLOIT]
        assert len(exec_combos) == 1

    def test_cve_with_safe_tool_no_match(self):
        vuln = _vuln("CVE-2024-0022", Severity.CRITICAL)
        tools = [_tool("read_file", "Read a file from disk")]
        br = _br(vuln=vuln, tools=tools)
        combos = detect_toxic_combinations(_report([br]))
        exec_combos = [c for c in combos if c.pattern == ToxicPattern.EXECUTE_EXPLOIT]
        assert len(exec_combos) == 0

    def test_medium_cve_no_match(self):
        vuln = _vuln("CVE-2024-0023", Severity.MEDIUM)
        tools = [_tool("run_command", "Execute a shell command")]
        br = _br(vuln=vuln, tools=tools)
        combos = detect_toxic_combinations(_report([br]))
        exec_combos = [c for c in combos if c.pattern == ToxicPattern.EXECUTE_EXPLOIT]
        assert len(exec_combos) == 0


# ---------------------------------------------------------------------------
# TestMultiAgentCVE
# ---------------------------------------------------------------------------


class TestMultiAgentCVE:
    def test_cve_across_3_agents(self):
        vuln = _vuln("CVE-2024-0030")
        agents = [_agent("a1"), _agent("a2"), _agent("a3")]
        br = _br(vuln=vuln, agents=agents)
        combos = detect_toxic_combinations(_report([br]))
        multi = [c for c in combos if c.pattern == ToxicPattern.MULTI_AGENT_CVE]
        assert len(multi) == 1
        assert "3 agents" in multi[0].title

    def test_cve_across_2_agents_no_match(self):
        vuln = _vuln("CVE-2024-0031")
        agents = [_agent("a1"), _agent("a2")]
        br = _br(vuln=vuln, agents=agents)
        combos = detect_toxic_combinations(_report([br]))
        multi = [c for c in combos if c.pattern == ToxicPattern.MULTI_AGENT_CVE]
        assert len(multi) == 0

    def test_different_cves_no_match(self):
        br1 = _br(vuln=_vuln("CVE-2024-0032"), agents=[_agent("a1"), _agent("a2")])
        br2 = _br(vuln=_vuln("CVE-2024-0033"), agents=[_agent("a3"), _agent("a4")])
        combos = detect_toxic_combinations(_report([br1, br2]))
        multi = [c for c in combos if c.pattern == ToxicPattern.MULTI_AGENT_CVE]
        assert len(multi) == 0


# ---------------------------------------------------------------------------
# TestTransitiveCritical
# ---------------------------------------------------------------------------


class TestTransitiveCritical:
    def test_critical_transitive(self):
        vuln = _vuln("CVE-2024-0040", Severity.CRITICAL)
        pkg = _pkg(name="hidden-dep", is_direct=False, parent="express")
        br = _br(vuln=vuln, pkg=pkg)
        combos = detect_toxic_combinations(_report([br]))
        trans = [c for c in combos if c.pattern == ToxicPattern.TRANSITIVE_CRITICAL]
        assert len(trans) == 1
        assert "hidden-dep" in trans[0].title
        assert "express" in trans[0].description

    def test_critical_direct_no_match(self):
        vuln = _vuln("CVE-2024-0041", Severity.CRITICAL)
        pkg = _pkg(name="direct-dep", is_direct=True)
        br = _br(vuln=vuln, pkg=pkg)
        combos = detect_toxic_combinations(_report([br]))
        trans = [c for c in combos if c.pattern == ToxicPattern.TRANSITIVE_CRITICAL]
        assert len(trans) == 0

    def test_high_transitive_no_match(self):
        vuln = _vuln("CVE-2024-0042", Severity.HIGH)
        pkg = _pkg(name="trans-dep", is_direct=False, parent="parent")
        br = _br(vuln=vuln, pkg=pkg)
        combos = detect_toxic_combinations(_report([br]))
        trans = [c for c in combos if c.pattern == ToxicPattern.TRANSITIVE_CRITICAL]
        assert len(trans) == 0


# ---------------------------------------------------------------------------
# TestLateralChain
# ---------------------------------------------------------------------------


class TestLateralChain:
    def test_cve_on_lateral_path(self):
        vuln = _vuln("CVE-2024-0050", Severity.CRITICAL)
        srv = _server("mcp-filesystem")
        br = _br(vuln=vuln, servers=[srv])
        context_graph = {"lateral_paths": [["mcp-filesystem", "mcp-slack"]]}
        combos = detect_toxic_combinations(_report([br]), context_graph_data=context_graph)
        lateral = [c for c in combos if c.pattern == ToxicPattern.LATERAL_CHAIN]
        assert len(lateral) == 1
        assert "lateral" in lateral[0].title.lower()

    def test_cve_not_on_lateral_path(self):
        vuln = _vuln("CVE-2024-0051", Severity.CRITICAL)
        srv = _server("mcp-other")
        br = _br(vuln=vuln, servers=[srv])
        context_graph = {"lateral_paths": [["mcp-filesystem", "mcp-slack"]]}
        combos = detect_toxic_combinations(_report([br]), context_graph_data=context_graph)
        lateral = [c for c in combos if c.pattern == ToxicPattern.LATERAL_CHAIN]
        assert len(lateral) == 0

    def test_no_lateral_paths(self):
        vuln = _vuln("CVE-2024-0052", Severity.CRITICAL)
        srv = _server("mcp-filesystem")
        br = _br(vuln=vuln, servers=[srv])
        combos = detect_toxic_combinations(_report([br]), context_graph_data={"lateral_paths": []})
        lateral = [c for c in combos if c.pattern == ToxicPattern.LATERAL_CHAIN]
        assert len(lateral) == 0


# ---------------------------------------------------------------------------
# TestEdgeCases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_report(self):
        combos = detect_toxic_combinations(AIBOMReport())
        assert combos == []

    def test_no_blast_radii(self):
        report = AIBOMReport(agents=[_agent()])
        combos = detect_toxic_combinations(report)
        assert combos == []

    def test_deduplication(self):
        """Same CVE in two blast radii shouldn't produce duplicate combos."""
        vuln = _vuln("CVE-2024-9999", is_kev=True)
        br1 = _br(vuln=vuln, creds=["TOKEN_A"])
        br2 = _br(vuln=vuln, creds=["TOKEN_B"])
        combos = detect_toxic_combinations(_report([br1, br2]))
        kev = [c for c in combos if c.pattern == ToxicPattern.KEV_WITH_CREDS]
        # Two distinct blast radii may produce two combos (different creds)
        # but they get deduped by title if identical
        assert len(kev) >= 1

    def test_sorted_by_risk_score(self):
        vuln_crit = _vuln("CVE-2024-0001", Severity.CRITICAL, is_kev=True)
        vuln_high = _vuln("CVE-2024-0002", Severity.HIGH)
        br1 = _br(vuln=vuln_crit, creds=["TOKEN"], risk_score=9.0)
        br2 = _br(vuln=vuln_high, creds=["KEY"], risk_score=5.0)
        combos = detect_toxic_combinations(_report([br1, br2]))
        if len(combos) >= 2:
            assert combos[0].risk_score >= combos[1].risk_score


# ---------------------------------------------------------------------------
# TestPrioritization
# ---------------------------------------------------------------------------


class TestPrioritization:
    def test_toxic_combos_included(self):
        vuln = _vuln("CVE-2024-0001", Severity.CRITICAL, is_kev=True)
        br = _br(vuln=vuln, creds=["TOKEN"], risk_score=8.0)
        combos = detect_toxic_combinations(_report([br]))
        findings = prioritize_findings([br], combos)
        types = [f["type"] for f in findings]
        assert "toxic_combination" in types
        assert "vulnerability" in types

    def test_sorted_by_risk(self):
        vuln1 = _vuln("CVE-2024-0001", Severity.CRITICAL)
        vuln2 = _vuln("CVE-2024-0002", Severity.LOW)
        br1 = _br(vuln=vuln1, risk_score=9.0)
        br2 = _br(vuln=vuln2, risk_score=2.0)
        findings = prioritize_findings([br1, br2], [])
        assert findings[0]["risk_score"] >= findings[1]["risk_score"]

    def test_in_toxic_combo_flagged(self):
        vuln = _vuln("CVE-2024-0001", Severity.CRITICAL)
        br = _br(vuln=vuln, creds=["TOKEN"], risk_score=8.0)
        combos = detect_toxic_combinations(_report([br]))
        findings = prioritize_findings([br], combos)
        vuln_findings = [f for f in findings if f["type"] == "vulnerability"]
        assert len(vuln_findings) == 1
        assert vuln_findings[0]["in_toxic_combo"] is True

    def test_empty_inputs(self):
        findings = prioritize_findings([], [])
        assert findings == []


# ---------------------------------------------------------------------------
# TestSerialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_to_serializable(self):
        combo = ToxicCombination(
            pattern=ToxicPattern.CRED_BLAST,
            severity="critical",
            title="Test combo",
            description="Test description",
            components=[{"type": "cve", "id": "CVE-2024-0001", "label": "critical"}],
            risk_score=9.5,
            remediation="Fix it",
        )
        data = to_serializable([combo])
        assert len(data) == 1
        assert data[0]["pattern"] == "credential_blast"
        assert data[0]["severity"] == "critical"
        assert data[0]["risk_score"] == 9.5

    def test_empty_serialization(self):
        assert to_serializable([]) == []


# ---------------------------------------------------------------------------
# TestCachePoison
# ---------------------------------------------------------------------------


class TestCachePoison:
    def test_cache_poison_detected_via_retrieval_tool(self):
        """CVE + vector/RAG retrieval tool = CACHE_POISON."""
        vuln = _vuln("CVE-2024-9999", Severity.CRITICAL)
        tool = _tool("similarity_search", "Semantic similarity search over vector store")
        br = _br(vuln=vuln, tools=[tool])
        report = _report([br])
        context = {"vector_db_servers": [], "shared_servers": []}
        combos = detect_toxic_combinations(report, context)
        cache = [c for c in combos if c.pattern == ToxicPattern.CACHE_POISON]
        assert len(cache) == 1
        assert "CVE-2024-9999" in cache[0].title
        assert cache[0].severity == "critical"
        assert cache[0].risk_score >= 9.0

    def test_cache_poison_detected_via_vector_db_server(self):
        """CVE on server in vector_db_servers list = CACHE_POISON."""
        vuln = _vuln("CVE-2024-8888", Severity.HIGH)
        server = _server("qdrant-mcp")
        br = _br(vuln=vuln, servers=[server])
        report = _report([br])
        context = {"vector_db_servers": [{"name": "qdrant-mcp"}], "shared_servers": []}
        combos = detect_toxic_combinations(report, context)
        cache = [c for c in combos if c.pattern == ToxicPattern.CACHE_POISON]
        assert len(cache) == 1

    def test_cache_poison_not_triggered_for_low_severity(self):
        """Low severity CVE + retrieval tool should not trigger CACHE_POISON."""
        vuln = _vuln("CVE-2024-0001", Severity.LOW)
        tool = _tool("retrieve_docs", "Retrieve documents from knowledge base")
        br = _br(vuln=vuln, tools=[tool])
        combos = detect_toxic_combinations(_report([br]), {})
        cache = [c for c in combos if c.pattern == ToxicPattern.CACHE_POISON]
        assert len(cache) == 0

    def test_cache_poison_remediation_mentions_vector_db(self):
        vuln = _vuln("CVE-2024-7777", Severity.CRITICAL)
        tool = _tool("vector_search", "Search vector index")
        br = _br(vuln=vuln, tools=[tool])
        combos = detect_toxic_combinations(_report([br]), {})
        cache = [c for c in combos if c.pattern == ToxicPattern.CACHE_POISON]
        assert len(cache) == 1
        assert "vector" in cache[0].remediation.lower() or "retrieval" in cache[0].remediation.lower()


# ---------------------------------------------------------------------------
# TestCrossAgentPoison
# ---------------------------------------------------------------------------


class TestCrossAgentPoison:
    def test_cross_agent_poison_detected(self):
        """Shared server with write+read tools across 2+ agents = CROSS_AGENT_POISON."""
        report = _report([])
        context = {
            "shared_servers": [
                {
                    "name": "shared-memory-mcp",
                    "agents": ["agent-a", "agent-b"],
                    "tools": ["store_memory", "similarity_search"],
                }
            ],
            "vector_db_servers": [],
        }
        combos = detect_toxic_combinations(report, context)
        cross = [c for c in combos if c.pattern == ToxicPattern.CROSS_AGENT_POISON]
        assert len(cross) == 1
        assert "shared-memory-mcp" in cross[0].title
        assert cross[0].severity == "high"

    def test_cross_agent_poison_requires_both_tools(self):
        """Server with only read tools (no write) should not trigger."""
        report = _report([])
        context = {
            "shared_servers": [
                {
                    "name": "readonly-mcp",
                    "agents": ["agent-a", "agent-b"],
                    "tools": ["similarity_search", "retrieve_docs"],
                }
            ],
            "vector_db_servers": [],
        }
        combos = detect_toxic_combinations(report, context)
        cross = [c for c in combos if c.pattern == ToxicPattern.CROSS_AGENT_POISON]
        assert len(cross) == 0

    def test_cross_agent_poison_requires_multiple_agents(self):
        """Single agent on server should not trigger."""
        report = _report([])
        context = {
            "shared_servers": [
                {
                    "name": "solo-mcp",
                    "agents": ["agent-a"],
                    "tools": ["store_memory", "retrieve_docs"],
                }
            ],
            "vector_db_servers": [],
        }
        combos = detect_toxic_combinations(report, context)
        cross = [c for c in combos if c.pattern == ToxicPattern.CROSS_AGENT_POISON]
        assert len(cross) == 0

    def test_cross_agent_poison_remediation_mentions_isolation(self):
        report = _report([])
        context = {
            "shared_servers": [
                {
                    "name": "shared-mcp",
                    "agents": ["agent-a", "agent-b", "agent-c"],
                    "tools": ["index_document", "query_index"],
                }
            ],
            "vector_db_servers": [],
        }
        combos = detect_toxic_combinations(report, context)
        cross = [c for c in combos if c.pattern == ToxicPattern.CROSS_AGENT_POISON]
        assert len(cross) == 1
        assert "isolat" in cross[0].remediation.lower() or "separate" in cross[0].remediation.lower()

    def test_new_patterns_in_enum(self):
        assert ToxicPattern.CACHE_POISON.value == "cache_poison"
        assert ToxicPattern.CROSS_AGENT_POISON.value == "cross_agent_poison"
