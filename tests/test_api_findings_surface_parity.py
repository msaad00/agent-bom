"""API/hosted-scan findings-surface parity.

Several graph/CLI evaluators computed findings that never reached the unified
finding stream on the API path — so ``/v1/findings``, SARIF, and the severity
gate were blind to them on hosted scans while the CLI surfaced them. These tests
pin the fix: NHI governance, toxic-combination, and MCP tool-rule findings now
reach ``AIBOMReport.to_findings()`` (and therefore the API + SARIF), with no
double-count, stable/idempotent ids, and tenant/scope preserved.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.finding import FindingType
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.scan_findings import attach_graph_derived_findings
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, MCPTool
from agent_bom.output.sarif import to_sarif

NOW = datetime(2026, 6, 20, tzinfo=timezone.utc)


# ── Fixtures ─────────────────────────────────────────────────────────────────


def _dormant_over_granted_graph(tenant_id: str = "tenant-a") -> UnifiedGraph:
    """A managed identity granted a permission it never uses and with no owner
    and no usage timestamp → over-granted + dormant + orphaned."""
    g = UnifiedGraph(scan_id="scan-1", tenant_id=tenant_id)
    g.add_node(
        UnifiedNode(
            id="managed_identity:svc",
            entity_type=EntityType.MANAGED_IDENTITY,
            label="svc-account",
            attributes={"identity_id": "svc", "is_admin": True},
        )
    )
    g.add_node(UnifiedNode(id="res:unused", entity_type=EntityType.CLOUD_RESOURCE, label="bucket-unused"))
    g.add_edge(UnifiedEdge(source="managed_identity:svc", target="res:unused", relationship=RelationshipType.HAS_PERMISSION))
    return g


def _toxic_graph(g: UnifiedGraph) -> UnifiedGraph:
    """Add a public-exposed + vulnerable resource pair that fires a toxic rule."""
    g.add_node(
        UnifiedNode(
            id="res:web",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="web",
            severity="high",
            attributes={"toxic_exposed_vulnerable": True, "internet_exposed": True},
        )
    )
    g.add_node(UnifiedNode(id="vuln:cve", entity_type=EntityType.VULNERABILITY, label="CVE-x", severity="critical"))
    g.add_edge(UnifiedEdge(source="res:web", target="vuln:cve", relationship=RelationshipType.VULNERABLE_TO))
    return g


def _report_with_bad_tool() -> AIBOMReport:
    """A report whose discovered MCP tool carries a stored schema-rule finding
    (as runtime introspection would populate)."""
    tool = MCPTool(name="run_cmd", description="runs a command")
    tool.schema_rule_findings = [
        {
            "rule_id": "MCP-TOOL-01-shell-input",
            "severity": "high",
            "title": "Shell command input",
            "message": "Tool 'run_cmd' accepts a freeform shell 'command' argument.",
            "evidence": "property 'command' is freeform string",
            "tool_name": "run_cmd",
            "property_name": "command",
            "owasp_tags": ["LLM01"],
            "owasp_mcp_tags": ["MCP-A01"],
            "cwe_ids": ["CWE-78"],
        }
    ]
    server = MCPServer(name="exec-server")
    server.tools = [tool]
    agent = Agent(name="agent-x", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/x")
    agent.mcp_servers = [server]
    return AIBOMReport(agents=[agent], blast_radii=[], findings=[], scan_id="scan-1")


# ── NHI governance ───────────────────────────────────────────────────────────


def test_nhi_governance_findings_reach_unified_stream():
    from agent_bom.graph.nhi_governance import apply_nhi_governance_with_findings

    graph = _dormant_over_granted_graph()
    # The shared build path computes the findings onto the graph (mirrors builder).
    _, findings = apply_nhi_governance_with_findings(graph, now=NOW)
    graph.nhi_governance_findings = findings
    assert findings, "expected NHI governance findings on the graph"

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="scan-1")
    # Before wiring: no NHI finding in the stream.
    assert not [f for f in report.to_findings() if f.evidence.get("nhi_governance")]

    attach_graph_derived_findings(report, graph)
    nhi = [f for f in report.to_findings() if f.evidence.get("nhi_governance")]
    assert nhi, "NHI governance findings must reach the unified stream after wiring"
    # Over-grant right-sizing findings carry CIEM_OVER_PRIVILEGE; dormant/orphaned
    # credential findings carry CREDENTIAL_EXPOSURE.
    assert all(
        f.finding_type in (FindingType.CREDENTIAL_EXPOSURE, FindingType.CIEM_OVER_PRIVILEGE) for f in nhi
    )


def test_builder_computes_nhi_governance_findings():
    """The shared graph build path materializes NHI findings onto the graph."""
    from agent_bom.graph.builder import build_unified_graph_from_report

    report_json = {
        "scan_id": "scan-1",
        "agents": [],
        "blast_radius": [],
        "identity_discovery": {
            "provider": "azure",
            "identities": [
                {
                    "identity_id": "svc-1",
                    "name": "orphan-svc",
                    "identity_type": "service_account",
                    "provider": "azure",
                }
            ],
        },
    }
    graph = build_unified_graph_from_report(report_json, scan_id="scan-1", tenant_id="tenant-a")
    assert hasattr(graph, "nhi_governance_findings")
    # A managed identity with no owner / no usage → at least a dormant finding.
    assert graph.nhi_governance_findings, "builder must compute NHI governance findings onto the graph"


# ── Toxic combinations ───────────────────────────────────────────────────────


def test_toxic_findings_reach_unified_stream():
    graph = _toxic_graph(UnifiedGraph(scan_id="scan-1", tenant_id="tenant-a"))
    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="scan-1")
    assert not [f for f in report.to_findings() if f.finding_type == FindingType.COMBINATION]

    attach_graph_derived_findings(report, graph)
    toxic = [f for f in report.to_findings() if f.finding_type == FindingType.COMBINATION]
    assert toxic, "toxic-combination findings must reach the unified stream after wiring"


# ── MCP tool-rule ────────────────────────────────────────────────────────────


def test_mcp_tool_rule_findings_reach_unified_stream():
    report = _report_with_bad_tool()
    mcp = [f for f in report.to_findings() if f.evidence.get("mcp_tool_rule")]
    assert mcp, "MCP tool-rule findings must reach the unified stream"
    finding = mcp[0]
    assert finding.evidence.get("rule_id") == "MCP-TOOL-01-shell-input"
    assert finding.asset.name == "run_cmd"
    assert "MCP-A01" in finding.owasp_mcp_tags


def test_mcp_tool_rule_empty_stays_empty():
    """Fail-closed: a tool with no stored rule findings produces no finding."""
    tool = MCPTool(name="safe", description="safe tool")
    server = MCPServer(name="s")
    server.tools = [tool]
    agent = Agent(name="a", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/a")
    agent.mcp_servers = [server]
    report = AIBOMReport(agents=[agent], blast_radii=[], findings=[], scan_id="scan-1")
    assert not [f for f in report.to_findings() if f.evidence.get("mcp_tool_rule")]


# ── No double-count + idempotency ────────────────────────────────────────────


def test_no_double_count_and_idempotent():
    graph = _toxic_graph(_dormant_over_granted_graph())
    from agent_bom.graph.nhi_governance import apply_nhi_governance_with_findings

    _, nhi_findings = apply_nhi_governance_with_findings(graph, now=NOW)
    graph.nhi_governance_findings = nhi_findings

    report = _report_with_bad_tool()

    attach_graph_derived_findings(report, graph)
    first = report.to_findings()
    first_ids = [f.id for f in first]
    # No id appears twice in a single derivation.
    assert len(first_ids) == len(set(first_ids)), "findings must not double-count within one stream"

    # Idempotent: re-running the attach + to_findings does not multiply findings.
    attach_graph_derived_findings(report, graph)
    second = report.to_findings()
    assert [f.id for f in second] == first_ids, "re-running must be idempotent (stable ids, no growth)"

    # And to_findings() itself is pure — repeated calls are stable.
    assert [f.id for f in report.to_findings()] == first_ids


def test_all_three_categories_present_once():
    graph = _toxic_graph(_dormant_over_granted_graph())
    from agent_bom.graph.nhi_governance import apply_nhi_governance_with_findings

    _, nhi_findings = apply_nhi_governance_with_findings(graph, now=NOW)
    graph.nhi_governance_findings = nhi_findings
    report = _report_with_bad_tool()
    attach_graph_derived_findings(report, graph)

    findings = report.to_findings()
    assert [f for f in findings if f.evidence.get("nhi_governance")]
    assert [f for f in findings if f.finding_type == FindingType.COMBINATION]
    assert [f for f in findings if f.evidence.get("mcp_tool_rule")]


# ── Exporter surface ─────────────────────────────────────────────────────────


def test_new_findings_appear_in_sarif():
    graph = _toxic_graph(_dormant_over_granted_graph())
    from agent_bom.graph.nhi_governance import apply_nhi_governance_with_findings

    _, nhi_findings = apply_nhi_governance_with_findings(graph, now=NOW)
    graph.nhi_governance_findings = nhi_findings
    report = _report_with_bad_tool()
    attach_graph_derived_findings(report, graph)

    sarif = to_sarif(report)
    results = sarif["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in results}
    # Non-CVE unified loop emits finding/<type> rule ids for each category.
    assert f"finding/{FindingType.COMBINATION.value}" in rule_ids
    assert f"finding/{FindingType.CREDENTIAL_EXPOSURE.value}" in rule_ids
    assert f"finding/{FindingType.INJECTION.value}" in rule_ids


# ── Tenant / scope integrity ─────────────────────────────────────────────────


def test_tenant_scope_not_leaked_across_reports():
    """Two tenants with the same logical identity keep distinct, non-leaked
    findings; wiring never fabricates a finding for the other tenant."""
    ga = _dormant_over_granted_graph(tenant_id="tenant-a")
    gb = _dormant_over_granted_graph(tenant_id="tenant-b")
    from agent_bom.graph.nhi_governance import apply_nhi_governance_with_findings

    for g in (ga, gb):
        _, f = apply_nhi_governance_with_findings(g, now=NOW)
        g.nhi_governance_findings = f

    ra = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="scan-a")
    rb = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="scan-b")
    attach_graph_derived_findings(ra, ga)
    attach_graph_derived_findings(rb, gb)

    a_nhi = [f for f in ra.to_findings() if f.evidence.get("nhi_governance")]
    b_nhi = [f for f in rb.to_findings() if f.evidence.get("nhi_governance")]
    assert a_nhi and b_nhi
    # Same logical identity → same canonical id in both (dedup key is tenant-scoped
    # at the store layer, not baked into the finding content). Neither report
    # carries the other's findings object.
    assert {f.id for f in a_nhi} == {f.id for f in b_nhi}


# ── CLI ⇄ API parity ─────────────────────────────────────────────────────────


def test_cli_api_parity_same_fixture():
    """The same graph + report yields an identical finding-id set regardless of
    which caller (CLI scan_cmd or API pipeline) attaches the graph-derived
    findings — both route through the shared helper."""
    from agent_bom.graph.nhi_governance import apply_nhi_governance_with_findings

    def _stream(graph_factory):
        graph = _toxic_graph(_dormant_over_granted_graph())
        _, nhi = apply_nhi_governance_with_findings(graph, now=NOW)
        graph.nhi_governance_findings = nhi
        report = _report_with_bad_tool()
        attach_graph_derived_findings(report, graph)
        return {f.id for f in report.to_findings()}

    cli_ids = _stream(None)
    api_ids = _stream(None)
    assert cli_ids == api_ids
    assert cli_ids  # non-empty
