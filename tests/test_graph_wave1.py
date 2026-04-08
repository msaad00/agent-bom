"""Wave 1 tests — reverse queries, impact, search, new entity/relationship types,
runtime edges, blast radius enrichment, legends.
"""

from __future__ import annotations

from agent_bom.graph import (
    ENTITY_LEGEND,
    RELATIONSHIP_LEGEND,
    EntityType,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
)
from agent_bom.graph.builder import build_unified_graph_from_report


def _full_report():
    """Report with all entity types for Wave 1 testing."""
    return {
        "scan_id": "wave1-test",
        "agents": [
            {
                "name": "claude-desktop",
                "type": "claude-desktop",
                "status": "configured",
                "mcp_servers": [
                    {
                        "name": "mcp-fs",
                        "command": "npx",
                        "transport": "stdio",
                        "surface": "mcp-server",
                        "packages": [
                            {
                                "name": "express",
                                "version": "4.18.0",
                                "ecosystem": "npm",
                                "vulnerabilities": [
                                    {"id": "CVE-2024-1", "severity": "critical", "cvss_score": 9.8, "is_kev": True},
                                ],
                            },
                        ],
                        "tools": [{"name": "exec_cmd", "description": "Execute shell command"}],
                        "credential_env_vars": ["GITHUB_TOKEN"],
                    }
                ],
            },
        ],
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-1",
                "severity": "critical",
                "package_name": "express",
                "package_version": "4.18.0",
                "ecosystem": "npm",
                "risk_score": 9.8,
                "affected_agents": ["claude-desktop"],
                "affected_servers": ["mcp-fs"],
                "exposed_credentials": ["GITHUB_TOKEN"],
                "exposed_tools": [{"name": "exec_cmd"}],
                "reachability": "confirmed",
                "actionable": True,
                "owasp_tags": ["OWASP-A06"],
            },
        ],
        "runtime_session_graph": {
            "edges": [
                {
                    "source_node_id": "agent:claude-desktop",
                    "target_node_id": "tool:server:claude-desktop:mcp-fs:exec_cmd",
                    "interaction_type": "tool_call",
                    "timestamp": "2026-04-08T00:00:00Z",
                },
            ],
        },
        "model_provenance": [
            {"model_name": "gpt-4o", "framework": "openai", "source": "api", "verified": True},
        ],
        "toxic_combinations": [
            {"name": "rce_chain", "vulnerability_ids": ["CVE-2024-1"], "risk_score": 10.0},
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════
# New entity types
# ═══════════════════════════════════════════════════════════════════════════


class TestNewEntityTypes:
    def test_user_group_service_account_in_enum(self):
        assert EntityType.USER.value == "user"
        assert EntityType.GROUP.value == "group"
        assert EntityType.SERVICE_ACCOUNT.value == "service_account"

    def test_fleet_cluster_in_enum(self):
        assert EntityType.FLEET.value == "fleet"
        assert EntityType.CLUSTER.value == "cluster"

    def test_user_is_ocsf_category_3(self):
        from agent_bom.graph.ocsf import ENTITY_OCSF_MAP

        assert ENTITY_OCSF_MAP[EntityType.USER.value]["category_uid"] == 3
        assert ENTITY_OCSF_MAP[EntityType.GROUP.value]["category_uid"] == 3

    def test_fleet_is_ocsf_category_5(self):
        from agent_bom.graph.ocsf import ENTITY_OCSF_MAP

        assert ENTITY_OCSF_MAP[EntityType.FLEET.value]["category_uid"] == 5


# ═══════════════════════════════════════════════════════════════════════════
# New relationship types
# ═══════════════════════════════════════════════════════════════════════════


class TestNewRelationshipTypes:
    def test_governance_relationships(self):
        assert RelationshipType.MANAGES.value == "manages"
        assert RelationshipType.OWNS.value == "owns"
        assert RelationshipType.PART_OF.value == "part_of"
        assert RelationshipType.MEMBER_OF.value == "member_of"

    def test_vulnerability_relationships(self):
        assert RelationshipType.REMEDIATES.value == "remediates"
        assert RelationshipType.TRIGGERS.value == "triggers"


# ═══════════════════════════════════════════════════════════════════════════
# Reverse adjacency & impact
# ═══════════════════════════════════════════════════════════════════════════


class TestReverseAdjacency:
    def test_edges_to(self):
        g = UnifiedGraph()
        g.add_node(UnifiedNode(id="a", entity_type=EntityType.AGENT, label="a"))
        g.add_node(UnifiedNode(id="s", entity_type=EntityType.SERVER, label="s"))
        g.add_edge(UnifiedEdge(source="a", target="s", relationship=RelationshipType.USES))

        # "what points at server s?"
        incoming = g.edges_to("s")
        assert len(incoming) == 1
        assert incoming[0].source == "a"

    def test_sources_of(self):
        g = UnifiedGraph()
        g.add_node(UnifiedNode(id="a1", entity_type=EntityType.AGENT, label="a1"))
        g.add_node(UnifiedNode(id="a2", entity_type=EntityType.AGENT, label="a2"))
        g.add_node(UnifiedNode(id="s", entity_type=EntityType.SERVER, label="s"))
        g.add_edge(UnifiedEdge(source="a1", target="s", relationship=RelationshipType.USES))
        g.add_edge(UnifiedEdge(source="a2", target="s", relationship=RelationshipType.USES))

        sources = g.sources_of("s")
        assert set(sources) == {"a1", "a2"}

    def test_impact_of_vuln(self):
        g = build_unified_graph_from_report(_full_report())
        impact = g.impact_of("vuln:CVE-2024-1")

        # Vuln is pointed at by package and server — their parents (agent) are affected
        assert impact["affected_count"] > 0
        assert "package" in impact["affected_by_type"] or "server" in impact["affected_by_type"]

    def test_impact_of_nonexistent_node(self):
        g = UnifiedGraph()
        impact = g.impact_of("doesnt:exist")
        assert impact["affected_count"] == 0


# ═══════════════════════════════════════════════════════════════════════════
# Search
# ═══════════════════════════════════════════════════════════════════════════


class TestSearch:
    def test_search_by_label(self):
        g = build_unified_graph_from_report(_full_report())
        results = g.search_nodes("express")
        labels = {r.label for r in results}
        assert any("express" in lbl for lbl in labels)

    def test_search_by_entity_type(self):
        g = build_unified_graph_from_report(_full_report())
        results = g.search_nodes("vulnerability")
        assert any(r.entity_type == EntityType.VULNERABILITY for r in results)

    def test_search_by_severity(self):
        g = build_unified_graph_from_report(_full_report())
        results = g.search_nodes("critical")
        assert len(results) >= 1

    def test_search_by_compliance_tag(self):
        g = build_unified_graph_from_report(_full_report())
        results = g.search_nodes("OWASP")
        assert len(results) >= 1

    def test_search_empty_query(self):
        g = build_unified_graph_from_report(_full_report())
        # Single char search
        results = g.search_nodes("z")
        # May or may not find anything, just shouldn't crash
        assert isinstance(results, list)

    def test_search_limit(self):
        g = build_unified_graph_from_report(_full_report())
        results = g.search_nodes("a", limit=2)
        assert len(results) <= 2


# ═══════════════════════════════════════════════════════════════════════════
# Runtime edges
# ═══════════════════════════════════════════════════════════════════════════


class TestRuntimeEdges:
    def test_invoked_edge_created(self):
        g = build_unified_graph_from_report(_full_report())
        invoked = [e for e in g.edges if e.relationship == RelationshipType.INVOKED]
        assert len(invoked) >= 1
        assert invoked[0].source == "agent:claude-desktop"

    def test_runtime_edges_have_evidence(self):
        g = build_unified_graph_from_report(_full_report())
        invoked = [e for e in g.edges if e.relationship == RelationshipType.INVOKED]
        assert invoked[0].evidence.get("timestamp")


# ═══════════════════════════════════════════════════════════════════════════
# Toxic combination edges
# ═══════════════════════════════════════════════════════════════════════════


class TestToxicCombos:
    def test_triggers_edge_created(self):
        g = build_unified_graph_from_report(_full_report())
        triggers = [e for e in g.edges if e.relationship == RelationshipType.TRIGGERS]
        assert len(triggers) >= 1
        assert triggers[0].source == "vuln:CVE-2024-1"


# ═══════════════════════════════════════════════════════════════════════════
# Blast radius enrichment
# ═══════════════════════════════════════════════════════════════════════════


class TestBlastRadiusEnrichment:
    def test_vuln_node_has_blast_stats(self):
        g = build_unified_graph_from_report(_full_report())
        vuln = g.get_node("vuln:CVE-2024-1")
        assert vuln is not None
        assert vuln.attributes.get("affected_agent_count") == 1
        assert vuln.attributes.get("affected_server_count") == 1
        assert vuln.attributes.get("reachability") == "confirmed"
        assert vuln.attributes.get("actionable") is True


# ═══════════════════════════════════════════════════════════════════════════
# Legends
# ═══════════════════════════════════════════════════════════════════════════


class TestLegends:
    def test_entity_legend_covers_all_types(self):
        legend_keys = {e.key for e in ENTITY_LEGEND}
        for et in EntityType:
            assert et.value in legend_keys, f"Missing legend for {et.value}"

    def test_relationship_legend_covers_all_types(self):
        legend_keys = {e.key for e in RELATIONSHIP_LEGEND}
        for rt in RelationshipType:
            assert rt.value in legend_keys, f"Missing legend for {rt.value}"

    def test_legend_entries_have_color(self):
        for entry in ENTITY_LEGEND + RELATIONSHIP_LEGEND:
            assert entry.color.startswith("#"), f"Bad color for {entry.key}: {entry.color}"
