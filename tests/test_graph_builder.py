"""Tests for build_unified_graph_from_report() — full inventory graph."""

from __future__ import annotations

from agent_bom.graph import EntityType, RelationshipType
from agent_bom.graph.builder import build_unified_graph_from_report


def _minimal_report():
    """Minimal AIBOMReport JSON with agents, packages, vulns."""
    return {
        "scan_id": "test-full-001",
        "agents": [
            {
                "name": "claude-desktop",
                "type": "claude-desktop",
                "status": "configured",
                "config_path": "/home/user/.config/claude/config.json",
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
                                "is_direct": True,
                                "vulnerabilities": [
                                    {
                                        "id": "CVE-2024-1234",
                                        "severity": "high",
                                        "cvss_score": 7.5,
                                        "is_kev": False,
                                        "fixed_version": "4.19.0",
                                    }
                                ],
                            },
                            {
                                "name": "lodash",
                                "version": "4.17.21",
                                "ecosystem": "npm",
                                "is_direct": False,
                                "vulnerabilities": [],
                            },
                        ],
                        "tools": [
                            {"name": "read_file", "description": "Read a file from disk"},
                            {"name": "write_file", "description": "Write a file to disk"},
                        ],
                        "credential_env_vars": ["GITHUB_TOKEN", "OPENAI_API_KEY"],
                        "env": {},
                    }
                ],
            },
            {
                "name": "cursor",
                "type": "cursor",
                "status": "configured",
                "mcp_servers": [
                    {
                        "name": "mcp-fs",
                        "command": "npx",
                        "transport": "stdio",
                        "surface": "mcp-server",
                        "packages": [],
                        "tools": [],
                        "credential_env_vars": ["GITHUB_TOKEN"],
                        "env": {},
                    }
                ],
            },
        ],
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-1234",
                "severity": "high",
                "package_name": "express",
                "package_version": "4.18.0",
                "ecosystem": "npm",
                "risk_score": 7.5,
                "cvss_score": 7.5,
                "is_kev": False,
                "affected_agents": ["claude-desktop"],
                "affected_servers": ["mcp-fs"],
                "owasp_tags": ["OWASP-A06"],
                "atlas_tags": [],
                "attack_tags": ["MITRE-T1059"],
            }
        ],
    }


class TestBuildUnifiedGraphFromReport:
    def test_all_entity_types_present(self):
        report = _minimal_report()
        g = build_unified_graph_from_report(report)

        types = {n.entity_type for n in g.nodes.values()}
        assert EntityType.AGENT in types
        assert EntityType.SERVER in types
        assert EntityType.PACKAGE in types
        assert EntityType.TOOL in types
        assert EntityType.CREDENTIAL in types
        assert EntityType.VULNERABILITY in types

    def test_agent_nodes(self):
        g = build_unified_graph_from_report(_minimal_report())
        agents = g.nodes_by_type(EntityType.AGENT)
        assert len(agents) == 2
        names = {a.label for a in agents}
        assert names == {"claude-desktop", "cursor"}

    def test_server_nodes(self):
        g = build_unified_graph_from_report(_minimal_report())
        servers = g.nodes_by_type(EntityType.SERVER)
        assert len(servers) == 2  # one per agent

    def test_package_nodes(self):
        g = build_unified_graph_from_report(_minimal_report())
        packages = g.nodes_by_type(EntityType.PACKAGE)
        assert len(packages) == 2  # express + lodash
        labels = {p.label for p in packages}
        assert "express@4.18.0" in labels
        assert "lodash@4.17.21" in labels

    def test_tool_nodes(self):
        g = build_unified_graph_from_report(_minimal_report())
        tools = g.nodes_by_type(EntityType.TOOL)
        assert len(tools) == 2
        names = {t.label for t in tools}
        assert "read_file" in names
        assert "write_file" in names

    def test_credential_nodes(self):
        g = build_unified_graph_from_report(_minimal_report())
        creds = g.nodes_by_type(EntityType.CREDENTIAL)
        labels = {c.label for c in creds}
        assert "GITHUB_TOKEN" in labels
        assert "OPENAI_API_KEY" in labels

    def test_vulnerability_nodes(self):
        g = build_unified_graph_from_report(_minimal_report())
        vulns = g.nodes_by_type(EntityType.VULNERABILITY)
        assert len(vulns) == 1
        assert vulns[0].label == "CVE-2024-1234"
        assert vulns[0].severity == "high"
        assert vulns[0].category_uid == 2
        assert vulns[0].class_uid == 2001

    def test_package_to_vuln_edge(self):
        g = build_unified_graph_from_report(_minimal_report())
        pkg_id = "pkg:express:npm:4.18.0"
        vuln_id = "vuln:CVE-2024-1234"
        assert g.has_edge(pkg_id, vuln_id)

    def test_server_to_package_edge(self):
        g = build_unified_graph_from_report(_minimal_report())
        assert g.has_edge("server:claude-desktop:mcp-fs", "pkg:express:npm:4.18.0")

    def test_agent_to_server_edge(self):
        g = build_unified_graph_from_report(_minimal_report())
        assert g.has_edge("agent:claude-desktop", "server:claude-desktop:mcp-fs")

    def test_shared_server_edge(self):
        g = build_unified_graph_from_report(_minimal_report())
        # claude-desktop and cursor both use mcp-fs
        assert g.has_edge("agent:claude-desktop", "agent:cursor") or g.has_edge("agent:cursor", "agent:claude-desktop")

    def test_shared_credential_edge(self):
        g = build_unified_graph_from_report(_minimal_report())
        # Both agents expose GITHUB_TOKEN
        has_share = any(e.relationship == RelationshipType.SHARES_CRED for e in g.edges)
        assert has_share

    def test_compliance_tags_on_vuln(self):
        g = build_unified_graph_from_report(_minimal_report())
        vuln = g.nodes.get("vuln:CVE-2024-1234")
        assert vuln is not None
        assert "OWASP-A06" in vuln.compliance_tags
        assert "MITRE-T1059" in vuln.compliance_tags

    def test_attack_path_traversal(self):
        g = build_unified_graph_from_report(_minimal_report())
        # agent → server → package → vuln should be traversable
        path = g.shortest_path("agent:claude-desktop", "vuln:CVE-2024-1234")
        assert path is not None
        assert path[0] == "agent:claude-desktop"
        assert path[-1] == "vuln:CVE-2024-1234"

    def test_credential_not_in_ocsf_events(self):
        g = build_unified_graph_from_report(_minimal_report())
        events = g.to_ocsf_events()
        # Only vuln should be in OCSF events, not credentials
        assert len(events) == 1
        assert events[0]["message"] == "vulnerability:CVE-2024-1234"

    def test_dimensions_populated(self):
        g = build_unified_graph_from_report(_minimal_report())
        pkg = g.nodes.get("pkg:express:npm:4.18.0")
        assert pkg is not None
        assert pkg.dimensions.ecosystem == "npm"

        agent = g.nodes.get("agent:claude-desktop")
        assert agent is not None
        assert agent.dimensions.agent_type == "claude-desktop"

    def test_scan_id_propagated(self):
        g = build_unified_graph_from_report(_minimal_report())
        assert g.scan_id == "test-full-001"

    def test_stats_complete(self):
        g = build_unified_graph_from_report(_minimal_report())
        s = g.stats()
        assert s["total_nodes"] >= 9  # 2 agents + 2 servers + 2 pkgs + 2 tools + 2 creds + 1 vuln
        assert s["total_edges"] >= 8
        assert "agent" in s["node_types"]
        assert "package" in s["node_types"]
        assert "vulnerability" in s["node_types"]


class TestCISMisconfigNodes:
    def test_cis_failures_become_misconfig_nodes(self):
        report = _minimal_report()
        report["cis_benchmark_data"] = {
            "checks": [
                {"check_id": "1.1", "title": "Ensure MFA is enabled", "status": "FAIL", "severity": "high"},
                {"check_id": "1.2", "title": "Ensure logging", "status": "PASS", "severity": "medium"},
            ]
        }
        g = build_unified_graph_from_report(report)
        misconfigs = g.nodes_by_type(EntityType.MISCONFIGURATION)
        assert len(misconfigs) == 1
        assert "MFA" in misconfigs[0].label
        assert misconfigs[0].severity == "high"
        assert misconfigs[0].category_uid == 2
        assert misconfigs[0].class_uid == 2003


class TestSASTNodes:
    def test_sast_findings_become_misconfig_nodes(self):
        report = _minimal_report()
        report["sast_data"] = {
            "findings": [
                {"rule_id": "CWE-79", "message": "XSS in template", "severity": "high", "path": "app.py", "line": 42},
            ]
        }
        g = build_unified_graph_from_report(report)
        misconfigs = g.nodes_by_type(EntityType.MISCONFIGURATION)
        assert len(misconfigs) == 1
        assert "XSS" in misconfigs[0].label


class TestModelProvenance:
    def test_model_nodes_created(self):
        report = _minimal_report()
        report["model_provenance"] = [
            {"model_name": "gpt-4", "framework": "openai", "source": "api", "verified": True},
        ]
        g = build_unified_graph_from_report(report)
        models = g.nodes_by_type(EntityType.MODEL)
        assert len(models) == 1
        assert models[0].label == "gpt-4"
