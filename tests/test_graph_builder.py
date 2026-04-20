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

    def test_provider_nodes_and_hosts_edges(self):
        g = build_unified_graph_from_report(_minimal_report())
        providers = g.nodes_by_type(EntityType.PROVIDER)
        assert len(providers) == 1
        assert providers[0].label == "local"
        assert g.has_edge("provider:local", "agent:claude-desktop")

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

    def test_blast_radius_does_not_cross_product_same_named_servers(self):
        g = build_unified_graph_from_report(_minimal_report())
        vuln_id = "vuln:CVE-2024-1234"
        assert g.has_edge("server:claude-desktop:mcp-fs", vuln_id)
        assert not g.has_edge("server:cursor:mcp-fs", vuln_id)

    def test_blast_radius_accepts_object_shaped_affected_servers(self):
        report = _minimal_report()
        report["blast_radius"][0]["affected_servers"] = [{"name": "mcp-fs"}]
        g = build_unified_graph_from_report(report)
        assert g.has_edge("server:claude-desktop:mcp-fs", "vuln:CVE-2024-1234")

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
        report["cis_benchmark"] = {
            "checks": [
                {
                    "check_id": "1.1",
                    "title": "Ensure MFA is enabled",
                    "status": "FAIL",
                    "severity": "high",
                    "resource_ids": ["bucket/prod-secrets"],
                },
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
        resources = g.nodes_by_type(EntityType.CLOUD_RESOURCE)
        assert len(resources) == 1
        assert resources[0].label == "bucket/prod-secrets"
        assert g.has_edge("misconfig:cis_benchmark:1.1", "cloud_resource:generic:bucket/prod-secrets")


class TestSASTNodes:
    def test_sast_findings_become_misconfig_nodes(self):
        report = _minimal_report()
        report["sast"] = {
            "findings": [
                {
                    "rule_id": "CWE-79",
                    "message": "XSS in template",
                    "severity": "high",
                    "file_path": "app.py",
                    "start_line": 42,
                    "end_line": 42,
                    "cwe_ids": ["CWE-79"],
                    "owasp_ids": ["A03:2021"],
                    "rule_url": "https://semgrep.dev/r/cwe-79",
                },
            ]
        }
        g = build_unified_graph_from_report(report)
        misconfigs = g.nodes_by_type(EntityType.MISCONFIGURATION)
        assert len(misconfigs) == 1
        assert "XSS" in misconfigs[0].label
        assert misconfigs[0].attributes["file_path"] == "app.py"
        assert misconfigs[0].attributes["start_line"] == 42
        assert "CWE-79" in misconfigs[0].compliance_tags
        assert "A03:2021" in misconfigs[0].compliance_tags


class TestIaCNodes:
    def test_iac_findings_become_misconfig_nodes_and_target_anchors(self):
        report = _minimal_report()
        report["iac_findings"] = {
            "findings": [
                {
                    "rule_id": "K8S-007",
                    "title": "Secrets in plain env values",
                    "message": "Container sets a plaintext secret in env.",
                    "severity": "high",
                    "file_path": "deploy/k8s/api.yaml",
                    "line_number": 27,
                    "category": "kubernetes",
                    "compliance": ["CIS-5.4.1"],
                    "attack_techniques": ["T1552.001"],
                    "remediation": "Use Secret refs instead of plaintext values.",
                }
            ]
        }

        g = build_unified_graph_from_report(report)

        misconfigs = g.nodes_by_type(EntityType.MISCONFIGURATION)
        assert len(misconfigs) == 1
        assert misconfigs[0].label == "Secrets in plain env values"
        assert misconfigs[0].attributes["file_path"] == "deploy/k8s/api.yaml"
        assert misconfigs[0].attributes["category"] == "kubernetes"
        assert misconfigs[0].attributes["remediation"] == "Use Secret refs instead of plaintext values."
        assert "CIS-5.4.1" in misconfigs[0].compliance_tags
        assert "T1552.001" in misconfigs[0].compliance_tags

        anchors = g.nodes_by_type(EntityType.CLOUD_RESOURCE)
        assert any(anchor.label == "deploy/k8s/api.yaml" for anchor in anchors)
        anchor = next(anchor for anchor in anchors if anchor.label == "deploy/k8s/api.yaml")
        assert anchor.attributes["target_type"] == "iac_file"
        assert g.has_edge("misconfig:iac:K8S-007:deploy/k8s/api.yaml:27", "iac_target:kubernetes:deploy/k8s/api.yaml")


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

    def test_dataset_and_container_nodes_created(self):
        report = _minimal_report()
        report["model_provenance"] = [
            {"model_name": "gpt-4", "framework": "openai", "source": "api", "verified": True},
        ]
        report["dataset_cards"] = {
            "datasets": [
                {
                    "name": "hf/acme-support",
                    "license": "apache-2.0",
                    "source_file": "datasets/support/README.md",
                    "compliance_tags": {"nist": ["NIST-AI-RMF-MAP-1.1"]},
                }
            ]
        }
        report["serving_configs"] = [
            {
                "name": "support-api",
                "framework": "mlflow",
                "container_image": "ghcr.io/acme/support-api:1.2.3",
                "model_uri": "models:/gpt-4/Production",
                "endpoint_url": "https://support.example/api",
            }
        ]
        report["toxic_combinations"] = [{"name": "rce_chain", "vulnerability_ids": ["CVE-2024-1234"], "risk_score": 9.5}]

        g = build_unified_graph_from_report(report)

        datasets = g.nodes_by_type(EntityType.DATASET)
        containers = g.nodes_by_type(EntityType.CONTAINER)
        assert len(datasets) == 1
        assert datasets[0].label == "hf/acme-support"
        assert "NIST-AI-RMF-MAP-1.1" in datasets[0].compliance_tags
        assert len(containers) == 1
        assert containers[0].attributes["container_image"] == "ghcr.io/acme/support-api:1.2.3"
        assert g.has_edge("container:ghcr.io/acme/support-api:1.2.3", "model:gpt-4")
        assert "toxic:rce_chain" in g.nodes
        assert g.has_edge("vuln:CVE-2024-1234", "toxic:rce_chain")
