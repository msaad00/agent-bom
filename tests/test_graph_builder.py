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

    def test_cloud_origin_metadata_becomes_lineage_nodes(self):
        report = _minimal_report()
        report["agents"][0]["source"] = "gcp-cloud-run"
        report["agents"][0]["metadata"] = {
            "cloud_origin": {
                "provider": "gcp",
                "service": "cloud-run",
                "resource_type": "service",
                "resource_id": "projects/acme/locations/us-central1/services/support-agent",
                "resource_name": "support-agent",
                "location": "us-central1",
                "scope": {"project_id": "acme"},
            },
            "cloud_principal": {
                "provider": "gcp",
                "service": "cloud-run",
                "resource_type": "service",
                "principal_type": "service-account",
                "principal_id": "support-agent@acme.iam.gserviceaccount.com",
                "source_field": "template.service_account",
            },
            "cloud_state": {
                "provider": "gcp",
                "service": "cloud-run",
                "resource_type": "service",
                "lifecycle_state": "ready",
            },
        }

        g = build_unified_graph_from_report(report)

        resource_id = "cloud_resource:gcp:cloud-run:service:projects/acme/locations/us-central1/services/support-agent"
        principal_id = "service_account:gcp:support-agent@acme.iam.gserviceaccount.com"
        resource = g.nodes.get(resource_id)
        principal = g.nodes.get(principal_id)

        assert resource is not None
        assert resource.entity_type == EntityType.CLOUD_RESOURCE
        assert resource.label == "support-agent"
        assert resource.attributes["cloud_origin"]["scope"]["project_id"] == "acme"
        assert resource.attributes["cloud_state"]["lifecycle_state"] == "ready"
        assert resource.dimensions.cloud_provider == "gcp"
        assert principal is not None
        assert principal.entity_type == EntityType.SERVICE_ACCOUNT
        assert principal.attributes["principal_type"] == "service-account"
        assert g.has_edge("provider:gcp", resource_id)
        assert g.has_edge(resource_id, "agent:claude-desktop")
        assert g.has_edge(principal_id, resource_id)
        # Direct principal → agent edge (audit P0 #1): single-hop reach so
        # "which principals can touch this agent?" doesn't have to traverse
        # the cloud_resource intermediate.
        assert g.has_edge(principal_id, "agent:claude-desktop")
        principal_to_agent = next(
            (
                e
                for e in g.edges
                if e.source == principal_id and e.target == "agent:claude-desktop" and e.relationship == RelationshipType.MANAGES
            ),
            None,
        )
        assert principal_to_agent is not None
        # The `via` evidence preserves the lineage so consumers can tell the
        # principal-to-agent relationship is mediated by a cloud_resource
        # rather than direct ownership.
        assert principal_to_agent.evidence.get("via") == resource_id

    def test_no_principal_agent_edge_when_principal_metadata_absent(self):
        # If cloud_origin is present but cloud_principal is missing, only
        # the resource-side lineage is created — no service_account node,
        # and definitely no orphan principal → agent edge.
        report = _minimal_report()
        report["agents"][0]["source"] = "gcp-cloud-run"
        report["agents"][0]["metadata"] = {
            "cloud_origin": {
                "provider": "gcp",
                "service": "cloud-run",
                "resource_type": "service",
                "resource_id": "no-principal",
                "resource_name": "no-principal",
            },
        }
        g = build_unified_graph_from_report(report)
        sa_nodes = [n for n in g.nodes_by_type(EntityType.SERVICE_ACCOUNT)]
        assert sa_nodes == []
        principal_to_agent = [e for e in g.edges if e.source.startswith("service_account:") and e.target == "agent:claude-desktop"]
        assert principal_to_agent == []

    def test_gpu_container_metadata_promotes_to_cloud_resource(self):
        # gpu_infra_to_agents (src/agent_bom/cloud/gpu_infra.py) attaches a
        # cloud_origin envelope so the existing promoter creates a
        # cloud_resource:gpu:... lineage node for each container. This test
        # asserts the contract end-to-end via the report-shaped dict, which
        # is what the unified-graph builder consumes.
        report = _minimal_report()
        report["agents"][0]["source"] = "gpu_infra"
        report["agents"][0]["metadata"] = {
            "cloud_origin": {
                "provider": "gpu",
                "service": "container_runtime",
                "resource_type": "nvidia",
                "resource_id": "ctr-abc123",
                "resource_name": "training-worker",
                "scope": {
                    "image": "nvcr.io/nvidia/pytorch:23.10-py3",
                    "gpu_requested": True,
                    "cuda_version": "12.2",
                    "cudnn_version": "8.9",
                },
            },
        }

        g = build_unified_graph_from_report(report)

        resource_id = "cloud_resource:gpu:container_runtime:nvidia:ctr-abc123"
        resource = g.nodes.get(resource_id)
        assert resource is not None
        assert resource.entity_type == EntityType.CLOUD_RESOURCE
        assert resource.label == "training-worker"
        assert resource.attributes["cloud_origin"]["scope"]["cuda_version"] == "12.2"
        assert resource.dimensions.cloud_provider == "gpu"
        assert g.has_edge("provider:gpu", resource_id)
        assert g.has_edge(resource_id, "agent:claude-desktop")

    def test_k8s_gpu_cluster_promotes_with_aggregated_scope(self):
        # The aggregated k8s-gpu-cluster agent rolls multiple GPU nodes into
        # a single cloud_resource so dashboards see one cluster, not one node
        # per row. Per-node facts live in the scope envelope.
        report = _minimal_report()
        report["agents"][0]["source"] = "gpu_infra"
        report["agents"][0]["metadata"] = {
            "cloud_origin": {
                "provider": "gpu",
                "service": "kubernetes",
                "resource_type": "nvidia",
                "resource_id": "k8s-gpu-cluster",
                "resource_name": "k8s-gpu-cluster",
                "scope": {
                    "node_count": 4,
                    "gpu_capacity_total": 32,
                    "vendors": ["nvidia"],
                },
            },
        }

        g = build_unified_graph_from_report(report)

        resource_id = "cloud_resource:gpu:kubernetes:nvidia:k8s-gpu-cluster"
        resource = g.nodes.get(resource_id)
        assert resource is not None
        assert resource.attributes["cloud_origin"]["scope"]["node_count"] == 4
        assert resource.attributes["cloud_origin"]["scope"]["gpu_capacity_total"] == 32
        assert g.has_edge(resource_id, "agent:claude-desktop")

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
        pkg_id = "pkg:npm:express@4.18.0"
        vuln_id = "vuln:CVE-2024-1234"
        assert g.has_edge(pkg_id, vuln_id)

    def test_server_to_package_edge(self):
        g = build_unified_graph_from_report(_minimal_report())
        assert g.has_edge("server:claude-desktop:mcp-fs", "pkg:npm:express@4.18.0")

    def test_package_edges_include_discovery_provenance(self):
        report = _minimal_report()
        report["agents"][0]["mcp_servers"][0]["packages"][0]["purl"] = "pkg:npm/express@4.18.0"
        report["agents"][0]["mcp_servers"][0]["packages"][0]["occurrences"] = [
            {
                "layer_index": 2,
                "layer_id": "sha256:abc",
                "package_path": "app/package-lock.json",
                "source_file": "package-lock.json",
                "line": 42,
                "parser": "npm-lock",
            }
        ]
        report["agents"][0]["mcp_servers"][0]["packages"][0]["occurrence_count"] = 1
        g = build_unified_graph_from_report(report)

        edge = next(e for e in g.edges if e.source == "server:claude-desktop:mcp-fs" and e.target == "pkg:npm:express@4.18.0")
        assert edge.evidence["source"] == "mcp-scan"
        assert edge.evidence["purl"] == "pkg:npm/express@4.18.0"
        assert edge.evidence["occurrences"][0]["package_path"] == "app/package-lock.json"
        assert edge.evidence["occurrences"][0]["line"] == 42

    def test_package_node_id_uses_canonical_identity(self):
        report = _minimal_report()
        report["agents"][0]["mcp_servers"][0]["packages"][0]["name"] = "torch_audio"
        report["agents"][0]["mcp_servers"][0]["packages"][0]["ecosystem"] = "PyPI"
        report["agents"][0]["mcp_servers"][0]["packages"][0]["version"] = "1.0.0"
        report["agents"][0]["mcp_servers"][0]["packages"][0]["purl"] = "pkg:pypi/torch.audio@1.0.0"
        report["blast_radius"][0]["package_name"] = "torch-audio"
        report["blast_radius"][0]["package_version"] = "1.0.0"
        report["blast_radius"][0]["ecosystem"] = "pypi"

        g = build_unified_graph_from_report(report)

        assert "pkg:pypi:torch-audio@1.0.0" in g.nodes
        assert g.has_edge("pkg:pypi:torch-audio@1.0.0", "vuln:CVE-2024-1234")

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
        pkg = g.nodes.get("pkg:npm:express@4.18.0")
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


class TestSkillAuditNodes:
    def test_skill_audit_findings_become_misconfig_nodes_and_attach_to_inventory(self):
        report = _minimal_report()
        report["agents"][1]["mcp_servers"][0]["name"] = "mcp-git"
        report["skill_audit"] = {
            "findings": [
                {
                    "severity": "high",
                    "category": "shell_access",
                    "title": "Shell access in skill config",
                    "detail": "Skill enables shell execution.",
                    "source_file": "/home/user/.config/claude/config.json",
                },
                {
                    "severity": "medium",
                    "category": "unknown_package",
                    "title": "Unknown skill package",
                    "detail": "Package express was referenced by a skill.",
                    "package": "express",
                    "source_file": "/skills/demo.md",
                },
                {
                    "severity": "medium",
                    "category": "unverified_server",
                    "title": "Unverified MCP server",
                    "detail": "Server mcp-fs is not verified.",
                    "server": "mcp-fs",
                    "source_file": "/skills/demo.md",
                },
            ]
        }

        g = build_unified_graph_from_report(report)

        misconfigs = g.nodes_by_type(EntityType.MISCONFIGURATION)
        labels = {node.label for node in misconfigs}
        assert "Shell access in skill config" in labels
        assert "Unknown skill package" in labels
        assert "Unverified MCP server" in labels

        shell_node = g.nodes.get("misconfig:skill_audit:shell_access:1")
        pkg_node = g.nodes.get("misconfig:skill_audit:unknown_package:2")
        server_node = g.nodes.get("misconfig:skill_audit:unverified_server:3")
        assert shell_node is not None
        assert pkg_node is not None
        assert server_node is not None
        assert shell_node.data_sources == ["skill-audit"]
        assert "skill_audit:shell_access" in shell_node.compliance_tags

        assert g.has_edge("misconfig:skill_audit:shell_access:1", "agent:claude-desktop")
        assert g.has_edge("misconfig:skill_audit:unknown_package:2", "pkg:npm:express@4.18.0")
        assert g.has_edge("misconfig:skill_audit:unverified_server:3", "server:claude-desktop:mcp-fs")
        assert not g.has_edge("misconfig:skill_audit:unverified_server:3", "server:cursor:mcp-git")


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


class TestFrameworkTopology:
    def test_framework_agents_and_static_topology_edges_enter_graph(self):
        report = _minimal_report()
        report["ai_inventory"] = {
            "framework_agents": [
                {
                    "stable_id": "framework-agent:crew",
                    "name": "crew",
                    "framework": "crewai",
                    "file_path": "crew.py",
                    "line_number": 5,
                    "confidence": "high",
                    "capabilities": [],
                    "model_refs": [],
                    "credential_refs": [],
                    "dynamic_edges": False,
                    "topology_edges": [
                        {
                            "source_id": "framework-agent:crew",
                            "source_name": "crew",
                            "target_id": "framework-agent:researcher",
                            "target_name": "Researcher",
                            "relationship": "delegated_to",
                            "framework": "crewai",
                            "file_path": "crew.py",
                            "line_number": 5,
                            "confidence": "high",
                            "evidence": "Crew(agents=[...])",
                        }
                    ],
                },
                {
                    "stable_id": "framework-agent:researcher",
                    "name": "Researcher",
                    "framework": "crewai",
                    "file_path": "crew.py",
                    "line_number": 3,
                    "confidence": "high",
                    "capabilities": [],
                    "model_refs": [],
                    "credential_refs": [],
                    "dynamic_edges": False,
                    "topology_edges": [],
                },
            ]
        }

        g = build_unified_graph_from_report(report)

        assert g.nodes["framework-agent:crew"].attributes["framework"] == "crewai"
        assert g.nodes["framework-agent:researcher"].attributes["agent_type"] == "framework-agent"
        assert g.has_edge("framework-agent:crew", "framework-agent:researcher")
        edge = next(edge for edge in g.edges if edge.source == "framework-agent:crew" and edge.target == "framework-agent:researcher")
        assert edge.relationship == RelationshipType.DELEGATED_TO
        assert edge.evidence["source"] == "source-ast"


class TestCrossEnvironmentCorrelation:
    """Cross-environment correlation lands on the unified graph as edges."""

    def _report_with_local_and_bedrock(self, *, local_account: str, local_region: str, local_model: str | None) -> dict:
        env: dict[str, str] = {"AWS_ACCOUNT_ID": local_account, "AWS_REGION": local_region}
        if local_model is not None:
            env["BEDROCK_MODEL_ID"] = local_model
        return {
            "scan_id": "test-cross-env",
            "agents": [
                {
                    "name": "cursor-dev",
                    "type": "cursor",
                    "agent_type": "cursor",
                    "status": "configured",
                    "config_path": "/home/dev/.cursor/mcp.json",
                    "version": "0.42.0",
                    "metadata": {},
                    "mcp_servers": [
                        {
                            "name": "bedrock-mcp",
                            "command": "python",
                            "transport": "stdio",
                            "surface": "mcp-server",
                            "env": env,
                            "packages": [],
                            "tools": [],
                            "credential_env_vars": [],
                        }
                    ],
                },
                {
                    "name": "bedrock:prod-agent",
                    "type": "custom",
                    "agent_type": "custom",
                    "source": "aws-bedrock",
                    "status": "configured",
                    "config_path": "arn:aws:bedrock:us-east-1:111122223333:agent/AGENTID01",
                    "version": "anthropic.claude-3-5-sonnet-20241022-v2:0",
                    "metadata": {
                        "cloud_origin": {
                            "provider": "aws",
                            "service": "bedrock",
                            "resource_type": "agent",
                            "resource_id": "arn:aws:bedrock:us-east-1:111122223333:agent/AGENTID01",
                            "resource_name": "prod-agent",
                            "location": "us-east-1",
                            "scope": {"account_id": "111122223333"},
                        }
                    },
                    "mcp_servers": [],
                },
            ],
        }

    def test_full_triplet_emits_correlates_with_edge(self):
        report = self._report_with_local_and_bedrock(
            local_account="111122223333",
            local_region="us-east-1",
            local_model="anthropic.claude-3-5-sonnet-20241022-v2:0",
        )

        g = build_unified_graph_from_report(report)

        edge = next(
            (edge for edge in g.edges if edge.source == "agent:cursor-dev" and edge.target == "agent:bedrock:prod-agent"),
            None,
        )
        assert edge is not None
        assert edge.relationship == RelationshipType.CORRELATES_WITH
        assert edge.evidence["confidence"] == "high"
        assert set(edge.evidence["matched_signals"]) == {"account_id", "region", "model_id"}

    def test_partial_match_emits_possibly_correlates_with_edge(self):
        report = self._report_with_local_and_bedrock(
            local_account="999988887777",
            local_region="eu-west-1",
            local_model="anthropic.claude-3-5-sonnet-20241022-v2:0",
        )

        g = build_unified_graph_from_report(report)

        edge = next(
            (edge for edge in g.edges if edge.source == "agent:cursor-dev" and edge.target == "agent:bedrock:prod-agent"),
            None,
        )
        assert edge is not None
        assert edge.relationship == RelationshipType.POSSIBLY_CORRELATES_WITH
        assert edge.evidence["confidence"] == "low"
        assert edge.evidence["matched_signals"] == ["model_id"]

    def test_sdk_presence_alone_does_not_emit_edge(self):
        report = self._report_with_local_and_bedrock(
            local_account="111122223333",
            local_region="us-east-1",
            local_model=None,
        )
        # Strip account too — leave only AWS_PROFILE-style noise.
        report["agents"][0]["mcp_servers"][0]["env"] = {"AWS_PROFILE": "dev"}

        g = build_unified_graph_from_report(report)

        cross_edges = [
            edge for edge in g.edges if edge.relationship in (RelationshipType.CORRELATES_WITH, RelationshipType.POSSIBLY_CORRELATES_WITH)
        ]
        assert cross_edges == []
