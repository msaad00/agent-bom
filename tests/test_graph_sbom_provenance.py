"""Imported package inventory does not establish runtime agent topology."""

from agent_bom.graph import EntityType, RelationshipType
from agent_bom.graph.builder import build_unified_graph_from_report


def _report():
    return {
        "scan_id": "sbom-provenance",
        "agents": [
            {
                "name": "sbom:inventory.cdx.json",
                "type": "custom",
                "source": "sbom",
                "config_path": "inventory.cdx.json",
                "mcp_servers": [
                    {
                        "name": "inventory",
                        "surface": "sbom",
                        "packages": [
                            {
                                "name": "pillow",
                                "version": "9.0.0",
                                "ecosystem": "pypi",
                                "vulnerabilities": [{"id": "CVE-2023-4863", "severity": "high"}],
                            }
                        ],
                    }
                ],
            }
        ],
        "findings": [{"id": "cve-in-pillow", "source": "SBOM", "severity": "high", "asset": {"name": "pillow", "asset_type": "package"}}],
    }


def test_sbom_inventory_is_one_source_artifact_not_runtime_topology():
    graph = build_unified_graph_from_report(_report())
    types = [n.entity_type for n in graph.nodes.values()]
    assert EntityType.AGENT not in types
    assert EntityType.SERVER not in types
    assert EntityType.APPLICATION not in types
    assert EntityType.CODE_MODULE not in types
    assert EntityType.PROVIDER not in types
    assert all(n.data_sources == ["sbom"] for n in graph.nodes.values())
    artifacts = [n for n in graph.nodes.values() if n.entity_type == EntityType.SOURCE_FILE]
    assert len(artifacts) == 1
    assert artifacts[0].dimensions.surface == "sbom"
    assert any(n.entity_type == EntityType.PACKAGE for n in graph.nodes.values())
    assert any(n.entity_type == EntityType.VULNERABILITY for n in graph.nodes.values())
    assert not any(e.relationship in {RelationshipType.USES, RelationshipType.SHARES_SERVER} for e in graph.edges)
    assert any(e.source == artifacts[0].id and e.target.startswith("pkg:") for e in graph.edges)


def test_legacy_sbom_import_without_source_keeps_artifact_semantics():
    report = _report()
    report["agents"][0].pop("source")
    graph = build_unified_graph_from_report(report)
    assert not any(n.entity_type in {EntityType.AGENT, EntityType.SERVER} for n in graph.nodes.values())


def test_real_mcp_agent_named_like_sbom_is_preserved():
    report = _report()
    report["agents"][0]["source"] = "local"
    report["agents"][0]["mcp_servers"][0]["surface"] = "mcp-server"
    graph = build_unified_graph_from_report(report)
    assert any(n.entity_type == EntityType.AGENT for n in graph.nodes.values())
    assert any(n.entity_type == EntityType.SERVER for n in graph.nodes.values())
    assert any(e.relationship == RelationshipType.USES for e in graph.edges)


def test_sbom_does_not_claim_tools_or_credentials_from_inventory_wrapper():
    report = _report()
    server = report["agents"][0]["mcp_servers"][0]
    server["tools"] = [{"name": "run_shell"}]
    server["credential_env_vars"] = ["API_TOKEN"]
    graph = build_unified_graph_from_report(report)
    assert not any(n.entity_type in {EntityType.TOOL, EntityType.CREDENTIAL} for n in graph.nodes.values())
    assert not any(e.relationship == RelationshipType.EXPLOITABLE_VIA for e in graph.edges)


def test_mixed_sbom_and_mcp_inventory_does_not_create_shared_server_edge():
    import copy

    report = _report()
    runtime = copy.deepcopy(report["agents"][0])
    runtime.update(name="assistant", source="local", type="custom")
    runtime["mcp_servers"][0]["surface"] = "mcp-server"
    report["agents"].append(runtime)
    graph = build_unified_graph_from_report(report)
    assert sum(n.entity_type == EntityType.AGENT for n in graph.nodes.values()) == 1
    assert sum(n.entity_type == EntityType.SERVER for n in graph.nodes.values()) == 1
    assert not any(e.relationship == RelationshipType.SHARES_SERVER for e in graph.edges)
    assert sum(n.entity_type == EntityType.PACKAGE for n in graph.nodes.values()) == 1


def test_sbom_graph_persistence_preserves_artifact_type_and_tenant(tmp_path):
    from agent_bom.db import graph_store

    graph = build_unified_graph_from_report(_report(), tenant_id="sbom-tenant")
    database = tmp_path / "graph.db"
    with graph_store.open_graph_db(database) as conn:
        graph_store.save_graph(conn, graph)
    with graph_store.open_graph_db(database) as conn:
        restored = graph_store.load_graph(conn, scan_id=graph.scan_id, tenant_id="sbom-tenant")
        other = graph_store.load_graph(conn, scan_id=graph.scan_id, tenant_id="other-tenant")
    assert restored is not None
    assert not any(n.entity_type in {EntityType.AGENT, EntityType.SERVER, EntityType.APPLICATION} for n in restored.nodes.values())
    assert len(restored.nodes) == len(graph.nodes)
    assert len(restored.edges) == len(graph.edges)
    assert other is None or not other.nodes


def test_same_label_runtime_and_sbom_keep_distinct_identities_in_both_orders():
    import copy

    report = _report()
    artifact = report["agents"][0]
    runtime = copy.deepcopy(artifact)
    runtime["source"] = "local"
    runtime["mcp_servers"][0]["surface"] = "mcp-server"
    runtime["mcp_servers"][0]["tools"] = [{"name": "read_file"}]
    identities = []
    for entries in ([artifact, runtime], [runtime, artifact]):
        report["agents"] = entries
        graph = build_unified_graph_from_report(report)
        sources = [n for n in graph.nodes.values() if n.entity_type == EntityType.SOURCE_FILE]
        agents = [n for n in graph.nodes.values() if n.entity_type == EntityType.AGENT]
        assert len(sources) == len(agents) == 1
        assert sources[0].id != agents[0].id
        assert not any(e.source == sources[0].id and e.relationship == RelationshipType.USES for e in graph.edges)
        assert any(e.source == agents[0].id and e.relationship == RelationshipType.USES for e in graph.edges)
        identities.append({n.id: n.entity_type for n in graph.nodes.values()})
    assert identities[0] == identities[1]
