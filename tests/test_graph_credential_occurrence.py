"""Credential slots must follow their owning server occurrence during correlation."""

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedGraph, UnifiedNode
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.correlation import CorrelationSnapshot, merge_graph_snapshots
from agent_bom.graph.correlation_scope import merged_identity_version
from agent_bom.graph.correlation_workspace import CorrelationMergeWorkspace
from agent_bom.graph.credential_projection import project_credentials


@pytest.fixture(params=[False, True], ids=["memory", "disk"])
def merge(request):
    def run(graphs):
        snapshots = [CorrelationSnapshot.from_graph(graph) for graph in graphs]
        if not request.param:
            return merge_graph_snapshots(correlation_id="corr", tenant_id="tenant", snapshots=snapshots).graph
        with CorrelationMergeWorkspace(
            correlation_id="corr", tenant_id="tenant", created_at="2026-10-02T01:00:00Z", max_output_nodes=100, max_output_edges=100
        ) as workspace:
            for snapshot in snapshots:
                workspace.add_snapshot(snapshot)
            return workspace.finish().graph

    return run


def report_graph(scan, environment, role):
    graph = build_unified_graph_from_report(
        {
            "agents": [
                {
                    "name": "assistant",
                    "type": "claude-desktop",
                    "environment": environment,
                    "mcp_servers": [
                        {
                            "name": "aws-tools",
                            "command": "aws-mcp",
                            "packages": [],
                            "credential_env_vars": ["AWS_ACCESS_KEY_ID"],
                            "identity_bindings": [
                                {
                                    "credential_ref": "AWS_ACCESS_KEY_ID",
                                    "identity_canonical_id": f"identity:{role}",
                                    "provider": "aws",
                                    "evidence_source": "synthetic-verified-binding",
                                }
                            ],
                        }
                    ],
                }
            ]
        },
        scan_id=scan,
        tenant_id="tenant",
    )
    graph.created_at = "2026-10-02T00:00:00Z"
    return graph


def nodes_of(graph, kind):
    return [node for node in graph.nodes.values() if node.entity_type == kind]


@pytest.mark.parametrize("legacy_raw", [False, True])
def test_report_credential_slots_cannot_bridge_dev_and_prod(merge, legacy_raw):
    graphs = [report_graph("dev", "dev", "dev-role"), report_graph("prod", "prod", "prod-role")]
    if legacy_raw:
        for graph in graphs:
            for node in nodes_of(graph, EntityType.CREDENTIAL):
                node.attributes.pop("credential_occurrence", None)
    result = merge(graphs)
    assert len(nodes_of(result, EntityType.CREDENTIAL)) == 2
    for server in nodes_of(result, EntityType.SERVER):
        slots = {e.target for e in result.edges if e.source == server.id and e.relationship == RelationshipType.EXPOSES_CRED}
        targets = {e.target for e in result.edges if e.source in slots and e.relationship == RelationshipType.AUTHENTICATES_AS}
        assert targets == {f"identity:{server.attributes['environment']}-role"}


@pytest.mark.parametrize("legacy_raw", [False, True])
def test_repeated_observation_of_same_server_slot_still_joins(merge, legacy_raw):
    graphs = [report_graph("first", "prod", "prod-role"), report_graph("second", "prod", "prod-role")]
    if legacy_raw:
        for graph in graphs:
            for node in nodes_of(graph, EntityType.CREDENTIAL):
                node.attributes.pop("credential_occurrence", None)
    result = merge(graphs)
    slots = nodes_of(result, EntityType.CREDENTIAL)
    assert len(slots) == 1
    assert slots[0].attributes["correlation"]["source_scan_ids"] == ["first", "second"]


@pytest.mark.parametrize("boundary", ["runtime_host_id", "cluster_id", "environment", "cloud_provider", "account_id"])
def test_slot_inherits_supported_server_occurrence_boundaries(merge, boundary):
    graphs = []
    for value in ["one", "two"]:
        graph = UnifiedGraph(scan_id=value, tenant_id="tenant", created_at="2026-10-02T00:00:00Z")
        graph.add_node(
            UnifiedNode(id="server", entity_type=EntityType.SERVER, label="tools", attributes={"runtime_id": "local", boundary: value})
        )
        project_credentials(graph, {"credential_env_vars": ["API_KEY"]}, "server", [], "fixture")
        graphs.append(graph)
    assert len(nodes_of(merge(graphs), EntityType.CREDENTIAL)) == 2


def test_legacy_slot_without_owning_server_cannot_join_across_snapshots(merge):
    graphs = []
    for scan in ["one", "two"]:
        graph = report_graph(scan, "prod", "prod-role")
        credential = nodes_of(graph, EntityType.CREDENTIAL)[0]
        credential.attributes.pop("credential_occurrence", None)
        graph.nodes = {credential.id: credential}
        graph.edges = []
        graphs.append(graph)
    assert len(nodes_of(merge(graphs), EntityType.CREDENTIAL)) == 2


def test_old_merged_slot_is_not_repaired_by_recorrelation(merge):
    graphs = [report_graph("one", "prod", "prod-role"), report_graph("two", "prod", "prod-role")]
    for graph in graphs:
        for node in nodes_of(graph, EntityType.CREDENTIAL):
            node.attributes["correlation"] = {"identity_version": "scoped-identity.v3", "source_scan_ids": ["dev", "prod"]}
    result = merge(graphs)
    slots = nodes_of(result, EntityType.CREDENTIAL)
    assert len(slots) == 2
    assert all(slot.attributes["correlation"]["identity_version"] == "legacy" for slot in slots)


def test_previous_identity_receipts_require_recomputation():
    assert merged_identity_version([{"identity_version": "scoped-identity.v3"}]) == "legacy"


def test_independent_canonical_credential_identity_keeps_existing_join(merge):
    graphs = []
    for scan in ["one", "two"]:
        graph = UnifiedGraph(scan_id=scan, tenant_id="tenant", created_at="2026-10-02T00:00:00Z")
        graph.add_node(
            UnifiedNode(
                id="secret",
                entity_type=EntityType.CREDENTIAL,
                label="secret reference",
                attributes={
                    "canonical_id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-reference",
                },
            )
        )
        graphs.append(graph)
    assert len(nodes_of(merge(graphs), EntityType.CREDENTIAL)) == 1


def test_current_slot_receipt_survives_repeated_correlation(merge):
    first = merge([report_graph("dev-one", "dev", "dev-role"), report_graph("prod-one", "prod", "prod-role")])
    second = merge([report_graph("dev-two", "dev", "dev-role"), report_graph("prod-two", "prod", "prod-role")])
    first.scan_id, second.scan_id = "first-correlation", "second-correlation"
    result = merge([first, second])
    assert len(nodes_of(result, EntityType.CREDENTIAL)) == 2
    for server in nodes_of(result, EntityType.SERVER):
        slots = {e.target for e in result.edges if e.source == server.id and e.relationship == RelationshipType.EXPOSES_CRED}
        targets = {e.target for e in result.edges if e.source in slots and e.relationship == RelationshipType.AUTHENTICATES_AS}
        assert targets == {f"identity:{server.attributes['environment']}-role"}


@pytest.mark.parametrize("conflict", ["parents", "slot", "server_identity"])
def test_conflicting_slot_ownership_is_not_an_exact_join(merge, conflict):
    graphs = [report_graph("one", "prod", "prod-role"), report_graph("two", "prod", "prod-role")]
    for graph in graphs:
        slot = nodes_of(graph, EntityType.CREDENTIAL)[0]
        if conflict == "parents":
            slot.attributes["servers"].append("different-server")
        elif conflict == "slot":
            slot.attributes["credential_occurrence"]["name"] = "DIFFERENT_KEY"
        else:
            slot.attributes["credential_occurrence"]["server_identity"][1] = "different-identity"
    assert len(nodes_of(merge(graphs), EntityType.CREDENTIAL)) == 2


def test_persisted_slot_scope_keeps_the_same_investigation_result(merge, tmp_path):
    from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph

    with open_graph_db(tmp_path / "graph.db") as conn:
        for environment in ["dev", "prod"]:
            save_graph(conn, report_graph(environment, environment, f"{environment}-role"))
        graphs = [load_graph(conn, tenant_id="tenant", scan_id=environment) for environment in ["dev", "prod"]]
    result = merge(graphs)
    assert len(nodes_of(result, EntityType.CREDENTIAL)) == 2
    assert all(node.attributes["credential_occurrence"]["name"] == "AWS_ACCESS_KEY_ID" for node in nodes_of(result, EntityType.CREDENTIAL))
