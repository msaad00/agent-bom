"""Persisted enterprise-style paths retain exact recorded relationship direction.

Synthetic tenants and identities use real SQLite persistence, auth middleware,
and graph HTTP routes. These cases do not claim live cloud authorization.
"""

import pytest

from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401


@pytest.mark.parametrize("direction", ["bidirectional", "directed"])
def test_shared_mcp_path_preserves_reverse_relationship_without_inventing_directed_access(api, direction):  # noqa: F811
    client, store, headers = api
    graph = UnifiedGraph(tenant_id="tenant-a", scan_id="shared-scan", created_at="2026-09-30T00:00:00Z")
    for key in ("agent:a", "agent:b"):
        graph.add_node(UnifiedNode(id=key, entity_type=EntityType.AGENT, label=key))
    graph.add_node(
        UnifiedNode(id="finding:package", entity_type=EntityType.VULNERABILITY, label="Modeled package finding", severity="high")
    )
    shared = UnifiedEdge(source="agent:a", target="agent:b", relationship=RelationshipType.SHARES_SERVER, direction=direction)
    finding = UnifiedEdge(source="agent:a", target="finding:package", relationship=RelationshipType.VULNERABLE_TO)
    unrelated = UnifiedEdge(source="agent:b", target="finding:package", relationship=RelationshipType.USES)
    for edge in (shared, finding, unrelated):
        graph.add_edge(edge)
    graph.attack_paths = [
        AttackPath(
            source="agent:b",
            target="finding:package",
            hops=["agent:b", "agent:a", "finding:package"],
            edges=["shares_server", "vulnerable_to"],
            composite_risk=75,
        )
    ]
    store.save_graph(graph)
    response = client.get("/v1/graph/attack-paths", params={"scan_id": "shared-scan"}, headers=headers["tenant-a"])
    assert response.status_code == 200
    payload = response.json()
    ids = {item["id"] for item in payload["edges"]}
    assert finding.id in ids
    assert unrelated.id not in ids
    assert (shared.id in ids) is (direction == "bidirectional")
    projected = payload["attack_paths"][0]["exposure_path"]
    assert projected["reachability"] != "confirmed"  # inventory is not observed successful access
    assert payload["attack_paths"][0]["severity"] == "high"
    other = client.get("/v1/graph/attack-paths", params={"scan_id": "shared-scan"}, headers=headers["tenant-b"])
    assert other.status_code == 200
    assert "Modeled package finding" not in other.text
    assert client.get("/v1/graph/attack-paths", params={"scan_id": "shared-scan"}).status_code == 401
