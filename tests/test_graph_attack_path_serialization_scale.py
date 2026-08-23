"""Attack-path serialization must index topology once per response page."""

from __future__ import annotations

from agent_bom.api.routes import graph as graph_routes
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedNode


def test_attack_path_page_builds_one_edge_lookup(monkeypatch) -> None:
    edges = [
        UnifiedEdge(source=f"noise:{index}", target=f"noise:{index + 1}", relationship=RelationshipType.USES) for index in range(1_000)
    ]
    edges.extend(
        [
            UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES),
            UnifiedEdge(source="server:s", target="vuln:v", relationship=RelationshipType.VULNERABLE_TO),
        ]
    )
    paths = [
        AttackPath(
            source="agent:a",
            target="vuln:v",
            hops=["agent:a", "server:s", "vuln:v"],
            composite_risk=90.0 - index / 100,
        )
        for index in range(100)
    ]
    nodes = {
        "agent:a": UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="Agent A"),
        "server:s": UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="Server S"),
        "vuln:v": UnifiedNode(id="vuln:v", entity_type=EntityType.VULNERABILITY, label="CVE-2026-1"),
    }

    calls = 0
    real_builder = graph_routes._build_edge_lookup

    def recording_builder(topology):
        nonlocal calls
        calls += 1
        return real_builder(topology)

    monkeypatch.setattr(graph_routes, "_build_edge_lookup", recording_builder)
    serialized = graph_routes._serialize_attack_path_batch(
        paths,
        edges,
        nodes_by_id=nodes,
        scan_id="scan-1",
    )

    assert calls == 1
    assert len(serialized) == 100
    assert serialized[0]["edges"] == ["uses", "vulnerable_to"]
    assert [item["relationship"] for item in serialized[0]["exposure_path"]["relationships"]] == [
        "uses",
        "vulnerable_to",
    ]
