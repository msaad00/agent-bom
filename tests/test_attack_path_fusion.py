"""End-to-end multi-hop attack-path fusion across the unified cloud graph."""

from __future__ import annotations

from agent_bom.graph.attack_path_fusion import (
    _MAX_DEPTH,
    _MAX_PATHS,
    apply_attack_path_fusion,
    compute_fused_attack_paths,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _kill_chain_graph() -> UnifiedGraph:
    """internet→vuln-workload→over-privileged-role→sensitive DATA_STORE.

    Mirrors the structure the CNAPP + effective-permissions overlays produce:
    - an internet-exposed, vulnerable workload (entry foothold)
    - a role the workload assumes (privilege escalation)
    - a HAS_PERMISSION assume_chain edge into a regulated data store
    """
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    # Internet-exposed + vulnerable entry workload.
    g.add_node(
        UnifiedNode(
            id="res:web",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="public-ec2",
            attributes={"internet_exposed": True, "toxic_exposed_vulnerable": True},
            risk_score=9.0,
        )
    )
    g.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical", risk_score=9.8))
    g.add_edge(UnifiedEdge(source="res:web", target="vuln:CVE-1", relationship=RelationshipType.VULNERABLE_TO, weight=8.0))

    # Over-privileged role the workload can assume, escalating to admin.
    g.add_node(
        UnifiedNode(
            id="role:admin",
            entity_type=EntityType.ROLE,
            label="AdminRole",
            attributes={"can_escalate_privilege": True, "escalates_to_admin": True},
        )
    )
    g.add_edge(UnifiedEdge(source="res:web", target="role:admin", relationship=RelationshipType.ASSUMES))

    # Crown jewel: a regulated (PCI) data store, reached via an assume-chain
    # effective permission.
    g.add_node(
        UnifiedNode(
            id="data_store:vault",
            entity_type=EntityType.DATA_STORE,
            label="data: cardholder-db",
            attributes={
                "data_sensitivity": "sensitive",
                "data_regulatory_frameworks": ["PCI-DSS"],
                "data_classification_tier": "restricted",
            },
        )
    )
    g.add_edge(
        UnifiedEdge(
            source="role:admin",
            target="data_store:vault",
            relationship=RelationshipType.HAS_PERMISSION,
            evidence={"access": "assume_chain"},
        )
    )
    return g


def _benign_graph() -> UnifiedGraph:
    """No internet entry and no sensitive store — no kill-chain exists."""
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="res:web", entity_type=EntityType.CLOUD_RESOURCE, label="private-ec2"))
    g.add_node(UnifiedNode(id="role:r", entity_type=EntityType.ROLE, label="ReadRole"))
    g.add_node(UnifiedNode(id="data_store:logs", entity_type=EntityType.DATA_STORE, label="data: app-logs"))
    g.add_edge(UnifiedEdge(source="res:web", target="role:r", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role:r", target="data_store:logs", relationship=RelationshipType.HAS_PERMISSION))
    return g


def test_kill_chain_produces_one_ranked_fused_path():
    g = _kill_chain_graph()
    paths = compute_fused_attack_paths(g)
    assert len(paths) == 1
    path = paths[0]
    assert path.source == "res:web"
    assert path.target == "data_store:vault"
    # Ordered end-to-end hops across all three pillars.
    assert path.hops == ["res:web", "role:admin", "data_store:vault"]
    assert path.edges == ["assumes", "has_permission"]
    # Composite risk rewards reaching regulated data + privilege escalation.
    assert path.composite_risk >= 60.0
    assert "PCI-DSS" in path.summary
    assert path.summary.startswith("Internet-exposed public-ec2")


def test_benign_graph_produces_no_fused_paths():
    assert compute_fused_attack_paths(_benign_graph()) == []


def test_no_internet_entry_yields_nothing():
    g = _kill_chain_graph()
    # Remove the only internet foothold.
    g.nodes["res:web"].attributes.pop("internet_exposed")
    assert compute_fused_attack_paths(g) == []


def test_no_sensitive_jewel_yields_nothing():
    g = _kill_chain_graph()
    g.nodes["data_store:vault"].attributes.clear()  # data store no longer sensitive
    assert compute_fused_attack_paths(g) == []


def test_reaching_sensitive_data_scores_above_non_sensitive():
    """A chain to regulated data must outrank an identical chain to plain data."""
    g = _kill_chain_graph()
    high = compute_fused_attack_paths(g)[0].composite_risk
    g.nodes["data_store:vault"].attributes.clear()
    g.nodes["data_store:vault"].attributes["data_sensitivity"] = "sensitive"
    low = compute_fused_attack_paths(g)[0].composite_risk
    assert high > low


def test_depth_cap_is_respected():
    """A chain longer than _MAX_DEPTH hops must not be returned."""
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="n0", entity_type=EntityType.CLOUD_RESOURCE, label="entry", attributes={"internet_exposed": True}))
    # Build a linear CAN_ACCESS chain longer than the depth cap.
    chain_len = _MAX_DEPTH + 3
    prev = "n0"
    for i in range(1, chain_len):
        nid = f"n{i}"
        g.add_node(UnifiedNode(id=nid, entity_type=EntityType.RESOURCE, label=f"r{i}"))
        g.add_edge(UnifiedEdge(source=prev, target=nid, relationship=RelationshipType.CAN_ACCESS))
        prev = nid
    # Crown jewel sits just past the depth budget.
    g.add_node(
        UnifiedNode(
            id="data_store:far",
            entity_type=EntityType.DATA_STORE,
            label="data: far",
            attributes={"data_sensitivity": "sensitive"},
        )
    )
    g.add_edge(UnifiedEdge(source=prev, target="data_store:far", relationship=RelationshipType.STORES))
    assert compute_fused_attack_paths(g) == []


def test_within_depth_cap_is_returned():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="n0", entity_type=EntityType.CLOUD_RESOURCE, label="entry", attributes={"internet_exposed": True}))
    g.add_node(UnifiedNode(id="n1", entity_type=EntityType.RESOURCE, label="r1"))
    g.add_edge(UnifiedEdge(source="n0", target="n1", relationship=RelationshipType.CAN_ACCESS))
    g.add_node(
        UnifiedNode(
            id="data_store:near",
            entity_type=EntityType.DATA_STORE,
            label="data: near",
            attributes={"data_sensitivity": "sensitive"},
        )
    )
    g.add_edge(UnifiedEdge(source="n1", target="data_store:near", relationship=RelationshipType.STORES))
    paths = compute_fused_attack_paths(g)
    assert len(paths) == 1
    assert paths[0].target == "data_store:near"


def test_node_budget_skips_oversized_graph():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="entry", entity_type=EntityType.CLOUD_RESOURCE, label="e", attributes={"internet_exposed": True}))
    g.add_node(UnifiedNode(id="data_store:x", entity_type=EntityType.DATA_STORE, label="d", attributes={"data_sensitivity": "sensitive"}))
    g.add_edge(UnifiedEdge(source="entry", target="data_store:x", relationship=RelationshipType.STORES))
    # Pad past the global node budget with isolated nodes.
    for i in range(5001):
        g.add_node(UnifiedNode(id=f"pad{i}", entity_type=EntityType.PACKAGE, label=f"p{i}"))
    assert compute_fused_attack_paths(g) == []


def test_returned_path_count_is_capped():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    # Many independent entry→jewel pairs, more than the cap.
    for i in range(_MAX_PATHS + 20):
        eid = f"entry{i}"
        did = f"data_store:{i}"
        g.add_node(UnifiedNode(id=eid, entity_type=EntityType.CLOUD_RESOURCE, label=f"e{i}", attributes={"internet_exposed": True}))
        g.add_node(UnifiedNode(id=did, entity_type=EntityType.DATA_STORE, label=f"d{i}", attributes={"data_sensitivity": "sensitive"}))
        g.add_edge(UnifiedEdge(source=eid, target=did, relationship=RelationshipType.STORES))
    paths = compute_fused_attack_paths(g)
    assert len(paths) == _MAX_PATHS


def test_apply_materialises_and_is_idempotent():
    g = _kill_chain_graph()
    stats = apply_attack_path_fusion(g)
    assert stats["fused_attack_paths"] == 1
    assert stats["max_fused_risk"] >= 60
    assert len(g.attack_paths) == 1
    # Re-running must not duplicate fusion paths.
    apply_attack_path_fusion(g)
    assert len([p for p in g.attack_paths if p.summary.startswith("Internet-exposed ")]) == 1


def test_apply_preserves_foreign_attack_paths():
    from agent_bom.graph.container import AttackPath

    g = _kill_chain_graph()
    foreign = AttackPath(source="a", target="b", hops=["a", "b"], summary="lateral movement chain")
    g.attack_paths.append(foreign)
    apply_attack_path_fusion(g)
    assert foreign in g.attack_paths
    assert any(p.summary.startswith("Internet-exposed ") for p in g.attack_paths)
