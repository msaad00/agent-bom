"""Typed MITRE ATT&CK / ATLAS technique enrichment for attack paths (#4108).

Mappings are derived from OBSERVED GRAPH EVIDENCE (edge relationship type +
target node entity type + edge evidence) — never by parsing the human-readable
summary/edge-label text — and every technique/tactic ID resolves against the
bundled catalog. Hops without mappable evidence stay unmapped (fail-closed).
These are *potential/mapped* techniques for the kill-chain sequence, never a
claim of detected attacker activity.
"""

from __future__ import annotations

from agent_bom.atlas import ATLAS_TECHNIQUES
from agent_bom.db import graph_store as gs
from agent_bom.graph.attack_path_fusion import apply_attack_path_fusion, compute_fused_attack_paths
from agent_bom.graph.attack_path_mitre import (
    apply_attack_path_technique_mappings,
    derive_attack_path_techniques,
)
from agent_bom.graph.container import AttackPath, TechniqueMapping, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.mitre_attack import get_attack_techniques


def _kill_chain_graph(tenant_id: str = "t", scan_id: str = "s") -> UnifiedGraph:
    """internet→vuln workload→ASSUMES role→HAS_PERMISSION(assume_chain)→data store."""
    g = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
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
    g.add_node(
        UnifiedNode(
            id="role:admin",
            entity_type=EntityType.ROLE,
            label="AdminRole",
            attributes={"can_escalate_privilege": True, "escalates_to_admin": True},
        )
    )
    g.add_edge(UnifiedEdge(source="res:web", target="role:admin", relationship=RelationshipType.ASSUMES))
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


def _catalog_ids() -> set[str]:
    return set(get_attack_techniques()) | set(ATLAS_TECHNIQUES)


# ── Derivation from observed evidence ────────────────────────────────────────


def test_multihop_evidence_maps_to_catalog_techniques_ordered():
    g = _kill_chain_graph()
    path = compute_fused_attack_paths(g)[0]
    assert path.hops == ["res:web", "role:admin", "data_store:vault"]

    mappings = derive_attack_path_techniques(path, g)

    # One mapping per hop that carried mappable evidence, ordered by kill-chain.
    assert [m.hop_index for m in mappings] == [0, 1]
    # hop 0: ASSUMES into a role → Valid Accounts (privilege escalation).
    assert mappings[0].technique_id == "T1078"
    assert mappings[0].catalog == "attack"
    assert "privilege-escalation" in mappings[0].tactics
    # hop 1: effective permission reaching a crown-jewel data store → collection.
    assert mappings[1].technique_id == "T1530"
    assert "collection" in mappings[1].tactics

    catalog = _catalog_ids()
    for m in mappings:
        assert m.technique_id in catalog, f"dangling technique {m.technique_id}"
        assert 0.0 < m.confidence <= 1.0
        assert m.tactics  # resolved from catalog, never empty
        # Provenance is derived from the observed graph edge, not the summary text.
        assert path.summary not in m.provenance
        assert m.provenance  # non-empty evidence description


def test_vulnerable_edge_from_internet_entry_maps_to_exploit_public_facing():
    g = _kill_chain_graph()
    # Direct exploit hop off the internet-exposed entry.
    path = AttackPath(source="res:web", target="vuln:CVE-1", hops=["res:web", "vuln:CVE-1"], edges=["vulnerable_to"])
    mappings = derive_attack_path_techniques(path, g)
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1190"  # Exploit Public-Facing Application
    assert "initial-access" in mappings[0].tactics


def test_tool_reach_maps_to_atlas_and_resolves():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.CLOUD_RESOURCE, label="agent", attributes={"internet_exposed": True}))
    g.add_node(UnifiedNode(id="tool:shell", entity_type=EntityType.TOOL, label="shell-tool"))
    g.add_edge(UnifiedEdge(source="agent:a", target="tool:shell", relationship=RelationshipType.REACHES_TOOL))
    path = AttackPath(source="agent:a", target="tool:shell", hops=["agent:a", "tool:shell"], edges=["reaches_tool"])

    mappings = derive_attack_path_techniques(path, g)

    assert len(mappings) == 1
    assert mappings[0].catalog == "atlas"
    assert mappings[0].technique_id in ATLAS_TECHNIQUES
    assert mappings[0].tactics  # ATLAS tactic IDs resolved from the upstream catalog


def test_hop_without_mappable_evidence_left_unmapped():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="app:x", entity_type=EntityType.CLOUD_RESOURCE, label="app"))
    g.add_node(UnifiedNode(id="lib:y", entity_type=EntityType.PACKAGE, label="libc"))
    g.add_edge(UnifiedEdge(source="app:x", target="lib:y", relationship=RelationshipType.USES))
    path = AttackPath(source="app:x", target="lib:y", hops=["app:x", "lib:y"], edges=["uses"])

    mappings = derive_attack_path_techniques(path, g)

    # No evidence maps to a technique → fail closed, no fabricated mapping.
    assert mappings == []


def test_mappings_never_claim_detected_activity():
    g = _kill_chain_graph()
    path = compute_fused_attack_paths(g)[0]
    mappings = derive_attack_path_techniques(path, g)
    joined = " ".join(m.provenance.lower() for m in mappings)
    assert "detected" not in joined
    assert "observed activity" not in joined


# ── Serialization round-trips ────────────────────────────────────────────────


def test_to_dict_from_dict_roundtrip_preserves_typed_fields():
    g = _kill_chain_graph()
    apply_attack_path_fusion(g)
    apply_attack_path_technique_mappings(g)
    path = g.attack_paths[0]
    assert path.technique_mappings

    d = path.to_dict()
    assert "technique_mappings" in d
    # Convenience deduped id list for exports/UI.
    assert d["mitre_technique_ids"] == sorted({m.technique_id for m in path.technique_mappings})

    restored = AttackPath.from_dict(d)
    assert restored.technique_mappings == path.technique_mappings


def test_sqlite_roundtrip_preserves_technique_mappings(tmp_path):
    g = _kill_chain_graph(tenant_id="acme", scan_id="s1")
    apply_attack_path_fusion(g)
    apply_attack_path_technique_mappings(g)
    expected = g.attack_paths[0].technique_mappings
    assert expected

    db = tmp_path / "graph.db"
    with gs.open_graph_db(db) as conn:
        gs.save_graph(conn, g)
    with gs.open_graph_db(db) as conn:
        loaded = gs.load_graph(conn, tenant_id="acme", scan_id="s1")

    assert len(loaded.attack_paths) == 1
    assert loaded.attack_paths[0].technique_mappings == expected


def test_tenant_isolation_technique_mappings_do_not_leak(tmp_path):
    g_a = _kill_chain_graph(tenant_id="tenant-a", scan_id="shared-scan")
    apply_attack_path_fusion(g_a)
    apply_attack_path_technique_mappings(g_a)
    a_ids = {m.technique_id for p in g_a.attack_paths for m in p.technique_mappings}
    assert a_ids

    # Tenant B: same scan id, a benign path with no mappable evidence.
    g_b = UnifiedGraph(scan_id="shared-scan", tenant_id="tenant-b")
    g_b.add_node(UnifiedNode(id="app:x", entity_type=EntityType.CLOUD_RESOURCE, label="app"))
    g_b.add_node(UnifiedNode(id="lib:y", entity_type=EntityType.PACKAGE, label="libc"))
    g_b.add_edge(UnifiedEdge(source="app:x", target="lib:y", relationship=RelationshipType.USES))
    g_b.attack_paths.append(AttackPath(source="app:x", target="lib:y", hops=["app:x", "lib:y"], edges=["uses"]))
    apply_attack_path_technique_mappings(g_b)

    db = tmp_path / "graph.db"
    with gs.open_graph_db(db) as conn:
        gs.save_graph(conn, g_a)
        gs.save_graph(conn, g_b)
    with gs.open_graph_db(db) as conn:
        loaded_b = gs.load_graph(conn, tenant_id="tenant-b", scan_id="shared-scan")

    b_ids = {m.technique_id for p in loaded_b.attack_paths for m in p.technique_mappings}
    assert b_ids.isdisjoint(a_ids)


def test_technique_mapping_to_dict_from_dict_symmetry():
    m = TechniqueMapping(
        hop_index=2,
        technique_id="T1078",
        technique_name="Valid Accounts",
        catalog="attack",
        tactics=["privilege-escalation"],
        provenance="assumes edge into ROLE 'role:admin'",
        confidence=0.7,
    )
    assert TechniqueMapping.from_dict(m.to_dict()) == m
