"""Consumption-side wiring of computed-but-dropped graph posture signals.

Guards three honesty/CIEM fixes on the READ side (graph route + fusion):

1. ``admin_equivalent`` principals now surface + rank in the CIEM/risk surface
   (previously computed on the node but read by nothing).
2. CNAPP exposure-mitigation flags (``exposure_mitigated`` / ``protected_by_waf``
   / ``toxic_exposed_vulnerable_mitigated``) de-prioritize a mitigated node —
   marked mitigated, never silently dropped — so toxic exposure is not
   over-reported.
3. ``sensitive_data_access_count`` (blast-radius reach) is surfaced on the risk
   signal for a sensitive store.
"""

from __future__ import annotations

from agent_bom.api.routes.graph import (
    _derived_attack_paths,
    _derived_toxic_combination_paths,
    _fusion_signals_for_path,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

# ── Defect 1: admin_equivalent surfaces + ranks ──────────────────────────────


def test_admin_equivalent_surfaces_as_fusion_signal_with_basis():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(
        UnifiedNode(
            id="role:admin",
            entity_type=EntityType.ROLE,
            label="admin-role",
            attributes={"admin_equivalent": True, "admin_equivalence_basis": "policy_evaluation"},
        )
    )
    signals = _fusion_signals_for_path(g, ["role:admin"])
    kinds = {kind for kind, _label, _detail, _boost in signals}
    assert "admin_equivalent" in kinds
    detail = next(detail for kind, _l, detail, _b in signals if kind == "admin_equivalent")
    # provenance (basis) stays visible where the flag is surfaced
    assert "policy_evaluation" in detail


def test_admin_equivalent_principal_appears_as_ciem_path():
    # A role that holds admin-equivalent permissions but does NOT reach anything
    # via an assume-chain must still surface as a first-class CIEM path — before
    # the fix it was absent from the queue entirely.
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(
        UnifiedNode(
            id="role:standing-admin",
            entity_type=EntityType.ROLE,
            label="standing-admin",
            attributes={"admin_equivalent": True, "admin_equivalence_basis": "scanner_actions"},
        )
    )
    paths = _derived_attack_paths(g)
    assert any("admin-equivalent" in p.summary.lower() for p in paths)


# ── Defect 2: exposure mitigation de-prioritizes, marked not hidden ───────────


def _exposed_node(node_id: str, *, mitigated: bool) -> UnifiedNode:
    attrs: dict[str, object] = {"internet_exposed": True}
    if mitigated:
        attrs["exposure_mitigated"] = True
        attrs["protected_by_waf"] = True
    return UnifiedNode(id=node_id, entity_type=EntityType.CLOUD_RESOURCE, label=node_id, attributes=attrs)


def test_mitigated_exposure_is_marked_and_deprioritized_not_dropped():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(_exposed_node("cloud:waf", mitigated=True))
    signals = _fusion_signals_for_path(g, ["cloud:waf"])
    kinds = {kind for kind, _l, _d, _b in signals}
    # honesty: it is NOT scored as a full-weight internet exposure...
    assert "internet_exposed" not in kinds
    # ...but it is NOT hidden either — surfaced as an explicitly mitigated signal.
    assert "internet_exposed_mitigated" in kinds
    mitig_boost = next(b for kind, _l, _d, b in signals if kind == "internet_exposed_mitigated")
    full_boost = 15.0  # the unmitigated internet_exposed boost
    assert 0 < mitig_boost < full_boost


def test_mitigated_toxic_combination_scores_below_unmitigated_and_is_marked():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    # Unmitigated: exposed + vulnerable.
    g.add_node(
        UnifiedNode(
            id="cloud:bare",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="bare-api",
            attributes={"internet_exposed": True, "toxic_exposed_vulnerable": True},
        )
    )
    g.add_node(UnifiedNode(id="vuln:a", entity_type=EntityType.VULNERABILITY, label="CVE-A", severity="critical"))
    g.add_edge(UnifiedEdge(source="cloud:bare", target="vuln:a", relationship=RelationshipType.VULNERABLE_TO))
    # Mitigated: same exposure + vuln but WAF-fronted (overlay set the *_mitigated flag).
    g.add_node(
        UnifiedNode(
            id="cloud:waf",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="waf-api",
            attributes={
                "internet_exposed": True,
                "exposure_mitigated": True,
                "protected_by_waf": True,
                "toxic_exposed_vulnerable_mitigated": True,
            },
        )
    )
    g.add_node(UnifiedNode(id="vuln:b", entity_type=EntityType.VULNERABILITY, label="CVE-B", severity="critical"))
    g.add_edge(UnifiedEdge(source="cloud:waf", target="vuln:b", relationship=RelationshipType.VULNERABLE_TO))

    paths = {p.source: p for p in _derived_toxic_combination_paths(g)}
    assert "cloud:bare" in paths, "unmitigated toxic combination must surface"
    assert "cloud:waf" in paths, "mitigated node must still surface (marked), not be dropped"
    assert paths["cloud:waf"].composite_risk < paths["cloud:bare"].composite_risk
    assert "mitigat" in paths["cloud:waf"].summary.lower()


# ── Defect 2b: sensitive_data_access_count surfaces on the risk signal ────────


def test_sensitive_access_count_surfaces_on_sensitive_signal():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(
        UnifiedNode(
            id="ds:pii",
            entity_type=EntityType.DATA_STORE,
            label="pii-store",
            attributes={"data_sensitivity": "sensitive", "sensitive_data_access_count": 4},
        )
    )
    signals = _fusion_signals_for_path(g, ["ds:pii"])
    detail = next(detail for kind, _l, detail, _b in signals if kind == "sensitive_data")
    assert "4" in detail
