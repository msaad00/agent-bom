"""Multi-hop attack-path fusion across the unified cloud graph.

The CNAPP overlay (``cnapp_overlay.py``) and the effective-permissions overlay
(``effective_permissions.py``) each enrich the *same* graph independently — one
adds internet-exposure flags, ``DATA_STORE`` nodes, ``EXPOSED_TO`` / ``STORES``
edges and sensitivity classification; the other resolves assume/trust chains
into transitive ``HAS_PERMISSION`` edges and privilege-escalation flags. On their
own they surface single-hop predicates ("exposed AND vulnerable", "exposed AND
sensitive").

This module fuses them. It walks true *end-to-end* kill-chains across the
unified graph:

    internet-exposed entry node
        → (vulnerable workload / exposed credential / effective permission /
           privilege-escalation hop)*
        → crown-jewel DATA_STORE holding sensitive / regulated data

Each fused chain becomes a first-class :class:`AttackPath` materialised on
``graph.attack_paths`` so every existing consumer (the graph API, the
should-i-deploy decision basis, exposure-path exports) surfaces it without new
plumbing. No new ``EntityType`` / ``RelationshipType`` is introduced — the walk
re-uses the edges the two overlays already wrote.

Bounded for scale exactly like ``effective_permissions``: a node budget caps the
number of nodes visited, a depth cap bounds chain length, entry/jewel fan-out is
capped, and the number of returned paths is capped after ranking + dedup.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

_logger = logging.getLogger(__name__)

_FUSION_SOURCE = "attack-path-fusion"

# ── Bounds (mirror effective_permissions' caps) ──────────────────────────────
_MAX_DEPTH = 6  # max hops (edges) in a single chain
_MAX_NODES = 5000  # node budget: skip fusion on graphs larger than this
_MAX_VISITED_PER_ENTRY = 2000  # per-entry traversal node budget
_MAX_ENTRIES = 200  # cap distinct internet-exposed entry points walked
_MAX_PATHS = 50  # ranked fused chains returned / materialised

_ANALYZER = "attack_path_fusion"
_LIMITS = {
    "max_nodes": _MAX_NODES,
    "max_visited_per_entry": _MAX_VISITED_PER_ENTRY,
    "max_entries": _MAX_ENTRIES,
    "max_depth": _MAX_DEPTH,
    "max_paths": _MAX_PATHS,
}


@dataclass(slots=True)
class _FusionComputation:
    paths: list[AttackPath]
    status: GraphAnalysisStatus


# Edges an attacker can traverse moving *forward* from an internet entry toward
# data. All are already present in the unified graph (inventory + both overlays).
# TRUSTS / CROSS_ACCOUNT_TRUST are deliberately excluded: they are emitted as
# ``role R -> trusted principal P`` where P is *allowed to assume* R (INBOUND
# trust). Walking them forward would fabricate a cross-account kill-chain from an
# exposed R into P's account (the class #3761 removed from toxic_findings).
# ASSUMES (principal -> role) remains the genuine outbound assume vector.
_TRAVERSABLE_RELS = frozenset(
    {
        RelationshipType.USES,
        RelationshipType.DEPENDS_ON,
        RelationshipType.CONTAINS,
        RelationshipType.VULNERABLE_TO,
        RelationshipType.EXPLOITABLE_VIA,
        RelationshipType.EXPOSES_CRED,
        RelationshipType.REACHES_TOOL,
        RelationshipType.PROVIDES_TOOL,
        RelationshipType.AUTHENTICATES_AS,
        RelationshipType.SCOPED_TO,
        RelationshipType.ASSUMES,
        RelationshipType.INHERITS,
        RelationshipType.CAN_ACCESS,
        RelationshipType.HAS_PERMISSION,
        RelationshipType.EXPOSED_TO,
        RelationshipType.STORES,
        RelationshipType.ACCESSED,
    }
)

# Crown-jewel target types — chains only "complete" when they reach a data store.
_CROWN_JEWEL_TYPES = frozenset({EntityType.DATA_STORE})


def _rel(edge: UnifiedEdge) -> RelationshipType:
    return edge.relationship


def _is_entry(node: UnifiedNode) -> bool:
    """An internet-reachable foothold the chain can start from."""
    return bool(node.attributes.get("internet_exposed"))


def _is_crown_jewel(node: UnifiedNode) -> bool:
    """A sensitive / regulated data store — the goal of the kill-chain."""
    if node.entity_type not in _CROWN_JEWEL_TYPES:
        return False
    attrs = node.attributes
    return bool(
        attrs.get("data_sensitivity")
        or attrs.get("toxic_exposed_sensitive")
        or attrs.get("data_regulatory_frameworks")
        or attrs.get("data_classification_tier")
    )


def _edge_boost(edge: UnifiedEdge, target: UnifiedNode) -> tuple[float, str]:
    """Risk contribution + human label for traversing ``edge`` into ``target``."""
    rel = _rel(edge)
    if rel == RelationshipType.VULNERABLE_TO:
        return 18.0, f"exploits vulnerability {target.label}"
    if rel == RelationshipType.EXPOSES_CRED or rel == RelationshipType.REACHES_TOOL:
        return 12.0, f"harvests credential/tool access via {target.label}"
    if rel == RelationshipType.HAS_PERMISSION:
        if (edge.evidence or {}).get("access") == "assume_chain":
            return 20.0, f"escalates privilege (assume-chain) to reach {target.label}"
        return 8.0, f"uses effective permission to reach {target.label}"
    if rel in (RelationshipType.ASSUMES, RelationshipType.INHERITS):
        return 14.0, f"assumes role into {target.label}"
    if rel == RelationshipType.EXPOSED_TO:
        return 16.0, f"reaches internet-exposed {target.label}"
    if rel == RelationshipType.STORES:
        return 6.0, f"pivots to stored data {target.label}"
    if rel == RelationshipType.CAN_ACCESS:
        return 6.0, f"accesses {target.label}"
    return 2.0, f"moves to {target.label}"


def _node_boost(node: UnifiedNode) -> float:
    """Standing risk a node contributes when it sits on a chain."""
    attrs = node.attributes
    boost = 0.0
    if attrs.get("toxic_exposed_vulnerable"):
        boost += 10.0
    elif attrs.get("toxic_exposed_vulnerable_mitigated"):
        # Exposure fronted by a WAF/API gateway: a real but mitigated toxic combo.
        # Counted at a reduced weight so it ranks below a bare toxic node without
        # being silently dropped (honesty: de-prioritized, not hidden).
        boost += 4.0
    if attrs.get("escalates_to_admin"):
        boost += 12.0
    elif attrs.get("can_escalate_privilege"):
        boost += 8.0
    # Standing admin-equivalent permissions are an independent escalation prize
    # (holds admin directly, distinct from reaching admin via an assume-chain).
    if attrs.get("admin_equivalent"):
        boost += 12.0
    return boost


def _jewel_reward(node: UnifiedNode) -> tuple[float, str]:
    """Reward for terminating at this crown jewel + a description of the prize."""
    attrs = node.attributes
    frameworks = attrs.get("data_regulatory_frameworks") or []
    tier = attrs.get("data_classification_tier")
    if frameworks:
        return 30.0, f"{'/'.join(str(f) for f in frameworks)} regulated data"
    if tier == "restricted":
        return 28.0, "restricted data"
    if attrs.get("toxic_exposed_sensitive"):
        return 26.0, "internet-exposed sensitive data"
    return 22.0, "sensitive data"


def _summary(hops: list[str], graph: UnifiedGraph, edge_labels: list[str], prize: str) -> str:
    entry = graph.nodes.get(hops[0])
    entry_label = entry.label if entry is not None else hops[0]
    steps = "; ".join(edge_labels)
    return f"Internet-exposed {entry_label} {steps} — reaching {prize} ({len(hops) - 1} hop chain)."


def compute_fused_attack_paths(graph: UnifiedGraph) -> list[AttackPath]:
    """Return ranked end-to-end fused attack paths. Bounded; never raises.

    Walks forward from each internet-exposed entry node along kill-chain edges,
    collecting the *highest-scoring* chain that terminates at each reachable
    crown-jewel data store, then ranks + dedups + caps the result.
    """
    return _compute_fused_attack_paths(graph).paths


def _compute_fused_attack_paths(graph: UnifiedGraph) -> _FusionComputation:
    """Compute paths together with an honest snapshot-wide execution status."""
    node_count = len(graph.nodes)
    base_observed = {"node_count": node_count}
    if not graph.nodes:
        return _FusionComputation(
            [],
            GraphAnalysisStatus(
                status=GraphAnalysisState.COMPLETE,
                limits=_LIMITS,
                observed={**base_observed, "entry_count": 0, "evaluated_entry_count": 0, "candidate_path_count": 0, "result_count": 0},
            ),
        )
    if len(graph.nodes) > _MAX_NODES:
        # Capped, NOT "no attack paths". Log a signal so a large real estate that
        # skipped fusion is not silently read as "flagship found nothing".
        _logger.warning(
            "attack-path fusion capped: %d nodes exceed cap %d; fused kill-chains "
            "NOT computed for this graph (result is 'skipped', not 'none')",
            len(graph.nodes),
            _MAX_NODES,
        )
        return _FusionComputation(
            [],
            GraphAnalysisStatus(
                status=GraphAnalysisState.SKIPPED,
                reason_codes=("node_cap_exceeded",),
                limits=_LIMITS,
                observed={**base_observed, "entry_count": 0, "evaluated_entry_count": 0, "candidate_path_count": 0, "result_count": 0},
            ),
        )

    entries = [n for n in graph.nodes.values() if _is_entry(n)]
    entry_count = len(entries)
    if not entries:
        return _FusionComputation(
            [],
            GraphAnalysisStatus(
                status=GraphAnalysisState.COMPLETE,
                limits=_LIMITS,
                observed={**base_observed, "entry_count": 0, "evaluated_entry_count": 0, "candidate_path_count": 0, "result_count": 0},
            ),
        )
    # Deterministic, bounded set of footholds.
    entries.sort(key=lambda n: (-n.risk_score, n.id))
    entries = entries[:_MAX_ENTRIES]
    reason_codes: set[str] = set()
    if entry_count > _MAX_ENTRIES:
        reason_codes.add("entry_cap_reached")

    # Best chain (by score) per (entry, jewel) pair, deduped across entries.
    best_by_pair: dict[tuple[str, str], tuple[float, AttackPath]] = {}

    for entry in entries:
        reason_codes.update(_walk_from_entry(graph, entry, best_by_pair))

    paths = [ap for _score, ap in best_by_pair.values()]
    paths.sort(key=lambda p: (p.composite_risk, len(p.hops)), reverse=True)
    candidate_path_count = len(paths)
    if candidate_path_count > _MAX_PATHS:
        reason_codes.add("path_cap_reached")
    paths = paths[:_MAX_PATHS]
    return _FusionComputation(
        paths,
        GraphAnalysisStatus(
            status=GraphAnalysisState.LIMITED if reason_codes else GraphAnalysisState.COMPLETE,
            reason_codes=tuple(sorted(reason_codes)),
            limits=_LIMITS,
            observed={
                **base_observed,
                "entry_count": entry_count,
                "evaluated_entry_count": len(entries),
                "candidate_path_count": candidate_path_count,
                "result_count": len(paths),
            },
        ),
    )


def _walk_from_entry(
    graph: UnifiedGraph,
    entry: UnifiedNode,
    best_by_pair: dict[tuple[str, str], tuple[float, AttackPath]],
) -> set[str]:
    """Bounded DFS from a single entry, recording best chain per crown jewel."""
    visited_budget = {"n": 0}
    limit_reasons: set[str] = set()

    def dfs(
        node_id: str,
        hops: list[str],
        edge_rels: list[str],
        edge_labels: list[str],
        on_path: set[str],
        score: float,
        vuln_ids: list[str],
        cred_exposure: list[str],
    ) -> None:
        if visited_budget["n"] >= _MAX_VISITED_PER_ENTRY:
            limit_reasons.add("visit_cap_reached")
            return
        visited_budget["n"] += 1
        node = graph.nodes.get(node_id)
        if node is None:
            return

        # Completed chain: reached a crown jewel (and we actually moved).
        if len(hops) > 1 and _is_crown_jewel(node):
            reward, prize = _jewel_reward(node)
            final_score = round(min(100.0, score + reward), 2)
            path = AttackPath(
                source=hops[0],
                target=node_id,
                hops=list(hops),
                edges=list(edge_rels),
                composite_risk=final_score,
                summary=_summary(hops, graph, edge_labels, prize),
                credential_exposure=sorted(set(cred_exposure)),
                vuln_ids=sorted(set(vuln_ids)),
            )
            key = (hops[0], node_id)
            existing = best_by_pair.get(key)
            if existing is None or final_score > existing[0]:
                best_by_pair[key] = (final_score, path)
            # A data store can also be a transit hop, so keep exploring.

        if len(hops) > _MAX_DEPTH:
            if any(_rel(edge) in _TRAVERSABLE_RELS and edge.target not in on_path for edge in graph.adjacency.get(node_id, [])):
                limit_reasons.add("depth_cap_reached")
            return

        for edge in graph.adjacency.get(node_id, []):
            if _rel(edge) not in _TRAVERSABLE_RELS:
                continue
            nxt = edge.target
            if nxt in on_path:  # no cycles
                continue
            target = graph.nodes.get(nxt)
            if target is None:
                continue
            boost, label = _edge_boost(edge, target)
            next_vulns = vuln_ids + [target.label or target.id] if target.entity_type == EntityType.VULNERABILITY else vuln_ids
            next_creds = (
                cred_exposure + [target.label or target.id]
                if target.entity_type in (EntityType.CREDENTIAL, EntityType.CREDENTIAL_REF)
                else cred_exposure
            )
            on_path.add(nxt)
            dfs(
                nxt,
                hops + [nxt],
                edge_rels + [_rel(edge).value],
                edge_labels + [label],
                on_path,
                score + boost + _node_boost(target),
                next_vulns,
                next_creds,
            )
            on_path.discard(nxt)

    dfs(entry.id, [entry.id], [], [], {entry.id}, _node_boost(entry), [], [])
    return limit_reasons


def apply_attack_path_fusion(graph: UnifiedGraph) -> dict[str, object]:
    """Compute fused chains and materialise them on ``graph.attack_paths``.

    Idempotent w.r.t. fusion: existing fusion-sourced paths are replaced so a
    re-run does not duplicate them. Other attack paths (lateral, governance) are
    preserved. Returns counts. Never raises into the builder.

    Large estates (> ``_MAX_NODES``) no longer skip: they run the bounded,
    partitioned campaign engine (:mod:`agent_bom.graph.attack_path_campaigns`),
    which yields bounded fused paths + prioritized campaigns with an honest
    ``LIMITED / partitioned`` completeness status (never a fabricated clean/complete
    result). Smaller estates keep the exact prior whole-graph behaviour.
    """
    if len(graph.nodes) > _MAX_NODES:
        return _apply_partitioned_campaigns(graph)

    computation = _compute_fused_attack_paths(graph)
    fused = computation.paths
    # Drop any prior fusion output, keep everything else.
    graph.attack_paths = [p for p in graph.attack_paths if not _is_fusion_path(p)]
    graph.attack_paths.extend(fused)
    graph.attack_campaigns = _cluster_small_graph_campaigns(graph, fused)
    graph.analysis_status[_ANALYZER] = computation.status
    return {
        "fused_attack_paths": len(fused),
        "max_fused_risk": int(round(max((p.composite_risk for p in fused), default=0.0))),
        "campaign_count": len(graph.attack_campaigns),
        "analysis_status": computation.status.to_dict(),
    }


def _cluster_small_graph_campaigns(graph: UnifiedGraph, fused: list[AttackPath]):
    """Cluster whole-graph fused paths into campaigns for a consistent surface."""
    from agent_bom.graph.attack_path_campaigns import _cluster_campaigns, _partition_key

    partition_of = {nid: _partition_key(node) for nid, node in graph.nodes.items()}
    return _cluster_campaigns(graph, fused, partition_of)


def _apply_partitioned_campaigns(graph: UnifiedGraph) -> dict[str, object]:
    """Run the bounded partitioned engine and materialise its output on the graph."""
    from agent_bom.graph.attack_path_campaigns import compute_partitioned_campaigns

    result = compute_partitioned_campaigns(graph)
    graph.attack_paths = [p for p in graph.attack_paths if not _is_fusion_path(p)]
    graph.attack_paths.extend(result.paths)
    graph.attack_campaigns = result.campaigns
    graph.analysis_status[_ANALYZER] = result.status
    return {
        "fused_attack_paths": len(result.paths),
        "max_fused_risk": int(round(max((p.composite_risk for p in result.paths), default=0.0))),
        "campaign_count": len(result.campaigns),
        "bounded": True,
        "partitioned": True,
        "campaigns": [c.to_dict() for c in result.campaigns],
        "analysis_status": result.status.to_dict(),
    }


def _is_fusion_path(path: AttackPath) -> bool:
    return path.summary.startswith("Internet-exposed ") and "hop chain)" in path.summary
