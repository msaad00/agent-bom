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

from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

_FUSION_SOURCE = "attack-path-fusion"

# ── Bounds (mirror effective_permissions' caps) ──────────────────────────────
_MAX_DEPTH = 6  # max hops (edges) in a single chain
_MAX_NODES = 5000  # node budget: skip fusion on graphs larger than this
_MAX_VISITED_PER_ENTRY = 2000  # per-entry traversal node budget
_MAX_ENTRIES = 200  # cap distinct internet-exposed entry points walked
_MAX_PATHS = 50  # ranked fused chains returned / materialised

# Edges an attacker can traverse moving *forward* from an internet entry toward
# data. All are already present in the unified graph (inventory + both overlays).
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
        RelationshipType.TRUSTS,
        RelationshipType.CROSS_ACCOUNT_TRUST,
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
    if rel in (RelationshipType.ASSUMES, RelationshipType.TRUSTS, RelationshipType.CROSS_ACCOUNT_TRUST, RelationshipType.INHERITS):
        return 14.0, f"assumes role/trust into {target.label}"
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
    if attrs.get("escalates_to_admin"):
        boost += 12.0
    elif attrs.get("can_escalate_privilege"):
        boost += 8.0
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
    if not graph.nodes or len(graph.nodes) > _MAX_NODES:
        return []

    entries = [n for n in graph.nodes.values() if _is_entry(n)]
    if not entries:
        return []
    # Deterministic, bounded set of footholds.
    entries.sort(key=lambda n: (-n.risk_score, n.id))
    entries = entries[:_MAX_ENTRIES]

    # Best chain (by score) per (entry, jewel) pair, deduped across entries.
    best_by_pair: dict[tuple[str, str], tuple[float, AttackPath]] = {}

    for entry in entries:
        _walk_from_entry(graph, entry, best_by_pair)

    paths = [ap for _score, ap in best_by_pair.values()]
    paths.sort(key=lambda p: (p.composite_risk, len(p.hops)), reverse=True)
    return paths[:_MAX_PATHS]


def _walk_from_entry(
    graph: UnifiedGraph,
    entry: UnifiedNode,
    best_by_pair: dict[tuple[str, str], tuple[float, AttackPath]],
) -> None:
    """Bounded DFS from a single entry, recording best chain per crown jewel."""
    visited_budget = {"n": 0}

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


def apply_attack_path_fusion(graph: UnifiedGraph) -> dict[str, int]:
    """Compute fused chains and materialise them on ``graph.attack_paths``.

    Idempotent w.r.t. fusion: existing fusion-sourced paths are replaced so a
    re-run does not duplicate them. Other attack paths (lateral, governance) are
    preserved. Returns counts. Never raises into the builder.
    """
    fused = compute_fused_attack_paths(graph)
    # Drop any prior fusion output, keep everything else.
    graph.attack_paths = [p for p in graph.attack_paths if not _is_fusion_path(p)]
    graph.attack_paths.extend(fused)
    return {
        "fused_attack_paths": len(fused),
        "max_fused_risk": int(round(max((p.composite_risk for p in fused), default=0.0))),
    }


def _is_fusion_path(path: AttackPath) -> bool:
    return path.summary.startswith("Internet-exposed ") and "hop chain)" in path.summary
