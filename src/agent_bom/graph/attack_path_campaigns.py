"""Bounded, partitioned attack-path campaigns for large estates.

``attack_path_fusion`` walks true end-to-end kill-chains, but returns an honest
``SKIPPED / node_cap_exceeded`` once a graph exceeds ``_MAX_NODES`` — a whole-graph
DFS does not stay bounded at estate scale. That left large estates with *no* fused
paths from the flagship correlation layer (issue #4156).

This module replaces the blanket skip with a **bounded, partitioned** computation:

1. **Partition** the graph deterministically by an authoritative, tenant-scoped
   partition key (cloud account / subscription / project + provider + environment,
   with a stable hash bucket for unattributed nodes). Same estate → same
   partitions.
2. **Compute within bounded partitions.** Each internet-exposed entry seeds a
   *partition-local* bounded DFS whose visited budget (``_MAX_PARTITION_NODES``)
   caps the working set — the analysis never materialises the full estate at once.
3. **Reconcile cross-partition joins from authoritative edges only.** When a walk
   reaches a node with an out-edge into another partition, it emits a bounded
   *arrival* into that partition rather than expanding the whole estate. Arrivals
   are processed highest-score-first through a capped frontier, so a chain
   ``entry(A) → role(B) → jewel(B)`` (or deeper, ``A → B → C``) is stitched from
   the real edges without a global entry×jewel product.
4. **Cluster** the resulting paths into prioritized **campaigns**, one per crown
   jewel, with deterministic identity (``tenant_id`` + jewel canonical id).

Honesty (issue #4156 §11): a partitioned run is *bounded by construction*, so its
status is always ``LIMITED`` with a ``partitioned`` reason code — never ``COMPLETE``
(would over-claim) and never ``SKIPPED`` (the old all-or-nothing regression). An
empty estate stays empty: zero paths, zero campaigns, no fabrication.
"""

from __future__ import annotations

import hashlib
import heapq
from collections.abc import Callable
from dataclasses import dataclass

from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.attack_path_fusion import (
    _TRAVERSABLE_RELS,
    _edge_boost,
    _is_crown_jewel,
    _is_entry,
    _jewel_reward,
    _node_boost,
    _rel,
    _summary,
)
from agent_bom.graph.container import AttackPath, Campaign, UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

# ── Bounds ───────────────────────────────────────────────────────────────────
_MAX_PARTITION_NODES = 2000  # per-partition local visit budget (bounds working set)
_MAX_PARTITIONS = 500  # cap distinct partitions explored
_MAX_ENTRIES = 500  # cap distinct entry footholds seeded
_MAX_FRONTIER = 5000  # cap cross-partition arrival events processed
_MAX_CHAIN_DEPTH = 12  # cap total hops (edges) across a full stitched chain
_MAX_CAMPAIGN_PATHS = 200  # cap ranked member paths retained
_HASH_BUCKETS = 64  # fixed fallback partitions for account-unattributed nodes

_LIMITS = {
    "max_partition_nodes": _MAX_PARTITION_NODES,
    "max_partitions": _MAX_PARTITIONS,
    "max_entries": _MAX_ENTRIES,
    "max_frontier": _MAX_FRONTIER,
    "max_chain_depth": _MAX_CHAIN_DEPTH,
    "max_campaign_paths": _MAX_CAMPAIGN_PATHS,
}


@dataclass(slots=True)
class PartitionedCampaignResult:
    """Bounded partitioned output: ranked paths, clustered campaigns, honest status."""

    paths: list[AttackPath]
    campaigns: list[Campaign]
    status: GraphAnalysisStatus


@dataclass(slots=True)
class _Arrival:
    """A bounded cross-partition entry into a partition, carrying its full prefix."""

    node_id: str
    entry_id: str
    hops: list[str]
    edges: list[str]
    labels: list[str]
    score: float
    vulns: list[str]
    creds: list[str]


def _partition_key(node: UnifiedNode) -> str:
    """Deterministic, authoritative partition key.

    Prefers the cloud account / subscription / project the node belongs to (the
    natural blast-radius boundary), qualified by provider + environment. Nodes with
    no account attribution fall into a stable hash bucket so the whole estate is
    covered without a single unbounded partition.
    """
    attrs = node.attributes
    account = str(
        attrs.get("cloud_account_id")
        or attrs.get("account_id")
        or attrs.get("subscription_id")
        or attrs.get("project_id")
        or attrs.get("account_ref")
        or ""
    ).strip()
    provider = str(node.dimensions.cloud_provider or attrs.get("provider") or "").strip()
    environment = str(node.dimensions.environment or "").strip()
    natural = ":".join(part for part in (provider, account, environment) if part)
    if natural:
        return natural
    # Fixed, bounded bucket space so unattributed nodes cluster into a small number
    # of partitions rather than each becoming its own — keeping partition count and
    # the working set bounded regardless of estate size.
    digest = hashlib.blake2b(node.id.encode("utf-8"), digest_size=8).hexdigest()
    return f"bucket:{int(digest, 16) % _HASH_BUCKETS}"


def _campaign_id(graph: UnifiedGraph, jewel: UnifiedNode | None, jewel_id: str) -> str:
    """Deterministic campaign identity: tenant-scoped + jewel canonical id.

    Excludes ``scan_id`` so the *same estate* re-scanned yields the *same* id;
    includes ``tenant_id`` so identical jewels never collide across tenants.
    """
    canonical = jewel.canonical_id if jewel is not None else jewel_id
    seed = f"{graph.tenant_id}|{canonical}".encode("utf-8")
    return "campaign-" + hashlib.sha256(seed).hexdigest()[:16]


def compute_partitioned_campaigns(graph: UnifiedGraph) -> PartitionedCampaignResult:
    """Bounded, partitioned campaign computation. Never raises; never over-claims."""
    node_count = len(graph.nodes)
    reason_codes: set[str] = {"partitioned"}

    partition_of: dict[str, str] = {nid: _partition_key(n) for nid, n in graph.nodes.items()}
    partitions = sorted(set(partition_of.values()))
    if len(partitions) > _MAX_PARTITIONS:
        reason_codes.add("partition_cap_reached")
        kept = set(partitions[:_MAX_PARTITIONS])
    else:
        kept = set(partitions)

    entries = [n for n in graph.nodes.values() if _is_entry(n) and partition_of[n.id] in kept]
    entry_count = len(entries)
    entries.sort(key=lambda n: (-n.risk_score, n.id))
    if entry_count > _MAX_ENTRIES:
        reason_codes.add("entry_cap_reached")
        entries = entries[:_MAX_ENTRIES]

    best_by_pair: dict[tuple[str, str], tuple[float, AttackPath, bool]] = {}
    state = {"frontier_events": 0, "peak_working_set": 0, "cross_partition_paths": 0}
    # (node_id, entry_id) -> best score already seeded, to bound frontier fan-out.
    seen_arrival: dict[tuple[str, str], float] = {}
    # Deterministic max-heap via negated score + tie-breakers + monotonic counter.
    heap: list[tuple[float, str, str, int, _Arrival]] = []
    counter = 0

    def push(arrival: _Arrival) -> None:
        nonlocal counter
        key = (arrival.node_id, arrival.entry_id)
        prior = seen_arrival.get(key)
        if prior is not None and prior >= arrival.score:
            return
        if len(seen_arrival) >= _MAX_FRONTIER and key not in seen_arrival:
            reason_codes.add("partition_frontier_cap_reached")
            return
        seen_arrival[key] = arrival.score
        heapq.heappush(heap, (-arrival.score, arrival.entry_id, arrival.node_id, counter, arrival))
        counter += 1

    for entry in entries:
        push(_Arrival(entry.id, entry.id, [entry.id], [], [], _node_boost(entry), [], []))

    while heap:
        if state["frontier_events"] >= _MAX_FRONTIER:
            reason_codes.add("partition_frontier_cap_reached")
            break
        _neg, _e, _n, _c, arrival = heapq.heappop(heap)
        state["frontier_events"] += 1
        _explore_partition(graph, arrival, partition_of, kept, best_by_pair, reason_codes, state, push)

    paths = [ap for _score, ap, _cross in best_by_pair.values()]
    paths.sort(key=lambda p: (p.composite_risk, len(p.hops)), reverse=True)
    candidate_path_count = len(paths)
    if candidate_path_count > _MAX_CAMPAIGN_PATHS:
        reason_codes.add("path_cap_reached")
        paths = paths[:_MAX_CAMPAIGN_PATHS]
    kept_keys = {(p.source, p.target) for p in paths}
    if any(cross for key, (_s, _p, cross) in best_by_pair.items() if key in kept_keys):
        reason_codes.add("cross_partition")

    campaigns = _cluster_campaigns(graph, paths, partition_of)

    status = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED,
        reason_codes=tuple(sorted(reason_codes)),
        limits=_LIMITS,
        observed={
            "node_count": node_count,
            "partition_count": len(partitions),
            "evaluated_partition_count": len(kept),
            "entry_count": entry_count,
            "evaluated_entry_count": len(entries),
            "frontier_events": state["frontier_events"],
            "cross_partition_paths": state["cross_partition_paths"],
            "candidate_path_count": candidate_path_count,
            "result_count": len(paths),
            "campaign_count": len(campaigns),
            "peak_working_set": state["peak_working_set"],
        },
    )
    return PartitionedCampaignResult(paths, campaigns, status)


def _explore_partition(
    graph: UnifiedGraph,
    arrival: _Arrival,
    partition_of: dict[str, str],
    kept: set[str],
    best_by_pair: dict[tuple[str, str], tuple[float, AttackPath, bool]],
    reason_codes: set[str],
    state: dict[str, int],
    push: Callable[[_Arrival], None],
) -> None:
    """Bounded DFS confined to a single partition from one arrival node.

    Records completed chains that reach a crown jewel and emits bounded arrivals
    across authoritative cross-partition out-edges. The local visited budget bounds
    the working set to one partition at a time.
    """
    part = partition_of.get(arrival.node_id)
    prefix_set = set(arrival.hops)
    start_partitions = {partition_of.get(h) for h in arrival.hops}
    local_budget = {"n": 0}

    def dfs(
        node_id: str,
        hops: list[str],
        edges: list[str],
        labels: list[str],
        score: float,
        vulns: list[str],
        creds: list[str],
        crossed: bool,
    ) -> None:
        if local_budget["n"] >= _MAX_PARTITION_NODES:
            reason_codes.add("visit_cap_reached")
            return
        local_budget["n"] += 1
        if local_budget["n"] > state["peak_working_set"]:
            state["peak_working_set"] = local_budget["n"]
        node = graph.nodes.get(node_id)
        if node is None:
            return

        if len(hops) > 1 and _is_crown_jewel(node):
            reward, prize = _jewel_reward(node)
            final_score = round(min(100.0, score + reward), 2)
            path = AttackPath(
                source=hops[0],
                target=node_id,
                hops=list(hops),
                edges=list(edges),
                composite_risk=final_score,
                summary=_summary(hops, graph, labels, prize),
                credential_exposure=sorted(set(creds)),
                vuln_ids=sorted(set(vulns)),
            )
            key = (hops[0], node_id)
            existing = best_by_pair.get(key)
            if existing is None or final_score > existing[0]:
                if crossed and (existing is None or not existing[2]):
                    state["cross_partition_paths"] += 1
                best_by_pair[key] = (final_score, path, crossed)

        if len(hops) > _MAX_CHAIN_DEPTH:
            reason_codes.add("depth_cap_reached")
            return

        for edge in graph.adjacency.get(node_id, []):
            if _rel(edge) not in _TRAVERSABLE_RELS:
                continue
            nxt = edge.target
            if nxt in prefix_set or nxt in hops:
                continue
            target = graph.nodes.get(nxt)
            if target is None:
                continue
            target_part = partition_of.get(nxt)
            if target_part not in kept:
                continue
            boost, label = _edge_boost(edge, target)
            next_vulns = vulns + [target.label or target.id] if target.entity_type == EntityType.VULNERABILITY else vulns
            next_creds = (
                creds + [target.label or target.id] if target.entity_type in (EntityType.CREDENTIAL, EntityType.CREDENTIAL_REF) else creds
            )
            next_score = score + boost + _node_boost(target)
            if target_part == part:
                dfs(nxt, hops + [nxt], edges + [_rel(edge).value], labels + [label], next_score, next_vulns, next_creds, crossed)
            else:
                # Authoritative cross-partition edge → bounded arrival into the next
                # partition. Does not expand the current partition's working set.
                push(
                    _Arrival(
                        node_id=nxt,
                        entry_id=hops[0],
                        hops=hops + [nxt],
                        edges=edges + [_rel(edge).value],
                        labels=labels + [label],
                        score=next_score,
                        vulns=next_vulns,
                        creds=next_creds,
                    )
                )

    already_crossed = len(start_partitions - {None}) > 1
    dfs(
        arrival.node_id,
        list(arrival.hops),
        list(arrival.edges),
        list(arrival.labels),
        arrival.score,
        list(arrival.vulns),
        list(arrival.creds),
        already_crossed,
    )


def _cluster_campaigns(
    graph: UnifiedGraph,
    paths: list[AttackPath],
    partition_of: dict[str, str],
) -> list[Campaign]:
    """Group paths by crown jewel into deterministic, prioritized campaigns."""
    by_jewel: dict[str, list[AttackPath]] = {}
    for path in paths:
        by_jewel.setdefault(path.target, []).append(path)

    campaigns: list[Campaign] = []
    for jewel_id, members in by_jewel.items():
        members.sort(key=lambda p: (p.composite_risk, len(p.hops)), reverse=True)
        jewel = graph.nodes.get(jewel_id)
        top = members[0]
        exploitability = round(max(p.composite_risk for p in members), 2)
        _reward, prize = _jewel_reward(jewel) if jewel is not None else (0.0, "sensitive data")
        owner = ""
        if jewel is not None:
            owner = str(jewel.attributes.get("owner") or jewel.attributes.get("resource_owner") or "").strip()
        cross_partition = any(len({partition_of.get(h) for h in p.hops} - {None}) > 1 for p in members)
        evidence = sorted({vid for p in members for vid in p.vuln_ids} | {cid for p in members for cid in p.credential_exposure})
        campaigns.append(
            Campaign(
                campaign_id=_campaign_id(graph, jewel, jewel_id),
                crown_jewel=jewel_id,
                crown_jewel_label=(jewel.label if jewel is not None else jewel_id),
                partition=partition_of.get(jewel_id, ""),
                owner=owner or "unknown",
                business_impact=prize,
                exploitability=exploitability,
                expected_risk_reduction=exploitability,
                path_count=len(members),
                top_path_summary=top.summary,
                cross_partition=cross_partition,
                evidence=evidence,
                member_paths=[f"{p.source}->{p.target}" for p in members],
            )
        )
    campaigns.sort(key=lambda c: (c.exploitability, c.path_count, c.campaign_id), reverse=True)
    return campaigns
