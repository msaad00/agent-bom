"""Ranked, filterable page of the attack-path queue.

The stores return persisted paths ordered by stored ``composite_risk``; this
module re-ranks a bounded window of them by on-path exploitability evidence
(see :mod:`agent_bom.graph.attack_path_queue_rank`) before slicing the page, so
pagination, totals, and filters all describe the same ordered set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_bom.graph.attack_path_queue_rank import rank_attack_paths, ranking_node_ids
from agent_bom.graph.container import AttackPath

# Persisted paths re-ranked per request. A larger snapshot ranks its top window
# by stored score and reports ``ranking.complete = false``.
RANK_WINDOW = 20_000


def attack_path_rank_window() -> int:
    return RANK_WINDOW


@dataclass(slots=True)
class AttackPathFilters:
    min_severity: str | None = None
    has_credential: bool | None = None
    source_type: str | None = None

    def active(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in (
                ("min_severity", self.min_severity),
                ("has_credential", self.has_credential),
                ("source_type", self.source_type),
            )
            if value is not None
        }


@dataclass(slots=True)
class RankedPathPage:
    scan_id: str
    created_at: str
    paths: list[AttackPath]
    total: int
    snapshot_total: int
    ranking: dict[str, Any] = field(default_factory=dict)


def _rank_and_slice(
    candidates: list[AttackPath],
    nodes_by_id: dict[str, Any],
    *,
    offset: int,
    limit: int,
    filters: AttackPathFilters,
) -> tuple[list[AttackPath], int]:
    ranked = rank_attack_paths(
        candidates,
        nodes_by_id,
        min_severity=filters.min_severity,
        has_credential=filters.has_credential,
        source_type=filters.source_type,
    )
    return ranked[offset : offset + limit], len(ranked)


def _ranking_meta(*, snapshot_total: int, window: int) -> dict[str, Any]:
    complete = snapshot_total <= window
    return {
        "method": "exploitability_evidence",
        "order": ["evidence_tier", "is_kev", "severity", "composite_risk", "credential_count", "source", "target"],
        "window": window,
        "complete": complete,
        "scope": "all_snapshot_paths" if complete else "top_window_by_stored_composite_risk",
    }


def ranked_persisted_path_page(
    graph_store: Any,
    *,
    scan_id: str,
    tenant_id: str,
    offset: int,
    limit: int,
    filters: AttackPathFilters,
) -> RankedPathPage:
    window = attack_path_rank_window()
    effective_scan_id, created_at, candidates, snapshot_total = graph_store.attack_paths(
        scan_id=scan_id,
        tenant_id=tenant_id,
        offset=0,
        limit=window,
    )
    if snapshot_total == 0:
        return RankedPathPage(effective_scan_id, created_at, [], 0, 0)
    nodes = graph_store.nodes_by_ids(scan_id=effective_scan_id, tenant_id=tenant_id, node_ids=ranking_node_ids(candidates))
    nodes_by_id = {node.id: node for node in nodes}
    page, total = _rank_and_slice(candidates, nodes_by_id, offset=offset, limit=limit, filters=filters)
    return RankedPathPage(
        effective_scan_id,
        created_at,
        page,
        total,
        snapshot_total,
        _ranking_meta(snapshot_total=snapshot_total, window=window),
    )


def ranked_derived_path_page(
    graph: Any,
    derived_paths: list[AttackPath],
    *,
    offset: int,
    limit: int,
    filters: AttackPathFilters | None = None,
) -> RankedPathPage:
    page, total = _rank_and_slice(derived_paths, graph.nodes, offset=offset, limit=limit, filters=filters or AttackPathFilters())
    return RankedPathPage(
        graph.scan_id,
        graph.created_at,
        page,
        total,
        len(derived_paths),
        _ranking_meta(snapshot_total=len(derived_paths), window=len(derived_paths) or 1),
    )


__all__ = [
    "AttackPathFilters",
    "RankedPathPage",
    "attack_path_rank_window",
    "ranked_derived_path_page",
    "ranked_persisted_path_page",
]
