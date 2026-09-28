"""Typed graph persistence/query port, independent of API and database adapters."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Any, Protocol

from agent_bom.graph.analysis import GraphAnalysisStatus
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.correlation import CorrelationRunStatus, GraphCorrelationRun
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import RelationshipType

if TYPE_CHECKING:
    from agent_bom.graph.delta_digest import PriorSnapshotDigest


class GraphStoreProtocol(Protocol):
    """Backend-neutral graph store port owned by graph application services."""

    def latest_snapshot_id(self, *, tenant_id: str = "", snapshot_kind: str = "scan") -> str: ...

    def previous_snapshot_id(
        self,
        *,
        tenant_id: str = "",
        before_scan_id: str = "",
        snapshot_kind: str = "scan",
    ) -> str: ...

    def save_graph(self, graph: UnifiedGraph) -> None: ...

    def delete_snapshot(self, *, tenant_id: str, scan_id: str, expected_generation: str | None = None) -> int: ...

    def save_graph_streaming(
        self,
        *,
        scan_id: str,
        tenant_id: str = "",
        nodes: Iterable[UnifiedNode],
        edges: Iterable[UnifiedEdge],
        attack_paths: Iterable[AttackPath] = (),
        interaction_risks: Iterable[Any] = (),
        analysis_status: Mapping[str, GraphAnalysisStatus] | None = None,
        created_at: str = "",
        snapshot_kind: str = "scan",
        correlation_id: str = "",
        evidence_manifest_sha256: str = "",
        write_generation: str = "",
    ) -> dict[str, int]: ...

    def complete_correlation_run(
        self,
        graph: UnifiedGraph,
        *,
        result_manifest: Mapping[str, Any],
        manifest_sha256: str,
        completed_at: str = "",
        execution_owner: str = "",
    ) -> GraphCorrelationRun: ...

    def create_correlation_run(self, run: GraphCorrelationRun) -> tuple[GraphCorrelationRun, bool]: ...

    def get_correlation_run(self, *, tenant_id: str, correlation_id: str) -> GraphCorrelationRun | None: ...

    def get_correlation_run_by_idempotency_key(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
    ) -> GraphCorrelationRun | None: ...

    def list_correlation_runs(self, *, tenant_id: str, limit: int = 100) -> list[GraphCorrelationRun]: ...

    def count_active_correlation_runs(self, *, tenant_id: str) -> int: ...

    def claim_correlation_run_execution(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        owner_token: str,
        lease_seconds: int,
        now: str,
    ) -> GraphCorrelationRun | None: ...

    def heartbeat_correlation_run_execution(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        owner_token: str,
        lease_seconds: int,
        now: str,
    ) -> bool: ...

    def update_correlation_run(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        status: CorrelationRunStatus,
        manifest_sha256: str = "",
        result_manifest: Mapping[str, Any] | None = None,
        output_scan_id: str = "",
        failure_code: str = "",
        started_at: str = "",
        completed_at: str = "",
        execution_owner: str = "",
    ) -> GraphCorrelationRun: ...

    def prior_delta_digest(self, *, tenant_id: str = "", scan_id: str = "") -> "PriorSnapshotDigest": ...

    def load_graph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        relationship_types: frozenset[str] | None = None,
        node_budget: int | None = None,
    ) -> UnifiedGraph: ...

    def diff_snapshots(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]: ...

    def active_edges_at(self, at: str, *, tenant_id: str = "") -> list[dict[str, Any]]: ...

    def changed_edges_between_scans(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]: ...

    def list_snapshots(self, *, tenant_id: str = "", limit: int = 50, since: str | None = None) -> list[dict[str, Any]]: ...

    def snapshots_by_ids(self, *, tenant_id: str, scan_ids: set[str]) -> list[dict[str, Any]]: ...

    def snapshot_identity(self, *, tenant_id: str = "", scan_id: str = "") -> tuple[str, str]: ...

    def graph_history(self, *, tenant_id: str = "", limit: int = 50, since: str | None = None) -> dict[str, Any]: ...

    def evidence_manifest(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        baseline_scan_id: str = "",
    ) -> dict[str, Any]: ...

    def delete_tenant(self, *, tenant_id: str = "") -> int: ...

    def snapshot_stats(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> dict[str, Any]: ...

    def page_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 500,
    ) -> tuple[str, str, list[UnifiedNode], int, str | None]: ...

    def edges_for_node_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
        induced_only: bool = False,
    ) -> list[Any]: ...

    def search_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        query: str,
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        compliance_prefixes: set[str] | None = None,
        data_sources: set[str] | None = None,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[UnifiedNode], int, str | None]: ...

    def query_inventory(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        asset_entity_types: set[str],
        entity_types: set[str] | None = None,
        search: str = "",
        environment: str = "",
        provider: str = "",
        source: str = "",
        severity: str = "",
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]: ...

    def nodes_by_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[UnifiedNode]: ...

    def bfs_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source: str,
        max_depth: int = 4,
        traversable_only: bool = True,
    ) -> tuple[list[list[str]], set[str], bool, bool]:
        """Paths and reachable set from ``source``, plus how the walk was bounded.

        The last two elements are part of the answer, not diagnostics. Without
        them a caller cannot tell "these are all the reachable nodes" from
        "these are the first ``max_nodes`` we got to" (third element,
        budget-bounded) or "these are the ones within ``max_depth``" (fourth,
        depth-bounded, and only ever true when the frontier still had unwalked
        neighbours). Either way the surface downstream must not report the
        bound as the total.
        """
        ...

    def impact_of(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
        max_depth: int = 4,
    ) -> dict[str, Any] | None: ...

    def traverse_subgraph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        roots: list[str],
        direction: str = "forward",
        max_depth: int = 4,
        max_nodes: int = 500,
        max_edges: int = 10_000,
        deadline_monotonic: float | None = None,
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
        include_roots: bool = True,
    ) -> tuple[UnifiedGraph, dict[str, int], bool]: ...

    def attack_paths_for_sources(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source_ids: set[str],
    ) -> list[AttackPath]: ...

    def attack_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[str, str, list[AttackPath], int]: ...

    def incident_edges_page(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
        direction: str = "both",
        limit: int = 24,
        cursor: str | None = None,
        snapshot_generation: str | None = None,
    ) -> dict[str, Any] | None: ...

    def node_context(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
    ) -> dict[str, Any] | None: ...

    def compliance_summary(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        framework: str = "",
    ) -> dict[str, Any]: ...

    def save_preset(self, *, tenant_id: str, name: str, description: str, filters: dict[str, Any], created_at: str) -> None: ...

    def list_presets(self, *, tenant_id: str) -> list[dict[str, Any]]: ...

    def delete_preset(self, *, tenant_id: str, name: str) -> bool: ...
