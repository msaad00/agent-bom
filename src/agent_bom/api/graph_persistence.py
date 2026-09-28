"""Graph snapshot persistence service for scan and pushed-result workflows.

Owns enrichment, bounded writes and post-commit notifications. The caller supplies
its store factory; storage failures propagate, while optional enrichment and
notification failures retain the existing best-effort behavior.
"""

from __future__ import annotations

import contextlib
import logging
import os
import threading
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from agent_bom import __version__
from agent_bom.security import sanitize_error, sanitize_text

if TYPE_CHECKING:
    from agent_bom.api.models import ScanJob
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.delta_digest import PriorSnapshotDigest
    from agent_bom.graph.ports import GraphStoreProtocol

# Preserve the existing operator-facing log category across the extraction.
_logger = logging.getLogger("agent_bom.api.pipeline")


def _record_graph_persistence(
    job: ScanJob,
    *,
    status: str,
    scan_id: str | None = None,
    nodes: int | None = None,
    edges: int | None = None,
    lock: threading.Lock | None = None,
) -> None:
    """Expose graph persistence truth without leaking backend exceptions."""

    def _record() -> None:
        result = getattr(job, "result", None)
        if not isinstance(result, dict):
            return
        current = result.get("graph_persistence")
        # Delivery or post-persist bookkeeping can fail after the snapshot has
        # committed. Never overwrite durable evidence with a false failure.
        if status == "failed" and isinstance(current, dict) and current.get("status") == "persisted":
            return
        evidence: dict[str, Any] = {
            "status": status,
            "scan_id": scan_id or job.job_id,
        }
        if nodes is not None:
            evidence["nodes"] = nodes
        if edges is not None:
            evidence["edges"] = edges
        result["graph_persistence"] = evidence

    if lock is None:
        _record()
    else:
        with lock:
            _record()


def _graph_build_workspace_enabled() -> bool:
    """Opt-in flag for routing persistence through the build workspace.

    Default-off so the shipped persist path is byte-for-byte unchanged. When on,
    the persist streams from the storage-backed workspace instead of the
    materialised graph.

    When the store-backed producer is active, this consumer path is skipped
    (the streamed save already pages out of the container).
    """
    return os.environ.get("AGENT_BOM_GRAPH_BUILD_WORKSPACE", "").strip().lower() in ("1", "true", "yes", "on")


_DEFAULT_STORE_BACKED_MIN_ENTITIES = 5_000


def _estimate_graph_entities(report_json: Mapping[str, Any] | dict[str, Any]) -> int:
    """Cheap O(report) entity estimate for the store-backed auto gate.

    Counts agents, nested MCP servers/packages, top-level packages, findings,
    and blast-radius entries already resident in ``report_json``. Under-approximates
    final graph node count (overlays mint extras) — acceptable for a heuristic.
    """
    total = 0
    agents = report_json.get("agents") or []
    if isinstance(agents, list):
        total += len(agents)
        for agent in agents:
            if not isinstance(agent, dict):
                continue
            servers = agent.get("mcp_servers") or []
            if not isinstance(servers, list):
                continue
            total += len(servers)
            for server in servers:
                if isinstance(server, dict):
                    packages = server.get("packages") or []
                    if isinstance(packages, list):
                        total += len(packages)
    for key in ("packages", "findings"):
        value = report_json.get(key) or []
        if isinstance(value, list):
            total += len(value)
    blast = report_json.get("blast_radius") or []
    if isinstance(blast, list):
        total += len(blast)
    elif isinstance(blast, dict):
        total += len(blast)
    return total


def _graph_store_backed_build_enabled(report_json: Mapping[str, Any] | dict[str, Any] | None = None) -> bool:
    """Whether to build the graph into a store-backed container.

    Tri-state:

    * ``AGENT_BOM_GRAPH_STORE_BACKED_BUILD=1/true/on`` — force on
    * ``=0/false/off`` — force off (wins over the size heuristic)
    * unset — auto-on when ``report_json`` entity estimate is at or above
      ``AGENT_BOM_GRAPH_STORE_BACKED_MIN_ENTITIES`` (default 5000)

    When on, ``persist_graph_snapshot`` builds the correlated graph into a
    per-build :class:`~agent_bom.graph.store_backed.StoreBackedUnifiedGraph` on a
    throwaway private SQLite workspace (never the shared Postgres workspace
    tables). Small local / below-threshold scans keep the in-RAM producer.
    """
    raw = os.environ.get("AGENT_BOM_GRAPH_STORE_BACKED_BUILD", "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    if report_json is None:
        return False
    threshold_raw = os.environ.get("AGENT_BOM_GRAPH_STORE_BACKED_MIN_ENTITIES", "").strip()
    try:
        threshold = int(threshold_raw) if threshold_raw else _DEFAULT_STORE_BACKED_MIN_ENTITIES
    except ValueError:
        threshold = _DEFAULT_STORE_BACKED_MIN_ENTITIES
    if threshold < 1:
        threshold = _DEFAULT_STORE_BACKED_MIN_ENTITIES
    return _estimate_graph_entities(report_json) >= threshold


def _persist_via_build_workspace(graph_store: GraphStoreProtocol, graph: UnifiedGraph, *, write_generation: str = "") -> dict[str, int]:
    """Stream a built graph through the bounded workspace into the store.

    Produces a snapshot byte-identical to the direct streamed save; the workspace
    holds only a bounded batch in memory while it re-emits nodes/edges. Attack
    paths and interaction risks retain their existing in-memory representation.
    """
    from agent_bom.graph.build_workspace import open_graph_build_workspace

    with open_graph_build_workspace(tenant_id=graph.tenant_id, workspace_id=graph.scan_id) as workspace:
        workspace.add_nodes(graph.nodes.values())
        workspace.add_edges(graph.edges)
        counts: dict[str, int] = graph_store.save_graph_streaming(
            scan_id=graph.scan_id,
            tenant_id=graph.tenant_id,
            nodes=workspace.iter_nodes(),
            edges=workspace.iter_edges(),
            attack_paths=graph.attack_paths,
            interaction_risks=graph.interaction_risks,
            analysis_status=graph.analysis_status,
            created_at=graph.created_at,
            **({"write_generation": write_generation} if write_generation else {}),
        )
        return counts


def _with_cost_records(report_json: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    """Overlay tenant costs on a shallow copy; leave the persisted report intact."""
    try:
        from agent_bom.api.cost_store import get_cost_store, graph_cost_rollup

        cost_records = graph_cost_rollup(get_cost_store(), tenant_id)
        if cost_records:
            return {**report_json, "llm_cost_records": cost_records}
    except Exception as exc:  # noqa: BLE001
        _logger.debug("graph cost rollup skipped: %s", sanitize_text(exc))
    return report_json


def _build_container(*, store_backed: bool, tenant_id: str, scan_id: str) -> contextlib.AbstractContextManager[UnifiedGraph | None]:
    if store_backed:
        from agent_bom.graph.store_backed import open_store_backed_unified_graph

        # Private per-build SQLite even when the destination is PostgreSQL.
        return open_store_backed_unified_graph(tenant_id=tenant_id, scan_id=scan_id, backend="sqlite")
    return contextlib.nullcontext(None)


def _enrich_before_persist(report_json: dict[str, Any], graph: UnifiedGraph, tenant_id: str) -> None:
    try:
        from agent_bom.graph.asset_entity import link_report_findings_to_graph

        link_report_findings_to_graph(report_json, graph)
    except Exception as link_exc:  # noqa: BLE001 — never fail persist on FK stamping
        _logger.debug("finding↔node persist linking skipped: %s", sanitize_text(link_exc))
    try:
        from agent_bom.cloud.runtime_workload_evidence import (
            RuntimeWorkloadEvidenceIndex,
            enrich_graph_workload_runtime_evidence,
        )
        from agent_bom.cloud.runtime_workload_evidence_store import get_runtime_workload_evidence_store

        wl_index = RuntimeWorkloadEvidenceIndex.from_store(get_runtime_workload_evidence_store(), tenant_id)
        enrich_graph_workload_runtime_evidence(graph, wl_index)
    except Exception as runtime_exc:  # noqa: BLE001 — never fail persist on enrich
        _logger.debug("workload runtime evidence graph enrich skipped: %s", sanitize_text(runtime_exc))


def _write_snapshot(
    graph: UnifiedGraph,
    *,
    tenant_id: str,
    scan_id: str,
    store_factory: Callable[[], GraphStoreProtocol],
    store_backed: bool,
    write_generation: str,
) -> tuple[dict[str, int], PriorSnapshotDigest | None]:
    """Scope the store and prior digest to the tenant; never load a full prior graph."""
    from agent_bom.api.tenant_worker import tenant_bound_context

    if graph.tenant_id != tenant_id:
        raise ValueError("Graph tenant must match the persistence tenant")
    with tenant_bound_context(tenant_id):
        prior_digest = None
        graph_store = store_factory()
        previous_scan_id = graph_store.latest_snapshot_id(tenant_id=tenant_id, snapshot_kind="scan")
        if previous_scan_id and previous_scan_id != scan_id:
            prior_digest = graph_store.prior_delta_digest(tenant_id=tenant_id, scan_id=previous_scan_id)
        # The store-backed producer already pages out of its own container.
        if (not store_backed) and _graph_build_workspace_enabled():
            counts = _persist_via_build_workspace(graph_store, graph, write_generation=write_generation)
        else:
            counts = graph_store.save_graph_streaming(
                scan_id=graph.scan_id,
                tenant_id=graph.tenant_id,
                nodes=graph.nodes.values(),
                edges=graph.edges,
                attack_paths=graph.attack_paths,
                interaction_risks=graph.interaction_risks,
                analysis_status=graph.analysis_status,
                created_at=graph.created_at,
                **({"write_generation": write_generation} if write_generation else {}),
            )
        return counts, prior_digest


def _notify_after_commit(
    job: ScanJob,
    graph: UnifiedGraph,
    prior_digest: PriorSnapshotDigest | None,
    *,
    tenant_id: str,
    scan_id: str,
    lock: threading.Lock | None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    from agent_bom.graph.delta_digest import compute_delta_alerts_from_digest
    from agent_bom.graph.webhooks import dispatch_delta_alerts

    try:
        alerts = compute_delta_alerts_from_digest(prior_digest, graph)
        delivery = dispatch_delta_alerts(alerts, product_version=__version__, tenant_id=tenant_id) if alerts else None
        return alerts, delivery
    except Exception as alert_exc:  # noqa: BLE001 — alerting must never fail graph persistence
        _logger.warning(
            "Graph delta alerting failed for scan=%s tenant=%s: %s",
            scan_id,
            tenant_id,
            sanitize_text(sanitize_error(alert_exc, generic=True)),
        )
        if lock:
            with lock:
                job.progress.append("Graph delta alerting failed; snapshot persisted without delta notifications")
        return [], None


def _record_completion(
    job: ScanJob,
    *,
    tenant_id: str,
    scan_id: str,
    node_count: int,
    edge_count: int,
    alerts: list[dict[str, Any]],
    delivery: dict[str, Any] | None,
    lock: threading.Lock | None,
) -> None:
    _logger.info(
        "Graph persisted for scan=%s tenant=%s nodes=%d edges=%d delta_alerts=%d delta_delivered=%d",
        scan_id,
        tenant_id,
        node_count,
        edge_count,
        len(alerts),
        delivery["delivered"] if delivery else 0,
    )
    if lock:
        with lock:
            job.progress.append(f"Graph persisted: {node_count} nodes, {edge_count} edges")
            if alerts:
                job.progress.append(f"Graph delta alerts: {len(alerts)}")
                if delivery and delivery["configured"]:
                    summary = (
                        f"Graph delta delivery: {delivery['delivered']}/{delivery['attempted']} "
                        f"via {delivery['outbound_channels']} outbound channel(s)"
                    )
                    job.progress.append(summary)
                else:
                    job.progress.append(f"Graph delta export ready: {delivery['ocsf_event_count'] if delivery else 0} OCSF event(s)")


def persist_graph_snapshot(
    job: ScanJob,
    report_json: dict[str, Any],
    *,
    store_factory: Callable[[], GraphStoreProtocol],
    lock: threading.Lock | None = None,
    write_generation: str = "",
) -> None:
    """Persist a scan graph, then publish notifications without undoing its receipt.

    Build/write failures propagate to the caller's scan or ingestion failure
    handler. Optional enrichment and delta notification failures are best-effort;
    neither suppresses a successful write nor marks missing evidence as clean.
    """
    from agent_bom.api.tenant_worker import tenant_bound_context
    from agent_bom.core.tenancy import require_explicit_tenant_id
    from agent_bom.graph.builder import build_unified_graph_from_report

    tenant_id = require_explicit_tenant_id(job.tenant_id)
    with tenant_bound_context(tenant_id):
        scan_id = report_json.get("scan_id") or job.job_id
        graph_input = _with_cost_records(report_json, tenant_id)
        store_backed = _graph_store_backed_build_enabled(report_json)
        with _build_container(store_backed=store_backed, tenant_id=tenant_id, scan_id=scan_id) as container:
            graph = build_unified_graph_from_report(graph_input, scan_id=scan_id, tenant_id=tenant_id, container=container)
            _enrich_before_persist(report_json, graph, tenant_id)
            counts, prior_digest = _write_snapshot(
                graph,
                tenant_id=tenant_id,
                scan_id=scan_id,
                store_factory=store_factory,
                store_backed=store_backed,
                write_generation=write_generation,
            )
            node_count = counts.get("nodes", len(graph.nodes))
            edge_count = counts.get("edges", len(graph.edges))
            _record_graph_persistence(job, status="persisted", scan_id=scan_id, nodes=node_count, edges=edge_count, lock=lock)
            alerts, delivery = _notify_after_commit(job, graph, prior_digest, tenant_id=tenant_id, scan_id=scan_id, lock=lock)
            _record_completion(
                job,
                tenant_id=tenant_id,
                scan_id=scan_id,
                node_count=node_count,
                edge_count=edge_count,
                alerts=alerts,
                delivery=delivery,
                lock=lock,
            )
