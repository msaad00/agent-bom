"""Serve a derived current estate without changing immutable scan observations.

The projection reuses finding replacement semantics and the existing immutable
query engine in a private rebuildable cache. Its identifier describes a set of evidence revisions,
never a new scan. Explicit historical scan reads and all writes pass through.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from functools import lru_cache, wraps
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from fastapi import HTTPException

from agent_bom.api.findings_current import _finding_snapshot_jobs, scan_collection_incomplete_reasons, scan_evidence_authority_key
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import JobStatus
from agent_bom.api.neptune_graph import NeptuneGraphStore
from agent_bom.graph import UnifiedGraph

CURRENT_PREFIX = "current-estate:"
_READS = frozenset(
    {
        "load_graph",
        "load_rollup_graph",
        "iter_nodes",
        "iter_edges",
        "snapshot_identity",
        "snapshot_stats",
        "page_nodes",
        "edges_for_node_ids",
        "search_nodes",
        "query_inventory",
        "nodes_by_ids",
        "bfs_paths",
        "impact_of",
        "traverse_subgraph",
        "attack_paths_for_sources",
        "attack_paths",
        "incident_edges_page",
        "node_context",
        "compliance_summary",
        "evidence_manifest",
    }
)


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


class CurrentGraphStore:
    """Add default current scope to graph reads over any durable graph backend."""

    def __init__(self, graph_store: Any, job_store: Any) -> None:
        self._graph_store = graph_store
        self._job_store = job_store
        self._cache_directory = TemporaryDirectory(prefix="agent-bom-current-")
        self._cache_path = str(Path(self._cache_directory.name) / "projection.db")
        self._projection_store = SQLiteGraphStore(self._cache_path)
        self._lock = threading.RLock()
        self._coverage: dict[str, dict[str, Any]] = {}
        self._cache: dict[str, tuple[str, tuple[tuple[str, str], ...], str]] = {}

    def __getattr__(self, name: str) -> Any:
        method = getattr(self._graph_store, name)
        if not callable(method):
            return method
        if name == "latest_snapshot_id":

            @wraps(method)
            def latest(*args: Any, **kwargs: Any) -> str:
                if "snapshot_kind" in kwargs:
                    return str(method(*args, **kwargs))
                return self._current_id(str(kwargs.get("tenant_id") or "default")) or str(method(*args, **kwargs))

            return latest
        if name not in _READS:
            return method

        def execute(*args: Any, **kwargs: Any) -> Any:
            requested = str(kwargs.get("scan_id") or "")
            if not requested or requested.startswith(CURRENT_PREFIX):
                tenant = str(kwargs.get("tenant_id") or "default")
                kwargs["scan_id"] = self._current_id(tenant)
            projected = str(kwargs.get("scan_id", "")).startswith(CURRENT_PREFIX)
            reader = getattr(self._projection_store, name) if projected else method
            result = reader(*args, **kwargs)
            if isinstance(result, dict) and str(kwargs.get("scan_id", "")).startswith(CURRENT_PREFIX):
                result = {
                    **result,
                    "evidence_scope": "current_estate",
                    "collection_coverage": self._coverage.get(
                        str(kwargs["scan_id"]), {"status": "unknown", "reason": "Collection coverage is unknown."}
                    ),
                    "snapshot_generation": str(kwargs["scan_id"]).removeprefix(CURRENT_PREFIX),
                }
            return result

        @wraps(method)
        def read(*args: Any, **kwargs: Any) -> Any:
            # Retire rebuildable generations only after active readers finish.
            # Iterators hold the same lock while consuming their SQLite cursor.
            if name in {"iter_nodes", "iter_edges"}:

                def iterate() -> Any:
                    with self._lock:
                        yield from execute(*args, **kwargs)

                return iterate()
            with self._lock:
                return execute(*args, **kwargs)

        return read

    def _revisions(self, tenant: str, scan_ids: Any) -> tuple[tuple[str, str], ...]:
        return tuple(self._graph_store.snapshot_identity(tenant_id=tenant, scan_id=scan, for_paging=True) for scan in scan_ids)

    def _current_id(self, tenant: str) -> str:
        # Summary reads do not deserialize retained report blobs on warm pages.
        summaries = self._job_store.list_summary(tenant_id=tenant, status=JobStatus.DONE)
        summaries = sorted((row for row in summaries if not row.get("child_job_ids")), key=lambda row: row["job_id"])
        if not summaries:
            return ""  # Legacy graph-only stores retain their explicit latest view.
        revision_reader = getattr(self._job_store, "overview_evidence_revision", None)
        jobs = None
        if callable(revision_reader):
            evidence_revision = revision_reader(tenant)
        else:
            # Backends without a durable revision must fingerprint the evidence,
            # including authority changes that preserve the original timestamps.
            jobs = self._job_store.list_all(tenant_id=tenant)
            evidence_revision = _digest([job.model_dump(mode="json") for job in jobs])
        fingerprint = _digest([summaries, evidence_revision])
        with self._lock:
            cached = self._cache.get(tenant)
            if cached and cached[0] == fingerprint:
                revisions = self._revisions(tenant, (scan for scan, _ in cached[1]))
                if revisions == cached[1] and self._projection_store.snapshot_identity(tenant_id=tenant, scan_id=cached[2])[1]:
                    return cached[2]
            if jobs is None:
                jobs = [self._job_store.get(row["job_id"], tenant_id=tenant) for row in summaries]
            jobs = [job for job in jobs if job is not None and job.tenant_id == tenant]
            selected, _ = _finding_snapshot_jobs(jobs, since=None, require_authoritative_evidence=False)
            selected.sort(key=scan_evidence_authority_key)
            sources = list(dict.fromkeys(str((job.result or {}).get("scan_id") or job.job_id) for job in selected))
            revisions = self._revisions(tenant, sources)
            if any(not generation for _, generation in revisions):
                raise HTTPException(503, "Current estate has retained scans whose graph evidence is unavailable; retry later.")
            identity = CURRENT_PREFIX + _digest([tenant, fingerprint, revisions])[:32]
            if not self._projection_store.snapshot_identity(tenant_id=tenant, scan_id=identity)[1]:
                self._materialize(tenant, identity, selected, revisions)
            if callable(revision_reader) and revision_reader(tenant) != evidence_revision:
                self._projection_store.delete_snapshot(tenant_id=tenant, scan_id=identity)
                raise HTTPException(409, "Current estate changed during the read; restart the query.")
            if cached and cached[2] != identity:
                self._projection_store.delete_snapshot(tenant_id=tenant, scan_id=cached[2])
                self._coverage.pop(cached[2], None)
            if tenant not in self._cache and len(self._cache) >= 128:
                evicted_tenant = next(iter(self._cache))
                _, _, evicted_id = self._cache.pop(evicted_tenant)
                self._projection_store.delete_snapshot(tenant_id=evicted_tenant, scan_id=evicted_id)
                self._coverage.pop(evicted_id, None)
            reasons = sorted({reason for job in selected for reason in scan_collection_incomplete_reasons(job)})
            if len(self._coverage) >= 256:
                self._coverage.pop(next(iter(self._coverage)))
            self._coverage[identity] = {
                "status": "partial" if reasons else "unknown",
                "reason_codes": reasons,
                "reason": "Incomplete collection; prior evidence is retained for affected targets."
                if reasons
                else "Recorded inventory does not establish source collection or assessment coverage.",
            }
            self._cache[tenant] = fingerprint, revisions, identity
            return identity

    def _materialize(self, tenant: str, identity: str, selected: Any, revisions: tuple[tuple[str, str], ...]) -> None:
        created_at = max((scan_evidence_authority_key(job)[0] for job in selected), default="")
        graph = UnifiedGraph(scan_id=identity, tenant_id=tenant, created_at=created_at)
        for scan, _ in revisions:
            source = self._graph_store.load_graph(tenant_id=tenant, scan_id=scan)
            if source.tenant_id != tenant:
                raise ValueError("Current estate source tenant mismatch")
            for node in source.nodes.values():
                graph.add_node(node)
            for edge in source.edges:
                graph.add_edge(edge)
            graph.attack_paths.extend(source.attack_paths)
            graph.interaction_risks.extend(source.interaction_risks)
        if self._revisions(tenant, (scan for scan, _ in revisions)) != revisions:
            raise HTTPException(409, "Current estate evidence changed during assembly; retry the read.")
        try:
            self._projection_store.save_graph_streaming(
                tenant_id=tenant,
                scan_id=identity,
                nodes=graph.nodes.values(),
                edges=graph.edges,
                attack_paths=graph.attack_paths,
                interaction_risks=graph.interaction_risks,
                created_at=graph.created_at,
                snapshot_kind="correlation",
                correlation_id=identity,
                evidence_manifest_sha256="sha256:" + _digest(revisions),
                write_generation=identity.removeprefix(CURRENT_PREFIX),
            )
            # Identical source generations resolve to the same paging revision
            # across workers and restarts, even though each owns its own cache.
            with sqlite3.connect(self._cache_path) as conn:
                conn.execute(
                    "UPDATE graph_snapshots SET read_revision = ? WHERE tenant_id = ? AND scan_id = ?",
                    (identity.removeprefix(CURRENT_PREFIX), tenant, identity),
                )
        except ValueError:
            # Concurrent workers may commit this identical immutable projection.
            if not self._projection_store.snapshot_identity(tenant_id=tenant, scan_id=identity)[1]:
                raise


@lru_cache(maxsize=8)
def current_graph_store(graph_store: Any, job_store: Any) -> Any:
    if isinstance(graph_store, NeptuneGraphStore):
        return graph_store  # Keep the experimental backend's explicit capability errors.
    return CurrentGraphStore(graph_store, job_store)
