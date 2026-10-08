"""Serve a derived current estate without changing immutable scan observations.

The projection reuses finding replacement semantics and the existing immutable
query engine in a private rebuildable cache. Its identifier describes a set of evidence revisions,
never a new scan. Explicit historical scan reads and all writes pass through.

For durable backing stores the cache lives in the state directory, so a
restarted or sibling worker reuses a projection whose identity (and therefore
every source generation it was built from) is unchanged instead of rebuilding.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache, wraps
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from starlette.exceptions import HTTPException

from agent_bom import __version__
from agent_bom.api.finding_read_context import read_once
from agent_bom.api.findings_current import _finding_snapshot_jobs, scan_collection_incomplete_reasons, scan_evidence_authority_key
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import JobStatus
from agent_bom.api.neptune_graph import NeptuneGraphStore
from agent_bom.core.settings import env_raw
from agent_bom.graph import UnifiedGraph
from agent_bom.storage.state_home import state_dir

CURRENT_PREFIX = "current-estate:"
_PROJECTION_FORMAT = 1
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


def _durable_locator(graph_store: Any) -> str:
    if isinstance(graph_store, SQLiteGraphStore):
        return "sqlite:" + str(Path(graph_store._db_path).expanduser().resolve())
    if type(graph_store).__module__ == "agent_bom.api.postgres_graph":
        return "postgres:" + (env_raw("AGENT_BOM_POSTGRES_URL") or env_raw("AGENT_BOM_DB") or "").strip()
    return ""


def _durable_cache_path(graph_store: Any) -> Path | None:
    """Return a private per-backing-store cache file, or None when it cannot persist."""
    locator = _durable_locator(graph_store)
    if not locator:
        return None
    directory = state_dir() / "current-estate-cache"
    path = directory / f"{_digest(locator)[:24]}.db"
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
        os.chmod(path, 0o600)
    except OSError:
        return None
    return path


class _ProjectionLock:
    """Readers share the projection; resolve and retire are exclusive.

    A waiting writer blocks new readers so a steady read stream cannot starve a
    rebuild. A thread that already reads may read again, but it may not escalate:
    waiting for its own shared hold would deadlock, so that is a 409 instead.
    """

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._reads: dict[int, int] = {}
        self._writer: int | None = None
        self._writer_depth = 0
        self._waiting_writers = 0

    @contextmanager
    def shared(self) -> Iterator[None]:
        me = threading.get_ident()
        with self._cond:
            if self._writer != me and not self._reads.get(me):
                while self._writer is not None or self._waiting_writers:
                    self._cond.wait()
            self._reads[me] = self._reads.get(me, 0) + 1
        try:
            yield
        finally:
            with self._cond:
                if self._reads[me] == 1:
                    del self._reads[me]
                    self._cond.notify_all()
                else:
                    self._reads[me] -= 1

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        me = threading.get_ident()
        with self._cond:
            if self._writer == me:
                self._writer_depth += 1
            else:
                if self._reads.get(me):
                    raise HTTPException(409, "Current estate changed during the read; restart the query.")
                self._waiting_writers += 1
                try:
                    while self._writer is not None or self._reads:
                        self._cond.wait()
                finally:
                    self._waiting_writers -= 1
                self._writer, self._writer_depth = me, 1
        try:
            yield
        finally:
            with self._cond:
                self._writer_depth -= 1
                if not self._writer_depth:
                    self._writer = None
                    self._cond.notify_all()


class CurrentGraphStore:
    """Add default current scope to graph reads over any durable graph backend."""

    def __init__(self, graph_store: Any, job_store: Any) -> None:
        self._graph_store = graph_store
        self._job_store = job_store
        durable = _durable_cache_path(graph_store)
        self._cache_directory: TemporaryDirectory[str] | None = None
        if durable is None:
            self._cache_directory = TemporaryDirectory(prefix="agent-bom-current-")
            durable = Path(self._cache_directory.name) / "projection.db"
        self._cache_path = str(durable)
        self._projection_store = SQLiteGraphStore(self._cache_path)
        self._lock = _ProjectionLock()
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
                return self._current_id(str(kwargs.get("tenant_id") or "default")) or str(method(*args, **kwargs, snapshot_kind="scan"))

            return latest
        if name not in _READS:
            return method

        def execute(*args: Any, **kwargs: Any) -> Any:
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
            requested = str(kwargs.get("scan_id") or "")
            if requested and not requested.startswith(CURRENT_PREFIX):
                return method(*args, **kwargs)
            # Retire rebuildable generations only after active readers finish.
            # Iterators hold a shared read while consuming their SQLite cursor.
            if name in {"iter_nodes", "iter_edges"}:

                def iterate() -> Any:
                    with self._reading(kwargs) as resolved:
                        yield from execute(*args, **resolved)

                return iterate()
            with self._reading(kwargs) as resolved:
                return execute(*args, **resolved)

        return read

    @contextmanager
    def _reading(self, kwargs: dict[str, Any]) -> Iterator[dict[str, Any]]:
        tenant = str(kwargs.get("tenant_id") or "default")
        identity = self._resolved_id(tenant)
        with self._lock.shared():
            self._require_live(tenant, identity)
            yield {**kwargs, "scan_id": identity}

    def _revisions(self, tenant: str, scan_ids: Any) -> tuple[tuple[str, str], ...]:
        return tuple(self._graph_store.snapshot_identity(tenant_id=tenant, scan_id=scan, for_paging=True) for scan in scan_ids)

    def _available_sources(self, tenant: str, jobs: list[Any]) -> tuple[list[Any], tuple[tuple[str, str], ...], set[str]]:
        """Retain available target history while declaring missing graph evidence.

        Track absent snapshots in the revision key too: a late graph commit
        must invalidate the projection even if its job row never changes.
        Exceptions from the backing store deliberately propagate.
        """
        missing: dict[str, str] = {}
        reasons: set[str] = set()
        while True:
            eligible = [job for job in jobs if str((job.result or {}).get("scan_id") or job.job_id) not in missing]
            selected, _ = _finding_snapshot_jobs(eligible, since=None, require_authoritative_evidence=False)
            selected.sort(key=scan_evidence_authority_key)
            reasons.update(reason for job in selected for reason in scan_collection_incomplete_reasons(job))
            sources = list(dict.fromkeys(str((job.result or {}).get("scan_id") or job.job_id) for job in selected))
            revisions = self._revisions(tenant, sources)
            absent = {source: generation for source, generation in revisions if not generation}
            if not absent:
                return selected, tuple((*revisions, *sorted(missing.items()))), reasons
            missing.update(absent)
            reasons.add("graph_evidence_unavailable")

    def _resolved_id(self, tenant: str) -> str:
        return read_once((f"current-graph:{id(self)}", tenant), lambda: self._resolve_current_id(tenant))

    def _require_live(self, tenant: str, identity: str) -> None:
        # A concurrent request may retire this rebuildable projection. Never
        # turn that race into an empty graph or silently switch generations.
        if identity and not self._projection_store.snapshot_identity(tenant_id=tenant, scan_id=identity)[1]:
            raise HTTPException(409, "Current estate generation was retired; restart the query.")

    def _current_id(self, tenant: str) -> str:
        identity = self._resolved_id(tenant)
        with self._lock.shared():
            self._require_live(tenant, identity)
        return identity

    def _cached_live_id(self, tenant: str, fingerprint: str) -> str:
        cached = self._cache.get(tenant)
        if cached and cached[0] == fingerprint:
            revisions = self._revisions(tenant, (scan for scan, _ in cached[1]))
            if revisions == cached[1] and self._projection_store.snapshot_identity(tenant_id=tenant, scan_id=cached[2])[1]:
                return cached[2]
        return ""

    def _resolve_current_id(self, tenant: str) -> str:
        # Summary reads do not deserialize retained report blobs on warm pages.
        summaries = self._job_store.list_summary(tenant_id=tenant, status=JobStatus.DONE)
        summaries = sorted((row for row in summaries if not row.get("child_job_ids")), key=lambda row: row["job_id"])
        if not summaries and self._graph_store.snapshot_identity(tenant_id=tenant, for_paging=True)[0]:
            return ""  # Legacy graph-only stores retain their explicit latest view.
        revision_reader = getattr(self._job_store, "overview_evidence_revision", None)
        jobs = None
        if callable(revision_reader):
            evidence_revision = revision_reader(tenant)
        else:
            # Backends without a durable revision must fingerprint the evidence,
            # including authority changes that preserve the original timestamps.
            jobs = read_once(
                ("jobs", tenant),
                lambda: [job for job in self._job_store.list_all(tenant_id=tenant) if job.status == JobStatus.DONE and job.result],
            )
            evidence_revision = _digest([job.model_dump(mode="json") for job in jobs])
        fingerprint = _digest([summaries, evidence_revision])
        with self._lock.shared():
            if live := self._cached_live_id(tenant, fingerprint):
                return live
        with self._lock.exclusive():
            if live := self._cached_live_id(tenant, fingerprint):
                return live
            cached = self._cache.get(tenant)
            if jobs is None:
                jobs = [self._job_store.get(row["job_id"], tenant_id=tenant) for row in summaries]
            jobs = [job for job in jobs if job is not None and job.tenant_id == tenant]
            selected, revisions, coverage_reasons = self._available_sources(tenant, jobs)
            identity = CURRENT_PREFIX + _digest([_PROJECTION_FORMAT, __version__, tenant, fingerprint, revisions])[:32]
            if not self._reusable(tenant, identity):
                self._materialize(tenant, identity, selected, revisions)
            if callable(revision_reader) and revision_reader(tenant) != evidence_revision:
                self._projection_store.delete_snapshot(tenant_id=tenant, scan_id=identity)
                raise HTTPException(409, "Current estate changed during the read; restart the query.")
            if not cached or cached[2] != identity:
                self._retire_other_generations(tenant, identity)
            if tenant not in self._cache and len(self._cache) >= 128:
                evicted_tenant = next(iter(self._cache))
                _, _, evicted_id = self._cache.pop(evicted_tenant)
                self._projection_store.delete_snapshot(tenant_id=evicted_tenant, scan_id=evicted_id)
                self._coverage.pop(evicted_id, None)
            reasons = sorted(coverage_reasons)
            if len(self._coverage) >= 256:
                self._coverage.pop(next(iter(self._coverage)))
            self._coverage[identity] = {
                "status": "partial" if reasons else "unknown",
                "reason_codes": reasons,
                "reason": "Incomplete collection or graph evidence; available prior evidence is retained for affected targets."
                if reasons
                else "Recorded inventory does not establish source collection or assessment coverage.",
            }
            self._cache[tenant] = fingerprint, revisions, identity
            return identity

    def _reusable(self, tenant: str, identity: str) -> bool:
        """Trust a persisted projection only once its paging revision was stamped."""
        _, revision = self._projection_store.snapshot_identity(tenant_id=tenant, scan_id=identity, for_paging=True)
        if revision == identity.removeprefix(CURRENT_PREFIX):
            return True
        if revision:
            self._projection_store.delete_snapshot(tenant_id=tenant, scan_id=identity)
        return False

    def _retire_other_generations(self, tenant: str, identity: str) -> None:
        # Other workers sharing this cache may have left superseded generations.
        for row in self._projection_store.list_snapshots(tenant_id=tenant, limit=1000):
            scan_id = str(row.get("scan_id") or "")
            if scan_id.startswith(CURRENT_PREFIX) and scan_id != identity:
                self._projection_store.delete_snapshot(tenant_id=tenant, scan_id=scan_id)
                self._coverage.pop(scan_id, None)

    def _materialize(self, tenant: str, identity: str, selected: Any, revisions: tuple[tuple[str, str], ...]) -> None:
        created_at = max((scan_evidence_authority_key(job)[0] for job in selected), default="")
        graph = UnifiedGraph(scan_id=identity, tenant_id=tenant, created_at=created_at)
        for scan, generation in revisions:
            if not generation:
                continue
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
