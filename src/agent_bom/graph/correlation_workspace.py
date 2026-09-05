"""Disk-backed accumulator for bounded-memory graph correlation.

The durable graph store remains the source of truth and the completed output is
still committed atomically by its owning correlation run.  This private
workspace only keeps source observations off heap while exact-identity groups
are merged; it is deleted whether the run succeeds or fails.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from itertools import groupby
from pathlib import Path
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation import (
    CorrelationMergeResult,
    CorrelationSnapshot,
    _digest,
    _EdgeObservation,
    _merge_edge,
    _merge_node,
    _NodeObservation,
    _relationship_value,
    _timestamp_instant,
    correlation_identity,
)
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode

_WRITE_BATCH_SIZE = 1000


class CorrelationMergeBudgetError(RuntimeError):
    """The exact merged output exceeded a configured node or edge bound."""


def _node_from_json(payload: str) -> UnifiedNode:
    raw = json.loads(payload)
    node = UnifiedNode.from_dict(raw)
    # UnifiedNode.from_dict helpfully projects canonical_id into attributes.
    # Correlation must retain the source attributes byte-for-byte instead.
    node.attributes = dict(raw.get("attributes") or {})
    return node


class CorrelationMergeWorkspace:
    """Accumulate source observations on disk, then materialize one output.

    Peak heap is one loaded source graph plus the final correlated graph.  It no
    longer scales with the sum of every input graph plus the final output.
    """

    def __init__(
        self,
        *,
        correlation_id: str,
        tenant_id: str,
        created_at: str,
        max_output_nodes: int,
        max_output_edges: int,
    ) -> None:
        fd, name = tempfile.mkstemp(prefix="abom-correlation-", suffix=".db")
        os.close(fd)
        self._path = Path(name)
        self._conn = sqlite3.connect(str(self._path))
        self._correlation_id = correlation_id
        self._tenant_id = tenant_id
        self._created_at = created_at
        self._max_output_nodes = max_output_nodes
        self._max_output_edges = max_output_edges
        self._snapshots: dict[str, dict[str, Any]] = {}
        self._snapshot_stubs: dict[str, CorrelationSnapshot] = {}
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            PRAGMA journal_mode=MEMORY;
            PRAGMA synchronous=OFF;
            CREATE TABLE node_groups (
                entity_type TEXT NOT NULL,
                identity TEXT NOT NULL,
                PRIMARY KEY (entity_type, identity)
            );
            CREATE TABLE node_observations (
                entity_type TEXT NOT NULL,
                identity TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                snapshot_created_at TEXT NOT NULL,
                node_id TEXT NOT NULL,
                identity_basis TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (entity_type, identity, scan_id, node_id)
            );
            CREATE INDEX idx_correlation_node_group
                ON node_observations(entity_type, identity);
            CREATE TABLE edge_groups (
                source_type TEXT NOT NULL,
                source_identity TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_identity TEXT NOT NULL,
                relationship TEXT NOT NULL,
                PRIMARY KEY (
                    source_type, source_identity, target_type,
                    target_identity, relationship
                )
            );
            CREATE TABLE edge_observations (
                source_type TEXT NOT NULL,
                source_identity TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_identity TEXT NOT NULL,
                relationship TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                snapshot_created_at TEXT NOT NULL,
                edge_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (
                    source_type, source_identity, target_type,
                    target_identity, relationship, scan_id, edge_id
                )
            );
            CREATE INDEX idx_correlation_edge_group
                ON edge_observations(
                    source_type, source_identity, target_type,
                    target_identity, relationship
                );
            CREATE TABLE merged_nodes (
                entity_type TEXT NOT NULL,
                identity TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (entity_type, identity)
            );
            CREATE INDEX idx_correlation_candidate_id
                ON merged_nodes(candidate_id);
            """
        )

    def add_snapshot(self, snapshot: CorrelationSnapshot) -> None:
        if snapshot.scan_id in self._snapshots:
            raise ValueError("Correlation snapshot IDs must be unique")
        if snapshot.tenant_id != self._tenant_id or snapshot.graph.tenant_id != self._tenant_id:
            raise ValueError("Correlation inputs must belong to the same tenant")
        if not snapshot.graph.nodes:
            raise ValueError("Correlation inputs must be non-empty graph snapshots")

        source_to_key: dict[str, tuple[str, str]] = {}
        with self._conn:
            node_group_rows: list[tuple[str, str]] = []
            node_observation_rows: list[tuple[str, str, str, str, str, str, str]] = []

            def flush_nodes() -> None:
                self._conn.executemany(
                    "INSERT OR IGNORE INTO node_groups(entity_type, identity) VALUES (?, ?)",
                    node_group_rows,
                )
                self._conn.executemany(
                    """
                    INSERT INTO node_observations(
                        entity_type, identity, scan_id, snapshot_created_at,
                        node_id, identity_basis, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    node_observation_rows,
                )
                node_group_rows.clear()
                node_observation_rows.clear()

            for node in sorted(snapshot.graph.nodes.values(), key=lambda item: item.id):
                entity_type, identity, basis = correlation_identity(node, scan_id=snapshot.scan_id)
                source_to_key[node.id] = (entity_type, identity)
                node_group_rows.append((entity_type, identity))
                node_observation_rows.append(
                    (
                        entity_type,
                        identity,
                        snapshot.scan_id,
                        snapshot.created_at,
                        node.id,
                        basis,
                        json.dumps(node.to_dict(), default=str, separators=(",", ":")),
                    )
                )
                if len(node_group_rows) >= _WRITE_BATCH_SIZE:
                    flush_nodes()
            flush_nodes()
            node_count = int(self._conn.execute("SELECT COUNT(*) FROM node_groups").fetchone()[0])
            if node_count > self._max_output_nodes:
                raise CorrelationMergeBudgetError("node_limit")

            edge_group_rows: list[tuple[str, str, str, str, str]] = []
            edge_observation_rows: list[tuple[str, str, str, str, str, str, str, str, str]] = []

            def flush_edges() -> None:
                self._conn.executemany(
                    """
                    INSERT OR IGNORE INTO edge_groups(
                        source_type, source_identity, target_type,
                        target_identity, relationship
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    edge_group_rows,
                )
                self._conn.executemany(
                    """
                    INSERT INTO edge_observations(
                        source_type, source_identity, target_type,
                        target_identity, relationship, scan_id,
                        snapshot_created_at, edge_id, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    edge_observation_rows,
                )
                edge_group_rows.clear()
                edge_observation_rows.clear()

            for edge in sorted(
                snapshot.graph.edges,
                key=lambda item: (item.source, item.target, _relationship_value(item)),
            ):
                source_key = source_to_key.get(edge.source)
                target_key = source_to_key.get(edge.target)
                if source_key is None or target_key is None:
                    continue
                relationship = _relationship_value(edge)
                group = (*source_key, *target_key, relationship)
                edge_group_rows.append(group)
                edge_observation_rows.append(
                    (
                        *group,
                        snapshot.scan_id,
                        snapshot.created_at,
                        edge.id,
                        json.dumps(edge.to_dict(), default=str, separators=(",", ":")),
                    )
                )
                if len(edge_group_rows) >= _WRITE_BATCH_SIZE:
                    flush_edges()
            flush_edges()
            edge_count = int(self._conn.execute("SELECT COUNT(*) FROM edge_groups").fetchone()[0])
            if edge_count > self._max_output_edges:
                raise CorrelationMergeBudgetError("edge_limit")

        self._snapshots[snapshot.scan_id] = {
            "scan_id": snapshot.scan_id,
            "created_at": snapshot.created_at,
            "digest": snapshot.digest,
            "node_count": len(snapshot.graph.nodes),
            "edge_count": len(snapshot.graph.edges),
            "data_sources": sorted({source for node in snapshot.graph.nodes.values() for source in node.data_sources}),
        }

    def _snapshot_stub(self, scan_id: str, created_at: str) -> CorrelationSnapshot:
        cached = self._snapshot_stubs.get(scan_id)
        if cached is not None:
            return cached
        metadata = self._snapshots[scan_id]
        snapshot = CorrelationSnapshot(
            scan_id=scan_id,
            tenant_id=self._tenant_id,
            created_at=created_at,
            graph=UnifiedGraph(scan_id=scan_id, tenant_id=self._tenant_id, created_at=created_at),
            digest=str(metadata["digest"]),
        )
        self._snapshot_stubs[scan_id] = snapshot
        return snapshot

    def finish(self) -> CorrelationMergeResult:
        if len(self._snapshots) < 2:
            raise ValueError("Correlation requires at least 2 graph snapshots")
        if len(self._snapshots) > 32:
            raise ValueError("Correlation accepts at most 32 graph snapshots")

        node_conflicts = 0
        node_rows = self._conn.execute(
            """
            SELECT entity_type, identity, scan_id, snapshot_created_at,
                   identity_basis, payload
            FROM node_observations
            ORDER BY entity_type, identity
            """
        )
        for (entity_type, identity), rows in groupby(node_rows, key=lambda row: (str(row[0]), str(row[1]))):
            node_observations = [
                _NodeObservation(
                    snapshot=self._snapshot_stub(str(scan_id), str(snapshot_created_at)),
                    node=_node_from_json(str(payload)),
                    identity_basis=str(identity_basis),
                )
                for _entity_type, _identity, scan_id, snapshot_created_at, identity_basis, payload in rows
            ]
            merged = _merge_node(node_observations)
            if merged.attributes.get("correlation", {}).get("conflict_fields"):
                node_conflicts += 1
            self._conn.execute(
                """
                INSERT INTO merged_nodes(entity_type, identity, candidate_id, payload)
                VALUES (?, ?, ?, ?)
                """,
                (
                    entity_type,
                    identity,
                    merged.id,
                    json.dumps(merged.to_dict(), default=str, separators=(",", ":")),
                ),
            )
        self._conn.commit()

        output = UnifiedGraph(
            scan_id=self._correlation_id,
            tenant_id=self._tenant_id,
            created_at=self._created_at,
        )
        output_id_by_key: dict[tuple[str, str], str] = {}
        for entity_type, identity, candidate_id, payload, duplicate_count in self._conn.execute(
            """
            SELECT m.entity_type, m.identity, m.candidate_id, m.payload, counts.n
            FROM merged_nodes m
            JOIN (
                SELECT candidate_id, COUNT(*) AS n
                FROM merged_nodes GROUP BY candidate_id
            ) counts ON counts.candidate_id = m.candidate_id
            ORDER BY m.entity_type, m.identity
            """
        ):
            node = _node_from_json(str(payload))
            if int(duplicate_count) > 1:
                key = (str(entity_type), str(identity))
                node.id = f"correlated:{key[0]}:{_digest(key).removeprefix('sha256:')}"
            output.add_node(node)
            output_id_by_key[(str(entity_type), str(identity))] = node.id

        edge_conflicts = 0
        edge_rows = self._conn.execute(
            """
            SELECT source_type, source_identity, target_type, target_identity,
                   relationship, scan_id, snapshot_created_at, payload
            FROM edge_observations
            ORDER BY source_type, source_identity, target_type,
                     target_identity, relationship
            """
        )
        for group, rows in groupby(edge_rows, key=lambda row: tuple(str(value) for value in row[:5])):
            source_type, source_identity, target_type, target_identity, relationship = group
            edge_observations = [
                _EdgeObservation(
                    snapshot=self._snapshot_stub(str(row[5]), str(row[6])),
                    edge=UnifiedEdge.from_dict(json.loads(str(row[7]))),
                )
                for row in rows
            ]
            edge = _merge_edge(
                edge_observations,
                source_id=output_id_by_key[(source_type, source_identity)],
                target_id=output_id_by_key[(target_type, target_identity)],
                correlation_id=self._correlation_id,
            )
            if edge.provenance.get("correlation", {}).get("conflict_fields"):
                edge_conflicts += 1
            output.add_edge(edge)

        ordered_snapshots = sorted(
            self._snapshots.values(),
            key=lambda item: (_timestamp_instant(str(item["created_at"])), str(item["scan_id"])),
        )
        manifest = {
            "schema_version": "agent-bom.graph-correlation.v1",
            "identity_version": "runtime-occurrence.v2",
            "correlation_id": self._correlation_id,
            "tenant_id": self._tenant_id,
            "created_at": output.created_at,
            "input_snapshots": ordered_snapshots,
            "output": {
                "scan_id": self._correlation_id,
                "node_count": len(output.nodes),
                "edge_count": len(output.edges),
                "node_conflict_count": node_conflicts,
                "edge_conflict_count": edge_conflicts,
            },
        }
        return CorrelationMergeResult(graph=output, manifest=manifest, manifest_sha256=_digest(manifest))

    def close(self) -> None:
        self._conn.close()
        self._path.unlink(missing_ok=True)

    def __enter__(self) -> CorrelationMergeWorkspace:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()


__all__ = ["CorrelationMergeBudgetError", "CorrelationMergeWorkspace"]
