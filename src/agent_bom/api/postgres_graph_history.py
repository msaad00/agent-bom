"""Snapshot diffs, temporal edge history and evidence manifests for the Postgres graph store."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Sequence

from agent_bom.db.graph_store import (
    graph_retention_policy,
    normalize_graph_tenant_id,
)
from agent_bom.graph.observation_scope import observation_scope

from .postgres_common import (
    _tenant_connection,
)
from .postgres_graph_snapshots import PostgresGraphSnapshotsMixin
from .postgres_graph_support import (
    _GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS,
    _GRAPH_EVIDENCE_INCLUDED_TABLES,
    _decode_json_array,
    _decode_json_object,
    _diff_summary_counts,
)


class PostgresGraphHistoryMixin(PostgresGraphSnapshotsMixin):
    """Compare snapshots and expose the temporal and evidence history of a graph."""

    def diff_snapshots(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]:
        from agent_bom.graph.drift_attributes import attribute_deltas, node_diff_metadata, node_snapshot_changed

        tenant_id = normalize_graph_tenant_id(tenant_id)

        def _load_nodes(conn: Any, scan_id: str) -> dict[str, dict[str, Any]]:
            loaded: dict[str, dict[str, Any]] = {}
            for row in conn.execute(
                """
                SELECT id, entity_type, label, status, severity, severity_id, risk_score,
                       attributes, compliance_tags
                FROM graph_nodes
                WHERE scan_id = %s AND tenant_id = %s
                """,
                (scan_id, tenant_id),
            ).fetchall():
                loaded[row[0]] = node_diff_metadata(
                    node_id=row[0],
                    entity_type=row[1],
                    label=row[2],
                    status=row[3],
                    severity=row[4],
                    severity_id=int(row[5] or 0),
                    risk_score=float(row[6] or 0.0),
                    attributes=_decode_json_object(row[7], field="node attributes"),
                    compliance_tags=_decode_json_array(row[8], field="node compliance tags"),
                )
            return loaded

        with _tenant_connection(self._pool) as conn:
            old_nodes = _load_nodes(conn, scan_id_old)
            new_nodes = _load_nodes(conn, scan_id_new)
            old_ids, new_ids = set(old_nodes), set(new_nodes)
            old_edges = {
                (row[0], row[1], row[2])
                for row in conn.execute(
                    "SELECT source_id, target_id, relationship FROM graph_edges WHERE scan_id = %s AND tenant_id = %s",
                    (scan_id_old, tenant_id),
                ).fetchall()
            }
            new_edges = {
                (row[0], row[1], row[2])
                for row in conn.execute(
                    "SELECT source_id, target_id, relationship FROM graph_edges WHERE scan_id = %s AND tenant_id = %s",
                    (scan_id_new, tenant_id),
                ).fetchall()
            }
            attribute_delta_index: dict[str, list[dict[str, Any]]] = {}
            nodes_changed: list[str] = []
            for nid in sorted(old_ids & new_ids):
                if not node_snapshot_changed(old_nodes[nid], new_nodes[nid]):
                    continue
                nodes_changed.append(nid)
                deltas = attribute_deltas(old_nodes[nid], new_nodes[nid])
                if deltas:
                    attribute_delta_index[nid] = deltas
            return {
                "nodes_added": [new_nodes[nid] for nid in sorted(new_ids - old_ids)],
                "nodes_removed": [old_nodes[nid] for nid in sorted(old_ids - new_ids)],
                "nodes_changed": nodes_changed,
                "attribute_deltas": attribute_delta_index,
                "edges_added": sorted(new_edges - old_edges),
                "edges_removed": sorted(old_edges - new_edges),
                "edges_changed": self.changed_edges_between_scans(scan_id_old, scan_id_new, tenant_id=tenant_id)["edges_changed"],
            }

    @staticmethod
    def _edge_history_dict(row: Sequence[Any]) -> dict[str, Any]:
        return {
            "source_id": row[0],
            "target_id": row[1],
            "relationship": row[2],
            "direction": row[3],
            "weight": float(row[4] or 0.0),
            "traversable": bool(row[5]),
            "first_seen": row[6],
            "last_seen": row[7],
            "valid_from": row[8] or row[6],
            "valid_to": row[9],
            "confidence": float(row[10] if row[10] is not None else 1.0),
            "provenance": _decode_json_object(row[11], field="edge provenance"),
            "source_scan_id": row[12] or row[16],
            "source_run_id": row[13] or "",
            "evidence": _decode_json_object(row[14], field="edge evidence"),
            "activity_id": int(row[15] or 1),
            "scan_id": row[16],
            "tenant_id": row[17],
        }

    @staticmethod
    def _edge_change_fingerprint(edge: dict[str, Any]) -> dict[str, Any]:
        return {
            "direction": edge["direction"],
            "weight": edge["weight"],
            "traversable": edge["traversable"],
            "confidence": edge["confidence"],
            "provenance": edge["provenance"],
            "evidence": edge["evidence"],
            "activity_id": edge["activity_id"],
        }

    def active_edges_at(self, at: str, *, tenant_id: str = "") -> list[dict[str, Any]]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                """
                SELECT ge.source_id, ge.target_id, ge.relationship, ge.direction, ge.weight, ge.traversable,
                       ge.first_seen, ge.last_seen, ge.valid_from, ge.valid_to, ge.confidence, ge.provenance,
                       ge.source_scan_id, ge.source_run_id, ge.evidence, ge.activity_id, ge.scan_id, ge.tenant_id,
                       ns.attributes, ns.dimensions, nt.attributes, nt.dimensions
                FROM graph_edges ge
                JOIN graph_snapshots gs ON gs.tenant_id = ge.tenant_id AND gs.scan_id = ge.scan_id
                LEFT JOIN graph_nodes ns ON ns.tenant_id = ge.tenant_id AND ns.scan_id = ge.scan_id AND ns.id = ge.source_id
                LEFT JOIN graph_nodes nt ON nt.tenant_id = ge.tenant_id AND nt.scan_id = ge.scan_id AND nt.id = ge.target_id
                WHERE ge.tenant_id = %s
                  AND gs.created_at <= %s
                  AND COALESCE(NULLIF(ge.valid_from, ''), ge.first_seen) <= %s
                  AND (ge.valid_to IS NULL OR ge.valid_to = '' OR ge.valid_to > %s)
                ORDER BY gs.created_at ASC, ge.scan_id ASC
                """,
                (tenant_id, at, at, at),
            ).fetchall()
        active_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
        for row in rows:
            edge = self._edge_history_dict(row)
            scope = observation_scope(edge["evidence"], row[18], row[19], row[20], row[21])
            namespace = ("recorded", *scope) if scope is not None else ("snapshot", edge["scan_id"])
            active_by_key[(namespace, edge["source_id"], edge["target_id"], edge["relationship"])] = edge
        return [active_by_key[key] for key in sorted(active_by_key)]

    def changed_edges_between_scans(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]:
        tenant_id = normalize_graph_tenant_id(tenant_id)

        def by_scan(conn: Any, scan_id: str) -> dict[tuple[str, str, str], dict[str, Any]]:
            rows = conn.execute(
                """
                SELECT source_id, target_id, relationship, direction, weight, traversable,
                       first_seen, last_seen, valid_from, valid_to, confidence, provenance,
                       source_scan_id, source_run_id, evidence, activity_id, scan_id, tenant_id
                FROM graph_edges
                WHERE tenant_id = %s AND scan_id = %s
                """,
                (tenant_id, scan_id),
            ).fetchall()
            return {
                (edge["source_id"], edge["target_id"], edge["relationship"]): edge
                for edge in (self._edge_history_dict(row) for row in rows)
            }

        with _tenant_connection(self._pool) as conn:
            old_edges = by_scan(conn, scan_id_old)
            new_edges = by_scan(conn, scan_id_new)

        old_keys, new_keys = set(old_edges), set(new_edges)
        shared = old_keys & new_keys
        changed = [
            {"before": old_edges[key], "after": new_edges[key]}
            for key in sorted(shared)
            if self._edge_change_fingerprint(old_edges[key]) != self._edge_change_fingerprint(new_edges[key])
        ]
        unchanged = [
            new_edges[key]
            for key in sorted(shared)
            if self._edge_change_fingerprint(old_edges[key]) == self._edge_change_fingerprint(new_edges[key])
        ]
        return {
            "scan_id_old": scan_id_old,
            "scan_id_new": scan_id_new,
            "edges_added": [new_edges[key] for key in sorted(new_keys - old_keys)],
            "edges_removed": [old_edges[key] for key in sorted(old_keys - new_keys)],
            "edges_changed": changed,
            "edges_unchanged": unchanged,
            "summary": {
                "added": len(new_keys - old_keys),
                "removed": len(old_keys - new_keys),
                "changed": len(changed),
                "unchanged": len(unchanged),
            },
        }

    def graph_history(self, *, tenant_id: str = "", limit: int = 50, since: str | None = None) -> dict[str, Any]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        snapshots = self.list_snapshots(tenant_id=tenant_id, limit=limit, since=since)
        history: list[dict[str, Any]] = []
        for snapshot in snapshots:
            scan_id = snapshot["scan_id"]
            baseline = self.previous_snapshot_id(tenant_id=tenant_id, before_scan_id=scan_id)
            diff_summary = _diff_summary_counts(self.diff_snapshots(baseline, scan_id, tenant_id=tenant_id)) if baseline else {}
            history.append(
                {
                    **snapshot,
                    "diff_baseline_scan_id": baseline,
                    "diff_summary": diff_summary,
                }
            )
        return {
            "schema_version": "agent-bom.graph_history/v1",
            "tenant_id": tenant_id,
            "retention_policy": graph_retention_policy(),
            "snapshots": history,
        }

    def evidence_manifest(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        baseline_scan_id: str = "",
    ) -> dict[str, Any]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        generated_at = datetime.now(timezone.utc).isoformat()
        if not effective_scan_id:
            return {
                "schema_version": "agent-bom.graph_evidence_manifest/v1",
                "tenant_id": tenant_id,
                "scan_id": "",
                "generated_at": generated_at,
                "retention_policy": graph_retention_policy(),
                "included_tables": list(_GRAPH_EVIDENCE_INCLUDED_TABLES),
                "excluded_private_fields": list(_GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS),
            }
        baseline = baseline_scan_id or self.previous_snapshot_id(tenant_id=tenant_id, before_scan_id=effective_scan_id)
        with _tenant_connection(self._pool) as conn:
            snapshot_row = conn.execute(
                "SELECT created_at FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, effective_scan_id),
            ).fetchone()
            if not snapshot_row:
                return {
                    "schema_version": "agent-bom.graph_evidence_manifest/v1",
                    "tenant_id": tenant_id,
                    "scan_id": "",
                    "generated_at": generated_at,
                    "retention_policy": graph_retention_policy(),
                    "included_tables": list(_GRAPH_EVIDENCE_INCLUDED_TABLES),
                    "excluded_private_fields": list(_GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS),
                }
            graph_digest, findings_digest, counts = self._snapshot_digests(
                conn,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
            )

        diff_summary = _diff_summary_counts(self.diff_snapshots(baseline, effective_scan_id, tenant_id=tenant_id)) if baseline else {}
        return {
            "schema_version": "agent-bom.graph_evidence_manifest/v1",
            "tenant_id": tenant_id,
            "scan_id": effective_scan_id,
            "generated_at": generated_at,
            "scan_created_at": str(snapshot_row[0]),
            "graph_digest": graph_digest,
            "findings_digest": findings_digest,
            "diff_baseline_scan_id": baseline,
            "diff_summary": diff_summary,
            "counts": counts,
            "included_tables": list(_GRAPH_EVIDENCE_INCLUDED_TABLES),
            "excluded_private_fields": list(_GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS),
            "retention_policy": graph_retention_policy(),
        }
