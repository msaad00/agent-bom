"""Attack-path and node-context reads for the Postgres graph store."""

from __future__ import annotations

from typing import Any

from agent_bom.db.graph_store import (
    normalize_graph_tenant_id,
)
from agent_bom.graph import technique_mappings_from_json
from agent_bom.graph.completeness import (
    graph_completeness,
)

from .postgres_common import (
    _tenant_connection,
)
from .postgres_graph_support import (
    _decode_json_array,
    _decode_json_object,
)
from .postgres_graph_traversal import PostgresGraphTraversalMixin


class PostgresGraphPathsMixin(PostgresGraphTraversalMixin):
    """Read materialised attack paths, incident edge pages and node context."""

    def attack_paths_for_sources(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source_ids: set[str],
    ) -> list[Any]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        if not source_ids:
            return []
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return []
        placeholders = ",".join(["%s"] * len(source_ids))
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"""
                SELECT source_node, target_node, path_nodes, path_edges, composite_risk,
                       summary, credential_exposure, tool_exposure, vuln_ids,
                       reachability, reachability_basis, technique_mappings,
                       hop_evidence, analysis
                FROM attack_paths
                WHERE tenant_id = %s AND scan_id = %s AND source_node IN ({placeholders})
                ORDER BY composite_risk DESC, source_node ASC, target_node ASC
                """,  # nosec B608 - placeholders are generated internally
                [tenant_id, effective_scan_id, *sorted(source_ids)],
            ).fetchall()

        from agent_bom.graph import AttackPath

        return [
            AttackPath(
                source=row[0],
                target=row[1],
                hops=_decode_json_array(row[2], field="attack path nodes"),
                edges=_decode_json_array(row[3], field="attack path edges"),
                composite_risk=row[4],
                summary=row[5] or "",
                credential_exposure=_decode_json_array(row[6], field="attack path credential exposure"),
                tool_exposure=_decode_json_array(row[7], field="attack path tool exposure"),
                vuln_ids=_decode_json_array(row[8], field="attack path vulnerability IDs"),
                reachability=row[9] or "unknown",
                reachability_basis=_decode_json_array(row[10], field="attack path reachability basis"),
                hop_evidence=[
                    dict(item) for item in _decode_json_array(row[12], field="attack path hop evidence") if isinstance(item, dict)
                ],
                analysis=_decode_json_object(row[13], field="attack path analysis"),
                technique_mappings=technique_mappings_from_json(row[11]),
            )
            for row in rows
        ]

    def attack_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[str, str, list[Any], int]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return scan_id, "", [], 0

        with _tenant_connection(self._pool) as conn:
            snapshot_row = conn.execute(
                "SELECT created_at FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, effective_scan_id),
            ).fetchone()
            total_row = conn.execute(
                "SELECT COUNT(*) FROM attack_paths WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, effective_scan_id),
            ).fetchone()
            rows = conn.execute(
                """
                SELECT source_node, target_node, path_nodes, path_edges, composite_risk,
                       summary, credential_exposure, tool_exposure, vuln_ids,
                       reachability, reachability_basis, technique_mappings,
                       hop_evidence, analysis
                FROM attack_paths
                WHERE tenant_id = %s AND scan_id = %s
                ORDER BY composite_risk DESC, source_node ASC, target_node ASC
                LIMIT %s OFFSET %s
                """,
                (tenant_id, effective_scan_id, limit, offset),
            ).fetchall()

        from agent_bom.graph import AttackPath

        return (
            effective_scan_id,
            str(snapshot_row[0]) if snapshot_row else "",
            [
                AttackPath(
                    source=row[0],
                    target=row[1],
                    hops=_decode_json_array(row[2], field="attack path nodes"),
                    edges=_decode_json_array(row[3], field="attack path edges"),
                    composite_risk=row[4],
                    summary=row[5] or "",
                    credential_exposure=_decode_json_array(row[6], field="attack path credential exposure"),
                    tool_exposure=_decode_json_array(row[7], field="attack path tool exposure"),
                    vuln_ids=_decode_json_array(row[8], field="attack path vulnerability IDs"),
                    reachability=row[9] or "unknown",
                    reachability_basis=_decode_json_array(row[10], field="attack path reachability basis"),
                    hop_evidence=[
                        dict(item) for item in _decode_json_array(row[12], field="attack path hop evidence") if isinstance(item, dict)
                    ],
                    analysis=_decode_json_object(row[13], field="attack path analysis"),
                    technique_mappings=technique_mappings_from_json(row[11]),
                )
                for row in rows
            ],
            int((total_row[0] if total_row else 0) or 0),
        )

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
    ) -> dict[str, Any] | None:
        """One tenant-scoped MVCC read, without full incident or impact reads."""
        from agent_bom.graph.adjacency_page import incident_edge_page, validate_graph_identifiers

        validate_graph_identifiers(tenant_id, scan_id, node_id, snapshot_generation or "")

        tenant_id = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool, repeatable_read=True) as conn:
            self._apply_search_timeout(conn)
            return incident_edge_page(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                node_id=node_id,
                direction=direction,
                limit=limit,
                cursor=cursor,
                snapshot_generation=snapshot_generation,
                marker="%s",
                node_from_row=self._node_from_row,
                edge_from_row=self._edge_from_row,
            )

    def node_context(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
    ) -> dict[str, Any] | None:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return None
        nodes = self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids={node_id})
        if not nodes:
            return None
        with _tenant_connection(self._pool) as conn:
            self._apply_search_timeout(conn)
            rows = conn.execute(
                """
                SELECT source_id, target_id, relationship, direction, weight, traversable,
                       first_seen, last_seen, valid_from, valid_to, confidence, provenance,
                       source_scan_id, source_run_id, evidence, activity_id, scan_id
                FROM graph_edges
                WHERE tenant_id = %s AND scan_id = %s AND (source_id = %s OR target_id = %s)
                ORDER BY source_id, target_id, relationship
                LIMIT 10001
                """,
                (tenant_id, effective_scan_id, node_id, node_id),
            ).fetchall()
        truncated = len(rows) > 10_000
        edges_out: list[Any] = []
        edges_in: list[Any] = []
        neighbors: list[str] = []
        sources: list[str] = []
        for row in rows[:10_000]:
            edge = self._edge_from_row(row)
            if edge.source == node_id:
                edges_out.append(edge)
                neighbors.append(edge.target)
                if edge.is_bidirectional:
                    edges_in.append(self._reverse_edge(edge))
                    sources.append(edge.target)
            if edge.target == node_id:
                edges_in.append(edge)
                sources.append(edge.source)
                if edge.is_bidirectional:
                    edges_out.append(self._reverse_edge(edge))
                    neighbors.append(edge.source)
        return {
            "node": nodes[0],
            "edges_out": edges_out,
            "edges_in": edges_in,
            "neighbors": neighbors,
            "sources": sources,
            "impact": self.impact_of(tenant_id=tenant_id, scan_id=effective_scan_id, node_id=node_id),
            # This used to hand-roll a fourth status word into a vocabulary of
            # three, so the completeness banner — which branches on
            # complete/truncated/sampled and on the booleans — silently ignored
            # it and rendered a bounded neighbourhood as the whole one.
            "completeness": {
                **graph_completeness(
                    returned=len(edges_in) + len(edges_out),
                    truncated=truncated,
                    reason="edge_budget" if truncated else "",
                ),
                "edge_budget": 10_000,
            },
        }
