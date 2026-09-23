"""Bounded recorded incident-edge pages shared by relational graph stores.

Pages assume snapshot IDs are immutable while being paged. Timestamp/manifest
changes invalidate cursors; legacy replacement preserving both cannot be detected
without a durable revision column. Each individual page is transaction-consistent.

A next-page caller must reuse the returned scan_id; resolving latest again rejects
a cursor if a newer snapshot appeared. Completeness covers only this recorded
edge page, not source collection coverage or the whole neighborhood.

Direction filters recorded endpoints; bidirectional edges are never fabricated
as additional reverse records. Cursors are scope tokens, not authorization.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

from agent_bom.graph.completeness import graph_completeness

EDGE_COLUMNS = (
    "source_id, target_id, relationship, direction, weight, traversable, first_seen, last_seen, "
    "valid_from, valid_to, confidence, provenance, source_scan_id, source_run_id, evidence, activity_id, scan_id"
)
NODE_COLUMNS = (
    "id, entity_type, label, category_uid, class_uid, type_uid, status, risk_score, severity, "
    "severity_id, first_seen, last_seen, attributes, compliance_tags, data_sources, dimensions"
)


def incident_edge_page(
    conn: Any,
    *,
    tenant_id: str,
    scan_id: str,
    node_id: str,
    direction: str,
    limit: int,
    cursor: str | None,
    marker: str,
    node_from_row: Callable[[Any], Any],
    edge_from_row: Callable[[Any], Any],
) -> dict[str, Any] | None:
    """Read inside the caller's transaction; materialize at most 2*(limit+1) edges."""
    if direction not in {"in", "out", "both"}:
        raise ValueError("direction must be in, out, or both")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    token: dict[str, Any] | None = None
    if cursor:
        try:
            if len(cursor) > 8192:
                raise ValueError
            token = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
            if not isinstance(token, dict) or token.get("v") != 1:
                raise ValueError
            if not isinstance(token.get("after"), list) or len(token["after"]) != 3 or not all(isinstance(v, str) for v in token["after"]):
                raise ValueError
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise ValueError("Invalid incident-edge cursor") from exc
    # Marker is a backend-owned literal, never caller text.
    if marker not in {"?", "%s"}:
        raise ValueError("Unsupported SQL parameter marker")
    if scan_id:
        snapshot = conn.execute(
            f"SELECT scan_id, created_at, evidence_manifest_sha256 FROM graph_snapshots WHERE tenant_id = {marker} AND scan_id = {marker}",  # nosec B608
            (tenant_id, scan_id),
        ).fetchone()
    else:
        snapshot = conn.execute(
            f"SELECT scan_id, created_at, evidence_manifest_sha256 FROM graph_snapshots WHERE tenant_id "
            f"= {marker} AND snapshot_kind = 'scan' ORDER BY created_at DESC, scan_id DESC LIMIT 1",  # nosec B608
            (tenant_id,),
        ).fetchone()
    if snapshot is None:
        if cursor:
            raise ValueError("Incident-edge cursor snapshot is unavailable")
        return None
    effective_scan_id, created_at = str(snapshot[0]), str(snapshot[1])
    scope = [tenant_id, effective_scan_id, created_at, str(snapshot[2] or ""), node_id, direction]
    if token is not None and token.get("scope") != scope:
        raise ValueError("Incident-edge cursor does not match request scope")
    seed = conn.execute(
        f"SELECT {NODE_COLUMNS} FROM graph_nodes WHERE tenant_id = {marker} AND scan_id = {marker} AND id = {marker}",  # nosec B608
        (tenant_id, effective_scan_id, node_id),
    ).fetchone()
    if seed is None:
        return None
    collation = ' COLLATE "C"' if marker == "%s" else ""
    rows_by_key: dict[tuple[str, str, str], Any] = {}
    for column in ("source_id", "target_id") if direction == "both" else ("source_id",) if direction == "out" else ("target_id",):
        params: list[Any] = [tenant_id, effective_scan_id, node_id]
        varying = "target_id" if column == "source_id" else "source_id"
        ordered_key = f"{varying}{collation}, relationship{collation}"
        after_sql = ""
        if token is not None:
            source, target, relationship = token["after"]
            # Remove the fixed endpoint from the seek tuple: SQLite otherwise
            # scans the entire preceding degree even with a covering index.
            if column == "source_id":
                if node_id < source:
                    continue
                if node_id == source:
                    after_sql = f" AND ({ordered_key}) > ({marker}, {marker})"
                    params.extend([target, relationship])
            elif node_id == target:
                after_sql = f" AND ({ordered_key}) > ({marker}, {marker})"
                params.extend([source, relationship])
            else:
                operator = ">=" if node_id > target else ">"
                after_sql = f" AND source_id{collation} {operator} {marker}"
                params.append(source)
        params.append(limit + 1)
        rows = conn.execute(
            f"SELECT {EDGE_COLUMNS} FROM graph_edges WHERE tenant_id = {marker} AND scan_id = {marker} "
            f"AND {column}{collation} = {marker}{after_sql} ORDER BY {ordered_key} LIMIT {marker}",  # nosec B608 - backend-owned fragments; values are bound
            params,
        ).fetchall()
        for row in rows:
            rows_by_key[(str(row[0]), str(row[1]), str(row[2]))] = row
    keys = sorted(rows_by_key)
    has_more = len(keys) > limit
    selected = keys[:limit]
    edges = [edge_from_row(rows_by_key[key]) for key in selected]
    endpoint_ids = sorted({endpoint for key in selected for endpoint in key[:2]} - {node_id})
    nodes = [node_from_row(seed)]
    if endpoint_ids:
        placeholders = ",".join(marker for _ in endpoint_ids)
        rows = conn.execute(
            f"SELECT {NODE_COLUMNS} FROM graph_nodes WHERE tenant_id = {marker} AND scan_id = {marker} "
            f"AND id IN ({placeholders}) ORDER BY id",  # nosec B608
            [tenant_id, effective_scan_id, *endpoint_ids],
        ).fetchall()
        nodes.extend(node_from_row(row) for row in rows)
    present_ids = {node.id for node in nodes}
    missing_endpoint_count = len(set(endpoint_ids) - present_ids)
    edges = [edge for edge in edges if edge.source in present_ids and edge.target in present_ids]
    retained_ids = {node_id, *(endpoint for edge in edges for endpoint in (edge.source, edge.target))}
    nodes = [node for node in nodes if node.id in retained_ids]
    next_cursor = None
    if has_more:
        next_cursor = base64.urlsafe_b64encode(
            json.dumps({"v": 1, "scope": scope, "after": selected[-1]}, separators=(",", ":")).encode()
        ).decode()
    return {
        "scan_id": effective_scan_id,
        "node": nodes[0],
        "nodes": nodes,
        "edges": edges,
        "next_cursor": next_cursor,
        "completeness": {
            **graph_completeness(
                returned=len(edges),
                truncated=has_more or bool(missing_endpoint_count),
                reason="missing_endpoint_nodes" if missing_endpoint_count else "page_limit" if has_more else "",
            ),
            "scope": "incident_edge_page",
            "missing_endpoint_count": missing_endpoint_count,
        },
    }
