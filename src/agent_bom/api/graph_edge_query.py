"""Tenant-scoped, bounded incident-edge queries shared by SQL graph stores."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import RelationshipType


def edge_query(
    *,
    tenant_id: str,
    scan_id: str,
    node_ids: set[str],
    dialect: str = "sqlite",
    induced_only: bool = False,
    direction: str = "both",
    relationships: set[str] | None = None,
    limit: int | None = None,
) -> tuple[str, list[Any]]:
    """Bound each indexed endpoint walk before joining the two directions.

    Identifier lists and placeholders are fixed by the selected SQL dialect.
    A bounded result is a deterministic subset, not a severity-ranked edge
    projection. Callers must probe one extra row and disclose omitted evidence.
    """
    if dialect not in {"sqlite", "postgres"}:
        raise ValueError("Unsupported graph SQL dialect")
    placeholder = "%s" if dialect == "postgres" else "?"
    columns = (
        (
            "source_id, target_id, relationship, direction, weight, traversable, "
            "first_seen, last_seen, valid_from, valid_to, confidence, provenance, "
            "source_scan_id, source_run_id, evidence, activity_id, scan_id"
        )
        if dialect == "postgres"
        else "*"
    )
    if direction not in {"in", "out", "both"}:
        raise ValueError("Invalid edge direction")
    if limit is not None and (type(limit) is not int or limit < 1):
        raise ValueError("Edge limit must be a positive integer")
    nodes = sorted(node_ids)
    marks = ",".join([placeholder] * len(nodes))
    scope = f"tenant_id = {placeholder} AND scan_id = {placeholder}"
    relations = sorted(relationships or ())
    relation_clause = ""
    if relations:
        relation_clause = f" AND relationship IN ({','.join([placeholder] * len(relations))})"
    if induced_only or limit is None:
        endpoint_join = "AND" if induced_only else "OR"
        endpoints = f"(source_id IN ({marks}) {endpoint_join} target_id IN ({marks}))"
        params: list[Any] = [tenant_id, scan_id, *nodes, *nodes, *relations]
        if direction != "both" and not induced_only:
            endpoints = f"{'target_id' if direction == 'in' else 'source_id'} IN ({marks})"
            params = [tenant_id, scan_id, *nodes, *relations]
        sql = f"SELECT {columns} FROM graph_edges WHERE {scope} AND {endpoints}{relation_clause}"  # nosec B608 - fixed dialect identifiers; values are bound
        if limit is not None:
            sql += f" ORDER BY source_id, target_id, relationship LIMIT {placeholder}"
            params.append(limit)
        return sql, params

    walks, params = [], []
    for endpoint, other in (("source_id", "target_id"), ("target_id", "source_id")):
        if (direction == "in" and endpoint == "source_id") or (direction == "out" and endpoint == "target_id"):
            continue
        walks.append(
            f"SELECT * FROM (SELECT {columns} FROM graph_edges WHERE {scope} "  # nosec B608 - fixed dialect identifiers; values are bound
            f"AND {endpoint} IN ({marks}){relation_clause} "
            f"ORDER BY {endpoint}, {other}, relationship LIMIT {placeholder}) edge_walk_{endpoint}"
        )
        params.extend([tenant_id, scan_id, *nodes, *relations, limit])
    sql = " UNION ".join(walks) + f" ORDER BY source_id, target_id, relationship LIMIT {placeholder}"
    return sql, [*params, limit]


def _edge_from_row(row: sqlite3.Row) -> UnifiedEdge:
    return UnifiedEdge(
        source=row["source_id"],
        target=row["target_id"],
        relationship=RelationshipType(row["relationship"]),
        direction=row["direction"],
        weight=row["weight"],
        traversable=bool(row["traversable"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        valid_from=row["valid_from"] or row["first_seen"],
        valid_to=row["valid_to"],
        confidence=row["confidence"],
        provenance=json.loads(row["provenance"] or "{}"),
        source_scan_id=row["source_scan_id"] or row["scan_id"],
        source_run_id=row["source_run_id"] or "",
        evidence=json.loads(row["evidence"]),
        activity_id=row["activity_id"],
    )
