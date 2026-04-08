"""Persistent graph storage — SQLite-backed unified graph with temporal diffs.

Each scan produces an immutable snapshot of nodes and edges.  The same
node ID can appear in multiple scans — the (id, scan_id, tenant_id) PK
preserves per-scan history so ``load_graph(scan_id=...)`` and
``diff_snapshots(...)`` are always correct.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

from agent_bom.graph import (
    SEVERITY_RANK,
    AttackPath,
    EntityType,
    InteractionRisk,
    NodeDimensions,
    NodeStatus,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
    _now_iso,
)

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# Schema DDL — scan_id is part of every PK for per-scan isolation
# ═══════════════════════════════════════════════════════════════════════════

_GRAPH_SCHEMA_VERSION = 2

_CREATE_TABLES = """\
-- ── Graph nodes (one row per node per scan) ──
CREATE TABLE IF NOT EXISTS graph_nodes (
    id              TEXT NOT NULL,
    entity_type     TEXT NOT NULL,
    label           TEXT NOT NULL,
    category_uid    INTEGER DEFAULT 0,
    class_uid       INTEGER DEFAULT 0,
    type_uid        INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'active',
    risk_score      REAL DEFAULT 0.0,
    severity        TEXT DEFAULT '',
    severity_id     INTEGER DEFAULT 0,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    attributes      TEXT DEFAULT '{}',
    compliance_tags TEXT DEFAULT '[]',
    data_sources    TEXT DEFAULT '[]',
    dimensions      TEXT DEFAULT '{}',
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT DEFAULT '',
    PRIMARY KEY (id, scan_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_gn_entity_type ON graph_nodes(entity_type);
CREATE INDEX IF NOT EXISTS idx_gn_severity ON graph_nodes(severity);
CREATE INDEX IF NOT EXISTS idx_gn_risk ON graph_nodes(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_gn_scan ON graph_nodes(scan_id);

-- ── Graph edges (one row per edge per scan) ──
CREATE TABLE IF NOT EXISTS graph_edges (
    source_id       TEXT NOT NULL,
    target_id       TEXT NOT NULL,
    relationship    TEXT NOT NULL,
    direction       TEXT DEFAULT 'directed',
    weight          REAL DEFAULT 1.0,
    traversable     INTEGER DEFAULT 1,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    evidence        TEXT DEFAULT '{}',
    activity_id     INTEGER DEFAULT 1,
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT DEFAULT '',
    PRIMARY KEY (source_id, target_id, relationship, scan_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_ge_source ON graph_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_ge_target ON graph_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_ge_rel ON graph_edges(relationship);
CREATE INDEX IF NOT EXISTS idx_ge_scan ON graph_edges(scan_id);

-- ── Snapshots ──
CREATE TABLE IF NOT EXISTS graph_snapshots (
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT DEFAULT '',
    created_at      TEXT NOT NULL,
    node_count      INTEGER DEFAULT 0,
    edge_count      INTEGER DEFAULT 0,
    risk_summary    TEXT DEFAULT '{}',
    PRIMARY KEY (scan_id, tenant_id)
);

-- ── Attack paths (per scan) ──
CREATE TABLE IF NOT EXISTS attack_paths (
    source_node     TEXT NOT NULL,
    target_node     TEXT NOT NULL,
    hop_count       INTEGER DEFAULT 0,
    composite_risk  REAL DEFAULT 0.0,
    path_nodes      TEXT DEFAULT '[]',
    path_edges      TEXT DEFAULT '[]',
    credential_exposure TEXT DEFAULT '[]',
    vuln_ids        TEXT DEFAULT '[]',
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT DEFAULT '',
    computed_at     TEXT NOT NULL,
    PRIMARY KEY (source_node, target_node, scan_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_ap_risk ON attack_paths(composite_risk DESC);
CREATE INDEX IF NOT EXISTS idx_ap_scan ON attack_paths(scan_id);

-- ── Interaction risks (per scan) ──
CREATE TABLE IF NOT EXISTS interaction_risks (
    pattern         TEXT NOT NULL,
    agents          TEXT NOT NULL,
    risk_score      REAL DEFAULT 0.0,
    description     TEXT DEFAULT '',
    owasp_agentic_tag TEXT DEFAULT NULL,
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT DEFAULT '',
    PRIMARY KEY (pattern, agents, scan_id, tenant_id)
);

-- ── Schema version ──
CREATE TABLE IF NOT EXISTS graph_schema_version (
    version INTEGER PRIMARY KEY
);
"""


# ═══════════════════════════════════════════════════════════════════════════
# Connection helpers
# ═══════════════════════════════════════════════════════════════════════════


def default_graph_db_path() -> Path:
    """Resolve the graph DB path from the active deployment configuration.

    Preference order:
    1. ``AGENT_BOM_GRAPH_DB`` explicit graph database path
    2. ``AGENT_BOM_DB`` shared SQLite database used by the API
    3. ``~/.agent-bom/db/graph.db`` local default
    """
    configured = os.environ.get("AGENT_BOM_GRAPH_DB") or os.environ.get("AGENT_BOM_DB")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".agent-bom" / "db" / "graph.db"


def _init_db(conn: sqlite3.Connection) -> None:
    """Ensure tables exist and schema is current."""
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_CREATE_TABLES)
    row = conn.execute("SELECT version FROM graph_schema_version ORDER BY version DESC LIMIT 1").fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO graph_schema_version (version) VALUES (?)",
            (_GRAPH_SCHEMA_VERSION,),
        )
    conn.commit()


@contextmanager
def open_graph_db(db_path: str | Path) -> Generator[sqlite3.Connection, None, None]:
    """Open (or create) a graph database with schema initialisation."""
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        _init_db(conn)
        yield conn
    finally:
        conn.close()


def latest_snapshot_id(conn: sqlite3.Connection, *, tenant_id: str = "") -> str:
    """Return the newest snapshot ID for a tenant, or ``""`` when absent."""
    row = conn.execute(
        """\
        SELECT scan_id
        FROM graph_snapshots
        WHERE tenant_id = ?
        ORDER BY created_at DESC, scan_id DESC
        LIMIT 1
        """,
        (tenant_id,),
    ).fetchone()
    return str(row["scan_id"]) if row else ""


def previous_snapshot_id(conn: sqlite3.Connection, *, tenant_id: str = "", before_scan_id: str = "") -> str:
    """Return the snapshot immediately before ``before_scan_id`` for a tenant."""
    if not before_scan_id:
        return ""
    current = conn.execute(
        "SELECT created_at FROM graph_snapshots WHERE tenant_id = ? AND scan_id = ?",
        (tenant_id, before_scan_id),
    ).fetchone()
    if not current:
        return ""
    row = conn.execute(
        """\
        SELECT scan_id
        FROM graph_snapshots
        WHERE tenant_id = ? AND created_at < ?
        ORDER BY created_at DESC, scan_id DESC
        LIMIT 1
        """,
        (tenant_id, current["created_at"]),
    ).fetchone()
    return str(row["scan_id"]) if row else ""


def _resolve_snapshot(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
) -> tuple[str, str]:
    """Resolve the requested or latest snapshot and return ``(scan_id, created_at)``."""
    effective_scan_id = scan_id or latest_snapshot_id(conn, tenant_id=tenant_id)
    if not effective_scan_id:
        return "", ""
    row = conn.execute(
        "SELECT created_at FROM graph_snapshots WHERE scan_id = ? AND tenant_id = ?",
        (effective_scan_id, tenant_id),
    ).fetchone()
    return effective_scan_id, (str(row["created_at"]) if row else "")


# ═══════════════════════════════════════════════════════════════════════════
# Write — each scan is an immutable snapshot (INSERT OR REPLACE by PK)
# ═══════════════════════════════════════════════════════════════════════════


def save_graph(conn: sqlite3.Connection, graph: UnifiedGraph) -> None:
    """Persist a UnifiedGraph as an immutable per-scan snapshot."""
    tenant = graph.tenant_id
    scan = graph.scan_id
    now = _now_iso()

    # ── Nodes ──
    node_rows = []
    for node in graph.nodes.values():
        node_rows.append(
            (
                node.id,
                node.entity_type.value if isinstance(node.entity_type, EntityType) else node.entity_type,
                node.label,
                node.category_uid,
                node.class_uid,
                node.type_uid,
                node.status.value if isinstance(node.status, NodeStatus) else node.status,
                node.risk_score,
                node.severity,
                node.severity_id,
                node.first_seen,
                node.last_seen,
                json.dumps(node.attributes, default=str),
                json.dumps(node.compliance_tags),
                json.dumps(node.data_sources),
                json.dumps(node.dimensions.to_dict()),
                scan,
                tenant,
            )
        )
    conn.executemany(
        """\
        INSERT OR REPLACE INTO graph_nodes (
            id, entity_type, label, category_uid, class_uid, type_uid,
            status, risk_score, severity, severity_id,
            first_seen, last_seen, attributes, compliance_tags,
            data_sources, dimensions, scan_id, tenant_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        node_rows,
    )

    # ── Edges ──
    edge_rows = []
    for edge in graph.edges:
        rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else edge.relationship
        edge_rows.append(
            (
                edge.source,
                edge.target,
                rel,
                edge.direction,
                edge.weight,
                1 if edge.traversable else 0,
                edge.first_seen,
                edge.last_seen,
                json.dumps(edge.evidence, default=str),
                edge.activity_id,
                scan,
                tenant,
            )
        )
    conn.executemany(
        """\
        INSERT OR REPLACE INTO graph_edges (
            source_id, target_id, relationship, direction, weight,
            traversable, first_seen, last_seen, evidence,
            activity_id, scan_id, tenant_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        edge_rows,
    )

    # ── Attack paths ──
    for ap in graph.attack_paths:
        conn.execute(
            """\
            INSERT OR REPLACE INTO attack_paths (
                source_node, target_node, hop_count, composite_risk,
                path_nodes, path_edges, credential_exposure, vuln_ids,
                scan_id, tenant_id, computed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ap.source,
                ap.target,
                len(ap.hops),
                ap.composite_risk,
                json.dumps(ap.hops),
                json.dumps(ap.edges),
                json.dumps(ap.credential_exposure),
                json.dumps(ap.vuln_ids),
                scan,
                tenant,
                now,
            ),
        )

    # ── Interaction risks ──
    for ir in graph.interaction_risks:
        conn.execute(
            """\
            INSERT OR REPLACE INTO interaction_risks (
                pattern, agents, risk_score, description,
                owasp_agentic_tag, scan_id, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ir.pattern, json.dumps(sorted(ir.agents)), ir.risk_score, ir.description, ir.owasp_agentic_tag, scan, tenant),
        )

    # ── Snapshot ──
    stats = graph.stats()
    conn.execute(
        "INSERT OR REPLACE INTO graph_snapshots VALUES (?, ?, ?, ?, ?, ?)",
        (scan, tenant, now, stats["total_nodes"], stats["total_edges"], json.dumps(stats.get("severity_counts", {}))),
    )

    conn.commit()
    logger.info(
        "Saved graph: %d nodes, %d edges, %d attack paths (scan=%s)",
        len(graph.nodes),
        len(graph.edges),
        len(graph.attack_paths),
        scan,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Read — load exactly one scan's snapshot
# ═══════════════════════════════════════════════════════════════════════════


def load_graph(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
    entity_types: set[str] | None = None,
    min_severity_rank: int = 0,
) -> UnifiedGraph:
    """Load a UnifiedGraph from a specific scan snapshot."""
    effective_scan_id, created_at = _resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
    graph = UnifiedGraph(scan_id=effective_scan_id, tenant_id=tenant_id, created_at=created_at)
    if not effective_scan_id:
        return graph

    query = "SELECT * FROM graph_nodes WHERE tenant_id = ? AND scan_id = ?"
    params: list[Any] = [tenant_id, effective_scan_id]
    if entity_types:
        placeholders = ",".join("?" * len(entity_types))
        query += f" AND entity_type IN ({placeholders})"
        params.extend(entity_types)

    node_ids: set[str] = set()
    for row in conn.execute(query, params):
        sev = row["severity"] or ""
        if min_severity_rank and SEVERITY_RANK.get(sev, 0) < min_severity_rank:
            continue
        graph.add_node(
            UnifiedNode(
                id=row["id"],
                entity_type=EntityType(row["entity_type"]),
                label=row["label"],
                category_uid=row["category_uid"],
                class_uid=row["class_uid"],
                type_uid=row["type_uid"],
                status=NodeStatus(row["status"]),
                risk_score=row["risk_score"],
                severity=sev,
                severity_id=row["severity_id"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                attributes=json.loads(row["attributes"]),
                compliance_tags=json.loads(row["compliance_tags"]),
                data_sources=json.loads(row["data_sources"]),
                dimensions=NodeDimensions.from_dict(json.loads(row["dimensions"])),
            )
        )
        node_ids.add(row["id"])

    eq = "SELECT * FROM graph_edges WHERE tenant_id = ? AND scan_id = ?"
    eparams: list[Any] = [tenant_id, effective_scan_id]
    for row in conn.execute(eq, eparams):
        if row["source_id"] not in node_ids or row["target_id"] not in node_ids:
            continue
        graph.add_edge(
            UnifiedEdge(
                source=row["source_id"],
                target=row["target_id"],
                relationship=RelationshipType(row["relationship"]),
                direction=row["direction"],
                weight=row["weight"],
                traversable=bool(row["traversable"]),
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                evidence=json.loads(row["evidence"]),
                activity_id=row["activity_id"],
            )
        )

    apq = "SELECT * FROM attack_paths WHERE tenant_id = ? AND scan_id = ?"
    apparams: list[Any] = [tenant_id, effective_scan_id]
    for row in conn.execute(apq, apparams):
        graph.attack_paths.append(
            AttackPath(
                source=row["source_node"],
                target=row["target_node"],
                hops=json.loads(row["path_nodes"]),
                edges=json.loads(row["path_edges"]),
                composite_risk=row["composite_risk"],
                credential_exposure=json.loads(row["credential_exposure"]),
                vuln_ids=json.loads(row["vuln_ids"]),
            )
        )

    irq = "SELECT * FROM interaction_risks WHERE tenant_id = ? AND scan_id = ?"
    irparams: list[Any] = [tenant_id, effective_scan_id]
    for row in conn.execute(irq, irparams):
        graph.interaction_risks.append(
            InteractionRisk(
                pattern=row["pattern"],
                agents=json.loads(row["agents"]),
                risk_score=row["risk_score"],
                description=row["description"],
                owasp_agentic_tag=row["owasp_agentic_tag"],
            )
        )

    return graph


# ═══════════════════════════════════════════════════════════════════════════
# Diff / temporal queries
# ═══════════════════════════════════════════════════════════════════════════


def diff_snapshots(
    conn: sqlite3.Connection,
    scan_id_old: str,
    scan_id_new: str,
    *,
    tenant_id: str = "",
) -> dict[str, Any]:
    """Compute the diff between two scan snapshots."""
    old_nodes: dict[str, dict] = {}
    for row in conn.execute(
        "SELECT id, severity, risk_score FROM graph_nodes WHERE scan_id = ? AND tenant_id = ?",
        (scan_id_old, tenant_id),
    ):
        old_nodes[row["id"]] = {"severity": row["severity"], "risk_score": row["risk_score"]}

    new_nodes: dict[str, dict] = {}
    for row in conn.execute(
        "SELECT id, severity, risk_score FROM graph_nodes WHERE scan_id = ? AND tenant_id = ?",
        (scan_id_new, tenant_id),
    ):
        new_nodes[row["id"]] = {"severity": row["severity"], "risk_score": row["risk_score"]}

    old_ids, new_ids = set(old_nodes), set(new_nodes)

    old_edges: set[tuple[str, str, str]] = set()
    for row in conn.execute(
        "SELECT source_id, target_id, relationship FROM graph_edges WHERE scan_id = ? AND tenant_id = ?",
        (scan_id_old, tenant_id),
    ):
        old_edges.add((row["source_id"], row["target_id"], row["relationship"]))

    new_edges: set[tuple[str, str, str]] = set()
    for row in conn.execute(
        "SELECT source_id, target_id, relationship FROM graph_edges WHERE scan_id = ? AND tenant_id = ?",
        (scan_id_new, tenant_id),
    ):
        new_edges.add((row["source_id"], row["target_id"], row["relationship"]))

    return {
        "nodes_added": sorted(new_ids - old_ids),
        "nodes_removed": sorted(old_ids - new_ids),
        "nodes_changed": sorted(nid for nid in (old_ids & new_ids) if old_nodes[nid] != new_nodes[nid]),
        "edges_added": sorted(new_edges - old_edges),
        "edges_removed": sorted(old_edges - new_edges),
    }


def list_snapshots(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List recent graph snapshots ordered by creation time desc."""
    rows = conn.execute(
        """\
        SELECT scan_id, created_at, node_count, edge_count, risk_summary
        FROM graph_snapshots
        WHERE tenant_id = ?
        ORDER BY created_at DESC LIMIT ?
        """,
        (tenant_id, limit),
    ).fetchall()
    return [
        {
            "scan_id": r["scan_id"],
            "created_at": r["created_at"],
            "node_count": r["node_count"],
            "edge_count": r["edge_count"],
            "risk_summary": json.loads(r["risk_summary"]),
        }
        for r in rows
    ]
