"""Persistent graph storage — SQLite-backed unified graph with temporal diffs.

Each scan produces an immutable snapshot of nodes and edges.  The same
node ID can appear in multiple scans — the (id, scan_id, tenant_id) PK
preserves per-scan history so ``load_graph(scan_id=...)`` and
``diff_snapshots(...)`` are always correct.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, Iterable, Iterator, Sequence

if TYPE_CHECKING:
    from agent_bom.graph.delta_digest import PriorSnapshotDigest

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
from agent_bom.security import sanitize_text

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# Schema DDL — scan_id is part of every PK for per-scan isolation
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_GRAPH_TENANT_ID = "default"
_GRAPH_SCHEMA_VERSION = 3
_DEFAULT_GRAPH_WRITE_BATCH_SIZE = 1000
_DEFAULT_GRAPH_RETENTION_DAYS = 180
_FINDING_ENTITY_TYPES = {
    EntityType.VULNERABILITY.value,
    EntityType.MISCONFIGURATION.value,
    EntityType.DRIFT_INCIDENT.value,
}
_GRAPH_EVIDENCE_INCLUDED_TABLES = [
    "graph_snapshots",
    "graph_nodes",
    "graph_edges",
    "attack_paths",
    "interaction_risks",
]
_GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS = [
    "graph_nodes.attributes",
    "graph_edges.provenance",
    "graph_edges.evidence",
    "attack_paths.credential_exposure",
]
_GRAPH_TENANT_TABLE_KEYS: dict[str, tuple[str, ...]] = {
    "graph_nodes": ("id", "scan_id"),
    "graph_edges": ("source_id", "target_id", "relationship", "scan_id"),
    "graph_snapshots": ("scan_id",),
    "attack_paths": ("source_node", "target_node", "scan_id"),
    "interaction_risks": ("pattern", "agents", "scan_id"),
}

_CREATE_TABLES = """\
-- ── Graph nodes (one row per node per scan) ──
CREATE TABLE IF NOT EXISTS graph_nodes (
    id              TEXT NOT NULL,
    entity_type     TEXT NOT NULL,
    label           TEXT NOT NULL,
    -- OCSF projection columns (derived from entity_type via graph/ocsf.py
    -- ENTITY_OCSF_MAP) for classification/filtering. They are not the
    -- canonical source of truth for graph entities.
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
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (id, scan_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_gn_entity_type ON graph_nodes(entity_type);
CREATE INDEX IF NOT EXISTS idx_gn_severity ON graph_nodes(severity);
CREATE INDEX IF NOT EXISTS idx_gn_risk ON graph_nodes(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_gn_scan ON graph_nodes(scan_id);
CREATE INDEX IF NOT EXISTS idx_gn_tenant_scan ON graph_nodes(tenant_id, scan_id);

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
    valid_from      TEXT DEFAULT '',
    valid_to        TEXT DEFAULT NULL,
    confidence      REAL DEFAULT 1.0,
    provenance      TEXT DEFAULT '{}',
    source_scan_id  TEXT DEFAULT '',
    source_run_id   TEXT DEFAULT '',
    evidence        TEXT DEFAULT '{}',
    activity_id     INTEGER DEFAULT 1,
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (source_id, target_id, relationship, scan_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_ge_source ON graph_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_ge_target ON graph_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_ge_rel ON graph_edges(relationship);
CREATE INDEX IF NOT EXISTS idx_ge_scan ON graph_edges(scan_id);
CREATE INDEX IF NOT EXISTS idx_ge_tenant_scan ON graph_edges(tenant_id, scan_id);

-- ── Snapshots ──
CREATE TABLE IF NOT EXISTS graph_snapshots (
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    created_at      TEXT NOT NULL,
    node_count      INTEGER DEFAULT 0,
    edge_count      INTEGER DEFAULT 0,
    risk_summary    TEXT DEFAULT '{}',
    node_type_counts TEXT DEFAULT NULL,
    PRIMARY KEY (scan_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_gs_recent ON graph_snapshots(tenant_id, created_at DESC);

-- ── Attack paths (per scan) ──
CREATE TABLE IF NOT EXISTS attack_paths (
    source_node     TEXT NOT NULL,
    target_node     TEXT NOT NULL,
    hop_count       INTEGER DEFAULT 0,
    composite_risk  REAL DEFAULT 0.0,
    summary         TEXT DEFAULT '',
    path_nodes      TEXT DEFAULT '[]',
    path_edges      TEXT DEFAULT '[]',
    credential_exposure TEXT DEFAULT '[]',
    tool_exposure   TEXT DEFAULT '[]',
    vuln_ids        TEXT DEFAULT '[]',
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
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
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (pattern, agents, scan_id, tenant_id)
);

-- ── Schema version ──
CREATE TABLE IF NOT EXISTS graph_schema_version (
    version INTEGER PRIMARY KEY
);

-- ── Retention purge state (single row) ──
CREATE TABLE IF NOT EXISTS graph_retention_state (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    last_purge_at     TEXT,
    last_purged_count INTEGER DEFAULT 0
);
"""

# Tables purged (in FK-safe order) when a graph snapshot ages out of the
# retention window. Ordered children-before-parents so a partial failure never
# leaves orphaned nodes/edges pointing at a deleted snapshot.
_GRAPH_PURGEABLE_TABLES = (
    "attack_paths",
    "interaction_risks",
    "graph_edges",
    "graph_nodes",
    "graph_snapshots",
)


# ═══════════════════════════════════════════════════════════════════════════
# Connection helpers
# ═══════════════════════════════════════════════════════════════════════════


def normalize_graph_tenant_id(tenant_id: str | None) -> str:
    """Map legacy blank graph tenants into the canonical default bucket."""

    return (tenant_id or "").strip() or DEFAULT_GRAPH_TENANT_ID


def _backfill_empty_tenant_ids(conn: sqlite3.Connection, table_keys: dict[str, tuple[str, ...]] | None = None) -> None:
    """Move legacy ``tenant_id = ''`` rows into the default graph tenant.

    When a default-tenant row already exists for the same graph key, keep the
    explicit default row and drop the duplicate legacy row before updating.
    """

    specs = table_keys or _GRAPH_TENANT_TABLE_KEYS
    for table, key_columns in specs.items():
        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'virtual') AND name = ?",
            (table,),
        ).fetchone()
        if table_exists is None:
            continue
        if key_columns:
            key_match = " AND ".join(f"existing.{column} = {table}.{column}" for column in key_columns)
            conn.execute(
                f"""
                DELETE FROM {table}
                WHERE tenant_id = ''
                  AND EXISTS (
                    SELECT 1
                    FROM {table} existing
                    WHERE existing.tenant_id = ?
                      AND {key_match}
                  )
                """,  # nosec B608 - table/key names are static internal schema metadata
                (DEFAULT_GRAPH_TENANT_ID,),
            )
        conn.execute(
            f"UPDATE {table} SET tenant_id = ? WHERE tenant_id = ''",  # nosec B608 - table names are static internal schema metadata
            (DEFAULT_GRAPH_TENANT_ID,),
        )


def default_graph_db_path() -> Path:
    """Resolve the graph DB path from the active deployment configuration.

    Preference order:
    1. ``AGENT_BOM_GRAPH_DB`` explicit graph database path
    2. ``AGENT_BOM_DB`` shared SQLite database used by the API
    3. ``AGENT_BOM_STATE_DIR`` per-process state dir (``<state>/db/graph.db``)
    4. ``~/.agent-bom/db/graph.db`` local default

    Honoring ``AGENT_BOM_STATE_DIR`` mirrors ``api.durable_store`` so the graph
    snapshot lands in the same isolated state dir an operator (or the test
    suite's conftest) redirects state to — instead of always writing the real
    ``~/.agent-bom/db/graph.db`` and accumulating cross-run/test pollution.
    """
    configured = os.environ.get("AGENT_BOM_GRAPH_DB") or os.environ.get("AGENT_BOM_DB")
    if configured:
        return Path(configured).expanduser()
    state_dir = os.environ.get("AGENT_BOM_STATE_DIR")
    if state_dir:
        return Path(state_dir).expanduser() / "db" / "graph.db"
    return Path.home() / ".agent-bom" / "db" / "graph.db"


def _init_db(conn: sqlite3.Connection, *, backfill_legacy_tenants: bool = True) -> None:
    """Ensure tables exist and schema is current."""
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_CREATE_TABLES)
    row = conn.execute("SELECT version FROM graph_schema_version ORDER BY version DESC LIMIT 1").fetchone()
    if row is None:
        conn.execute(
            "INSERT OR IGNORE INTO graph_schema_version (version) VALUES (?)",
            (_GRAPH_SCHEMA_VERSION,),
        )
    existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(attack_paths)").fetchall()}
    if "summary" not in existing_columns:
        conn.execute("ALTER TABLE attack_paths ADD COLUMN summary TEXT DEFAULT ''")
    if "tool_exposure" not in existing_columns:
        conn.execute("ALTER TABLE attack_paths ADD COLUMN tool_exposure TEXT DEFAULT '[]'")
    edge_columns = {row["name"] for row in conn.execute("PRAGMA table_info(graph_edges)").fetchall()}
    # v3 adds replay metadata. Empty valid_from is interpreted as first_seen for
    # stores created before this migration, so old snapshots remain queryable.
    edge_migrations = {
        "valid_from": "ALTER TABLE graph_edges ADD COLUMN valid_from TEXT DEFAULT ''",
        "valid_to": "ALTER TABLE graph_edges ADD COLUMN valid_to TEXT DEFAULT NULL",
        "confidence": "ALTER TABLE graph_edges ADD COLUMN confidence REAL DEFAULT 1.0",
        "provenance": "ALTER TABLE graph_edges ADD COLUMN provenance TEXT DEFAULT '{}'",
        "source_scan_id": "ALTER TABLE graph_edges ADD COLUMN source_scan_id TEXT DEFAULT ''",
        "source_run_id": "ALTER TABLE graph_edges ADD COLUMN source_run_id TEXT DEFAULT ''",
    }
    for column, statement in edge_migrations.items():
        if column not in edge_columns:
            conn.execute(statement)
    conn.execute("UPDATE graph_edges SET valid_from = first_seen WHERE valid_from = '' OR valid_from IS NULL")
    conn.execute("UPDATE graph_edges SET source_scan_id = scan_id WHERE source_scan_id = '' OR source_scan_id IS NULL")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ge_tenant_valid ON graph_edges(tenant_id, valid_from, valid_to)")
    # Materialise the per-snapshot entity-type breakdown so inventory/summary
    # reads a cached count instead of a per-request GROUP BY over every node.
    # NULL marks pre-migration snapshots, which fall back to the live GROUP BY.
    snapshot_columns = {row["name"] for row in conn.execute("PRAGMA table_info(graph_snapshots)").fetchall()}
    if "node_type_counts" not in snapshot_columns:
        conn.execute("ALTER TABLE graph_snapshots ADD COLUMN node_type_counts TEXT DEFAULT NULL")
    if backfill_legacy_tenants:
        _backfill_empty_tenant_ids(conn)
    conn.commit()


def _graph_write_batch_size() -> int:
    raw = os.environ.get("AGENT_BOM_GRAPH_WRITE_BATCH_SIZE", str(_DEFAULT_GRAPH_WRITE_BATCH_SIZE))
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_GRAPH_WRITE_BATCH_SIZE


def _graph_retention_days() -> int:
    raw = os.environ.get("AGENT_BOM_GRAPH_RETENTION_DAYS", str(_DEFAULT_GRAPH_RETENTION_DAYS))
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_GRAPH_RETENTION_DAYS


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'virtual') AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _read_purge_state(conn: sqlite3.Connection) -> tuple[str | None, int]:
    """Return ``(last_purge_at, last_purged_count)`` for the retention state row."""
    if not _table_exists(conn, "graph_retention_state"):
        return None, 0
    try:
        row = conn.execute("SELECT last_purge_at, last_purged_count FROM graph_retention_state WHERE id = 1").fetchone()
    except sqlite3.Error:
        return None, 0
    if row is None:
        return None, 0
    last_purge_at = row[0]
    last_purged_count = row[1] if row[1] is not None else 0
    return (str(last_purge_at) if last_purge_at is not None else None), int(last_purged_count)


def _record_purge_state(conn: sqlite3.Connection, *, purged_count: int, purged_at: str) -> None:
    conn.execute(
        """
        INSERT INTO graph_retention_state (id, last_purge_at, last_purged_count)
        VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            last_purge_at = excluded.last_purge_at,
            last_purged_count = excluded.last_purged_count
        """,
        (purged_at, int(purged_count)),
    )


def _parse_iso_timestamp(value: object) -> datetime | None:
    """Parse an ISO-8601 timestamp; return ``None`` when unparseable."""
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def graph_retention_policy(
    conn: sqlite3.Connection | None = None,
    *,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Describe the active graph retention policy.

    When a connection is supplied, the response reflects real enforcement state
    (``last_purge_at`` / ``last_purged_count``) recorded by
    :func:`purge_expired_graph_snapshots`, rather than metadata alone.

    Pass ``tenant_id`` to resolve the effective retention window for one tenant
    (store override, env JSON map, then global default).
    """
    from agent_bom.api.tenant_graph_retention import graph_retention_overrides_snapshot, resolve_graph_retention_days

    normalized_tenant = normalize_graph_tenant_id(tenant_id) if tenant_id is not None else None
    policy: dict[str, Any] = {
        "retention_days": resolve_graph_retention_days(normalized_tenant),
        "default_retention_days": _graph_retention_days(),
        "mode": "queryable_snapshot_history",
        "deletion_state": "active",
        "enforcement": "age_based_purge_on_save",
        "legal_hold": False,
        **graph_retention_overrides_snapshot(),
    }
    if normalized_tenant is not None:
        policy["tenant_id"] = normalized_tenant
    if conn is not None:
        last_purge_at, last_purged_count = _read_purge_state(conn)
        policy["last_purge_at"] = last_purge_at
        policy["last_purged_count"] = last_purged_count
    return policy


def purge_expired_graph_snapshots(
    conn: sqlite3.Connection,
    *,
    retention_days: int | None = None,
    now: datetime | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Delete graph snapshots older than the retention window and their rows.

    Age-based purge keyed on ``graph_snapshots.created_at``. Runs across every
    tenant by default; pass ``tenant_id`` to scope the purge to a single tenant.

    Fail-closed: a snapshot whose ``created_at`` cannot be parsed as an ISO-8601
    timestamp is *retained*, never deleted, so malformed rows can never trigger
    unintended data loss. Deletes cascade to ``graph_nodes``, ``graph_edges``,
    ``attack_paths`` and ``interaction_risks`` for the same ``(scan_id,
    tenant_id)`` pair, plus the API search index when present.
    """
    from agent_bom.api.tenant_graph_retention import resolve_graph_retention_days

    fixed_days = None if retention_days is None else max(1, int(retention_days))
    now_dt = now or datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    query = "SELECT scan_id, tenant_id, created_at FROM graph_snapshots"
    params: list[Any] = []
    if tenant_id is not None:
        query += " WHERE tenant_id = ?"
        params.append(normalize_graph_tenant_id(tenant_id))
    rows = conn.execute(query, params).fetchall()

    expired: list[tuple[str, str]] = []
    resolved_days: dict[str, int] = {}
    for row in rows:
        tid = str(row[1])
        days = fixed_days if fixed_days is not None else resolved_days.setdefault(tid, resolve_graph_retention_days(tid))
        cutoff = now_dt - timedelta(days=days)
        created = _parse_iso_timestamp(row[2])
        if created is not None and created < cutoff:
            expired.append((str(row[0]), tid))

    if expired:
        for table in _GRAPH_PURGEABLE_TABLES:
            conn.executemany(
                f"DELETE FROM {table} WHERE scan_id = ? AND tenant_id = ?",  # nosec B608 - table names are static internal schema metadata
                expired,
            )
        if _table_exists(conn, "graph_node_search"):
            conn.executemany(
                "DELETE FROM graph_node_search WHERE scan_id = ? AND tenant_id = ?",
                expired,
            )

    purged_at = _now_iso()
    _record_purge_state(conn, purged_count=len(expired), purged_at=purged_at)
    conn.commit()

    effective_days = fixed_days if fixed_days is not None else _graph_retention_days()
    return {
        "retention_days": effective_days,
        "per_tenant_retention_days": dict(resolved_days) if fixed_days is None and resolved_days else None,
        "cutoff": (now_dt - timedelta(days=effective_days)).isoformat(),
        "purged_count": len(expired),
        "last_purge_at": purged_at,
        "purged_snapshots": [{"scan_id": scan_id, "tenant_id": tid} for scan_id, tid in expired],
    }


def _batched_rows(rows: Iterable[Sequence[Any]], batch_size: int) -> Iterator[list[Sequence[Any]]]:
    batch: list[Sequence[Any]] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def _executemany_batched(
    conn: sqlite3.Connection,
    sql: str,
    rows: Iterable[Sequence[Any]],
    *,
    batch_size: int,
) -> int:
    total = 0
    for batch in _batched_rows(rows, batch_size):
        conn.executemany(sql, batch)
        total += len(batch)
    return total


@contextmanager
def open_graph_db(db_path: str | Path) -> Generator[sqlite3.Connection, None, None]:
    """Open (or create) a graph database with schema initialisation."""
    target = str(db_path)
    # Create the parent directory up front: on a fresh deploy (new volume /
    # container, offline) ``~/.agent-bom/db`` may not exist yet, and
    # ``sqlite3.connect`` does not create missing parents — it raises
    # "unable to open database file", which silently leaves the seeded demo
    # estate with an empty graph. ``:memory:`` has no parent to create.
    if target != ":memory:":
        Path(target).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        _init_db(conn)
        yield conn
    finally:
        conn.close()


def latest_snapshot_id(conn: sqlite3.Connection, *, tenant_id: str = "") -> str:
    """Return the newest snapshot ID for a tenant, or ``""`` when absent."""
    tenant_id = normalize_graph_tenant_id(tenant_id)
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
    tenant_id = normalize_graph_tenant_id(tenant_id)
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
    tenant_id = normalize_graph_tenant_id(tenant_id)
    effective_scan_id = scan_id or latest_snapshot_id(conn, tenant_id=tenant_id)
    if not effective_scan_id:
        return "", ""
    row = conn.execute(
        "SELECT created_at FROM graph_snapshots WHERE scan_id = ? AND tenant_id = ?",
        (effective_scan_id, tenant_id),
    ).fetchone()
    return effective_scan_id, (str(row["created_at"]) if row else "")


def _digest_payload(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════
# Write — each scan is an immutable snapshot (INSERT OR REPLACE by PK)
# ═══════════════════════════════════════════════════════════════════════════


def save_graph(conn: sqlite3.Connection, graph: UnifiedGraph) -> None:
    """Persist a UnifiedGraph as an immutable per-scan snapshot.

    Thin wrapper over :func:`save_graph_streaming` — the streamed path never
    holds more than one write batch plus the prior snapshot's edge index in
    memory, so peak RSS is decoupled from graph size (see #4055). Callers that
    already hold a fully built ``UnifiedGraph`` keep the same behaviour; callers
    that can produce nodes/edges lazily should call ``save_graph_streaming``
    directly with generators to avoid materialising the whole graph.
    """
    save_graph_streaming(
        conn,
        scan_id=graph.scan_id,
        tenant_id=graph.tenant_id,
        created_at=graph.created_at,
        nodes=graph.nodes.values(),
        edges=graph.edges,
        attack_paths=graph.attack_paths,
        interaction_risks=graph.interaction_risks,
    )


def save_graph_streaming(
    conn: sqlite3.Connection,
    *,
    scan_id: str,
    tenant_id: str = "",
    nodes: Iterable[UnifiedNode],
    edges: Iterable[UnifiedEdge],
    attack_paths: Iterable[AttackPath] = (),
    interaction_risks: Iterable[InteractionRisk] = (),
    created_at: str = "",
) -> dict[str, int]:
    """Persist a graph snapshot from streamed node/edge iterables.

    Unlike :func:`save_graph`, this never requires a fully materialised
    ``UnifiedGraph``. ``nodes`` and ``edges`` are consumed lazily and flushed to
    SQLite in bounded batches, and the snapshot's node/edge/severity/type
    breakdowns are accumulated incrementally as rows stream through — so a
    producer that yields nodes/edges on the fly keeps peak RSS flat regardless
    of graph size (#4055). Writes are byte-identical to ``save_graph``.

    Precondition — the caller must yield **deduplicated** items: unique node
    ``id`` and unique ``(source, target, relationship)`` edge keys, exactly the
    invariant :class:`~agent_bom.graph.UnifiedGraph` maintains for the
    ``save_graph`` caller. The stat counters (``node_count`` / ``edge_count`` /
    severity / type breakdowns) count each *yield* — they intentionally do NOT
    hold a seen-set, because that would reintroduce the O(n) memory this path
    exists to avoid. Persisted *rows* still dedupe via ``INSERT OR REPLACE`` on
    the primary key, so a duplicate-yielding producer would leave the stat
    columns over-counting the deduped row totals. Pass a pre-deduplicated
    iterable (a ``UnifiedGraph``'s ``nodes.values()`` / ``edges`` always is).

    Returns the persisted ``{"nodes": N, "edges": M}`` counts.
    """
    tenant = normalize_graph_tenant_id(tenant_id)
    scan = scan_id
    now = created_at or _now_iso()
    batch_size = _graph_write_batch_size()
    previous_scan = latest_snapshot_id(conn, tenant_id=tenant)
    if previous_scan == scan:
        previous_scan = previous_snapshot_id(conn, tenant_id=tenant, before_scan_id=scan)
    previous_edges: dict[tuple[str, str, str], sqlite3.Row] = {}
    if previous_scan:
        for row in conn.execute(
            """
            SELECT source_id, target_id, relationship, first_seen, valid_from, valid_to
            FROM graph_edges
            WHERE tenant_id = ? AND scan_id = ?
            """,
            (tenant, previous_scan),
        ):
            previous_edges[(row["source_id"], row["target_id"], row["relationship"])] = row

    # A scan id is one complete snapshot. Retries/replays must replace that
    # snapshot atomically; upserts alone would retain rows absent from the
    # retried producer and make graph_snapshots counts contradict graph rows.
    # The first DELETE also takes SQLite's write lock, serializing concurrent
    # writers before any streamed batch is consumed.
    for table in ("attack_paths", "interaction_risks", "graph_edges", "graph_nodes", "graph_snapshots"):
        conn.execute(
            f"DELETE FROM {table} WHERE tenant_id = ? AND scan_id = ?",  # nosec B608 - static table list
            (tenant, scan),
        )

    # Incrementally accumulated snapshot stats — mirrors UnifiedGraph.stats()
    # (severity_counts only counts truthy severities; node_type_counts is every
    # node) without a second pass over a fully materialised graph.
    node_count = 0
    edge_count = 0
    severity_counts: dict[str, int] = defaultdict(int)
    type_counts: dict[str, int] = defaultdict(int)
    # Retired-edge detection: start with the prior snapshot's edge keys and
    # discard each one still present in the incoming stream. This bounds the
    # extra set to the PREVIOUS snapshot size (empty on a first save) rather
    # than tracking every incoming edge key — so peak RSS stays flat.
    removed_edge_keys: set[tuple[str, str, str]] = set(previous_edges)

    # ── Nodes ──
    def node_rows() -> Iterator[tuple[Any, ...]]:
        nonlocal node_count
        for node in nodes:
            node_count += 1
            et = node.entity_type.value if isinstance(node.entity_type, EntityType) else node.entity_type
            type_counts[et] += 1
            if node.severity:
                severity_counts[node.severity] += 1
            yield (
                node.id,
                et,
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

    _executemany_batched(
        conn,
        """\
        INSERT OR REPLACE INTO graph_nodes (
            id, entity_type, label, category_uid, class_uid, type_uid,
            status, risk_score, severity, severity_id,
            first_seen, last_seen, attributes, compliance_tags,
            data_sources, dimensions, scan_id, tenant_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        node_rows(),
        batch_size=batch_size,
    )

    # ── Edges ──
    def edge_rows() -> Iterator[tuple[Any, ...]]:
        nonlocal edge_count
        for edge in edges:
            edge_count += 1
            rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
            removed_edge_keys.discard((edge.source, edge.target, rel))
            previous = previous_edges.get((edge.source, edge.target, rel))
            valid_from = edge.valid_from or edge.first_seen or now
            first_seen = edge.first_seen
            if previous is not None:
                valid_from = previous["valid_from"] or previous["first_seen"] or valid_from
                first_seen = previous["first_seen"] or first_seen
            elif valid_from > now:
                valid_from = now
            yield (
                edge.source,
                edge.target,
                rel,
                edge.direction,
                edge.weight,
                1 if edge.traversable else 0,
                first_seen,
                edge.last_seen,
                valid_from,
                edge.valid_to,
                edge.confidence,
                json.dumps(edge.provenance, default=str),
                edge.source_scan_id or scan,
                edge.source_run_id,
                json.dumps(edge.evidence, default=str),
                edge.activity_id,
                scan,
                tenant,
            )

    _executemany_batched(
        conn,
        """\
        INSERT OR REPLACE INTO graph_edges (
            source_id, target_id, relationship, direction, weight,
            traversable, first_seen, last_seen, valid_from, valid_to,
            confidence, provenance, source_scan_id, source_run_id, evidence,
            activity_id, scan_id, tenant_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        edge_rows(),
        batch_size=batch_size,
    )

    if removed_edge_keys:
        _executemany_batched(
            conn,
            """
            UPDATE graph_edges
            SET valid_to = COALESCE(valid_to, ?)
            WHERE tenant_id = ? AND scan_id = ? AND source_id = ? AND target_id = ? AND relationship = ?
            """,
            ((now, tenant, previous_scan, source, target, relationship) for source, target, relationship in sorted(removed_edge_keys)),
            batch_size=batch_size,
        )

    # ── Attack paths ──
    attack_path_count = 0
    for ap in attack_paths:
        attack_path_count += 1
        conn.execute(
            """\
            INSERT OR REPLACE INTO attack_paths (
                source_node, target_node, hop_count, composite_risk,
                summary, path_nodes, path_edges, credential_exposure,
                tool_exposure, vuln_ids, scan_id, tenant_id, computed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ap.source,
                ap.target,
                len(ap.hops),
                ap.composite_risk,
                ap.summary,
                json.dumps(ap.hops),
                json.dumps(ap.edges),
                json.dumps(ap.credential_exposure),
                json.dumps(ap.tool_exposure),
                json.dumps(ap.vuln_ids),
                scan,
                tenant,
                now,
            ),
        )

    # ── Interaction risks ──
    for ir in interaction_risks:
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
    # Materialise the entity-type and severity breakdowns alongside the node/edge
    # totals so inventory/summary serves them from this row instead of running a
    # GROUP BY over every node per request (O(N) → O(1)). ``risk_summary`` already
    # carries the severity breakdown; ``node_type_counts`` adds the entity types.
    conn.execute(
        """
        INSERT OR REPLACE INTO graph_snapshots
            (scan_id, tenant_id, created_at, node_count, edge_count, risk_summary, node_type_counts)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan,
            tenant,
            now,
            node_count,
            edge_count,
            json.dumps(dict(severity_counts)),
            json.dumps(dict(type_counts)),
        ),
    )

    conn.commit()
    logger.info(
        "Saved graph: %d nodes, %d edges, %d attack paths (scan=%s)",
        node_count,
        edge_count,
        attack_path_count,
        scan,
    )

    # Enforce age-based retention on the post-save lifecycle hook. A purge
    # failure must never fail the durable save that already committed above, so
    # it is best-effort and logged with sanitized text.
    try:
        result = purge_expired_graph_snapshots(conn)
        if result["purged_count"]:
            logger.info("Purged %d expired graph snapshot(s)", result["purged_count"])
    except sqlite3.Error as exc:
        logger.warning("Graph snapshot retention purge skipped: %s", sanitize_text(str(exc)))

    return {"nodes": node_count, "edges": edge_count}


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
    relationship_types: frozenset[str] | None = None,
) -> UnifiedGraph:
    """Load a UnifiedGraph from a specific scan snapshot."""
    tenant_id = normalize_graph_tenant_id(tenant_id)
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
    if relationship_types:
        placeholders = ",".join("?" * len(relationship_types))
        eq += f" AND relationship IN ({placeholders})"
        eparams.extend(sorted(relationship_types))
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
                valid_from=row["valid_from"] or row["first_seen"],
                valid_to=row["valid_to"],
                confidence=row["confidence"],
                provenance=json.loads(row["provenance"] or "{}"),
                source_scan_id=row["source_scan_id"] or row["scan_id"],
                source_run_id=row["source_run_id"] or "",
                evidence=json.loads(row["evidence"]),
                activity_id=row["activity_id"],
            )
        )

    if not relationship_types:
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
                    summary=row["summary"] or "",
                    credential_exposure=json.loads(row["credential_exposure"]),
                    tool_exposure=json.loads(row["tool_exposure"]),
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


def prior_delta_digest(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
) -> "PriorSnapshotDigest":
    """Build a bounded prior-snapshot digest for delta-alert computation.

    Streams only the columns :func:`agent_bom.graph.webhooks.compute_delta_alerts`
    reads from the prior graph (node ids, agent refs, attack-path and
    interaction-risk keys) instead of materialising a full ``UnifiedGraph`` — so
    peak RSS is decoupled from the prior snapshot's node/edge payload (#4055,
    #4075). The digest yields byte-identical delta alerts to the full-graph path.
    """
    from agent_bom.graph.delta_digest import PriorSnapshotDigestBuilder

    tenant_id = normalize_graph_tenant_id(tenant_id)
    builder = PriorSnapshotDigestBuilder()
    effective_scan_id, _created_at = _resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
    if not effective_scan_id:
        return builder.build()
    for row in conn.execute(
        "SELECT id, entity_type, label, severity, status, risk_score FROM graph_nodes WHERE tenant_id = ? AND scan_id = ?",
        (tenant_id, effective_scan_id),
    ):
        builder.add_node(
            row["id"],
            row["entity_type"],
            label=row["label"],
            severity=row["severity"] or "",
            status=row["status"],
            risk_score=row["risk_score"],
        )
    for row in conn.execute(
        "SELECT source_node, target_node FROM attack_paths WHERE tenant_id = ? AND scan_id = ?",
        (tenant_id, effective_scan_id),
    ):
        builder.add_attack_path(row["source_node"], row["target_node"])
    for row in conn.execute(
        "SELECT pattern, agents FROM interaction_risks WHERE tenant_id = ? AND scan_id = ?",
        (tenant_id, effective_scan_id),
    ):
        builder.add_interaction_risk(row["pattern"], json.loads(row["agents"]))
    return builder.build()


def _node_from_snapshot_row(row: sqlite3.Row) -> UnifiedNode:
    return UnifiedNode(
        id=row["id"],
        entity_type=EntityType(row["entity_type"]),
        label=row["label"],
        category_uid=row["category_uid"],
        class_uid=row["class_uid"],
        type_uid=row["type_uid"],
        status=NodeStatus(row["status"]),
        risk_score=row["risk_score"],
        severity=row["severity"] or "",
        severity_id=row["severity_id"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        attributes=json.loads(row["attributes"]),
        compliance_tags=json.loads(row["compliance_tags"]),
        data_sources=json.loads(row["data_sources"]),
        dimensions=NodeDimensions.from_dict(json.loads(row["dimensions"])),
    )


def _edge_from_snapshot_row(row: sqlite3.Row) -> UnifiedEdge:
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


def iter_graph_nodes(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
    entity_types: set[str] | None = None,
    min_severity_rank: int = 0,
) -> Iterator[UnifiedNode]:
    """Yield a snapshot's nodes one at a time without building a ``UnifiedGraph``.

    Bounded-memory read primitive for callers that genuinely need to iterate the
    whole graph (export, counting, streaming transforms) but do not need the
    adjacency indexes ``load_graph`` builds — peak RSS stays flat as the snapshot
    grows (#4055). ``sqlite3`` streams rows from the cursor lazily.
    """
    tenant_id = normalize_graph_tenant_id(tenant_id)
    effective_scan_id, _created_at = _resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
    if not effective_scan_id:
        return
    query = "SELECT * FROM graph_nodes WHERE tenant_id = ? AND scan_id = ?"
    params: list[Any] = [tenant_id, effective_scan_id]
    if entity_types:
        placeholders = ",".join("?" * len(entity_types))
        query += f" AND entity_type IN ({placeholders})"  # nosec B608 - placeholders are only "?" markers
        params.extend(sorted(entity_types))
    for row in conn.execute(query, params):
        if min_severity_rank and SEVERITY_RANK.get(row["severity"] or "", 0) < min_severity_rank:
            continue
        yield _node_from_snapshot_row(row)


def iter_graph_edges(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
    relationship_types: frozenset[str] | None = None,
    node_ids: set[str] | None = None,
) -> Iterator[UnifiedEdge]:
    """Yield a snapshot's edges one at a time without building a ``UnifiedGraph``.

    Endpoint handling — intentionally different from :func:`load_graph`, which
    reconstructs a consistent graph and therefore *always* drops an edge whose
    endpoints are not both in the loaded node set. This is a raw snapshot read:
    when ``node_ids`` is given, only edges whose both endpoints are in that set
    are yielded — reproducing ``load_graph``'s endpoint filter for the case where
    the node stream was itself filtered. When ``node_ids`` is omitted, *every*
    persisted edge is yielded (both endpoints exist by construction for a full
    snapshot; a dangling edge from partial/corrupt data would be yielded here but
    dropped by ``load_graph``). Pass the loaded node-id set to get parity.
    """
    tenant_id = normalize_graph_tenant_id(tenant_id)
    effective_scan_id, _created_at = _resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
    if not effective_scan_id:
        return
    query = "SELECT * FROM graph_edges WHERE tenant_id = ? AND scan_id = ?"
    params: list[Any] = [tenant_id, effective_scan_id]
    if relationship_types:
        placeholders = ",".join("?" * len(relationship_types))
        query += f" AND relationship IN ({placeholders})"  # nosec B608 - placeholders are only "?" markers
        params.extend(sorted(relationship_types))
    for row in conn.execute(query, params):
        if node_ids is not None and (row["source_id"] not in node_ids or row["target_id"] not in node_ids):
            continue
        yield _edge_from_snapshot_row(row)


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
    from agent_bom.graph.drift_attributes import attribute_deltas, node_diff_metadata, node_snapshot_changed

    tenant_id = normalize_graph_tenant_id(tenant_id)

    def _load_nodes(scan_id: str) -> dict[str, dict[str, Any]]:
        loaded: dict[str, dict[str, Any]] = {}
        for row in conn.execute(
            """
            SELECT id, entity_type, label, status, severity, severity_id, risk_score,
                   attributes, compliance_tags
            FROM graph_nodes
            WHERE scan_id = ? AND tenant_id = ?
            """,
            (scan_id, tenant_id),
        ):
            loaded[row["id"]] = node_diff_metadata(
                node_id=row["id"],
                entity_type=row["entity_type"],
                label=row["label"],
                status=row["status"],
                severity=row["severity"],
                severity_id=int(row["severity_id"] or 0),
                risk_score=float(row["risk_score"] or 0.0),
                attributes=row["attributes"],
                compliance_tags=row["compliance_tags"],
            )
        return loaded

    old_nodes = _load_nodes(scan_id_old)
    new_nodes = _load_nodes(scan_id_new)

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
        "edges_changed": changed_edges_between_scans(conn, scan_id_old, scan_id_new, tenant_id=tenant_id)["edges_changed"],
    }


def _edge_history_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "source_id": row["source_id"],
        "target_id": row["target_id"],
        "relationship": row["relationship"],
        "direction": row["direction"],
        "weight": float(row["weight"] or 0.0),
        "traversable": bool(row["traversable"]),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "valid_from": row["valid_from"] or row["first_seen"],
        "valid_to": row["valid_to"],
        "confidence": float(row["confidence"] if row["confidence"] is not None else 1.0),
        "provenance": json.loads(row["provenance"] or "{}"),
        "source_scan_id": row["source_scan_id"] or row["scan_id"],
        "source_run_id": row["source_run_id"] or "",
        "evidence": json.loads(row["evidence"] or "{}"),
        "activity_id": int(row["activity_id"] or 1),
        "scan_id": row["scan_id"],
        "tenant_id": row["tenant_id"],
    }


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


def active_edges_at(conn: sqlite3.Connection, at: str, *, tenant_id: str = "") -> list[dict[str, Any]]:
    """Return the latest known edge versions active at an ISO timestamp."""
    tenant_id = normalize_graph_tenant_id(tenant_id)
    rows = conn.execute(
        """
        SELECT ge.*
        FROM graph_edges ge
        JOIN graph_snapshots gs ON gs.tenant_id = ge.tenant_id AND gs.scan_id = ge.scan_id
        WHERE ge.tenant_id = ?
          AND gs.created_at <= ?
          AND COALESCE(NULLIF(ge.valid_from, ''), ge.first_seen) <= ?
          AND (ge.valid_to IS NULL OR ge.valid_to = '' OR ge.valid_to > ?)
        ORDER BY gs.created_at ASC, ge.scan_id ASC
        """,
        (tenant_id, at, at, at),
    ).fetchall()
    active_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        edge = _edge_history_row(row)
        key = (edge["source_id"], edge["target_id"], edge["relationship"])
        active_by_key[key] = edge
    return [active_by_key[key] for key in sorted(active_by_key)]


def changed_edges_between_scans(
    conn: sqlite3.Connection,
    scan_id_old: str,
    scan_id_new: str,
    *,
    tenant_id: str = "",
) -> dict[str, Any]:
    """Return rich edge lifecycle changes between two scan snapshots."""
    tenant_id = normalize_graph_tenant_id(tenant_id)

    def rows_for(scan_id: str) -> dict[tuple[str, str, str], dict[str, Any]]:
        rows = conn.execute(
            "SELECT * FROM graph_edges WHERE scan_id = ? AND tenant_id = ?",
            (scan_id, tenant_id),
        ).fetchall()
        return {(edge["source_id"], edge["target_id"], edge["relationship"]): edge for edge in (_edge_history_row(row) for row in rows)}

    old_edges = rows_for(scan_id_old)
    new_edges = rows_for(scan_id_new)
    old_keys, new_keys = set(old_edges), set(new_edges)
    shared = old_keys & new_keys
    changed = [
        {"before": old_edges[key], "after": new_edges[key]}
        for key in sorted(shared)
        if _edge_change_fingerprint(old_edges[key]) != _edge_change_fingerprint(new_edges[key])
    ]
    unchanged = [
        new_edges[key] for key in sorted(shared) if _edge_change_fingerprint(old_edges[key]) == _edge_change_fingerprint(new_edges[key])
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


def list_snapshots(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    limit: int = 50,
    since: str | None = None,
) -> list[dict[str, Any]]:
    """List recent graph snapshots ordered by creation time desc.

    ``since`` (an ISO-8601 cutoff) bounds the result to snapshots created within
    the read window; pass ``None`` to return all retained history.
    """
    tenant_id = normalize_graph_tenant_id(tenant_id)
    where = "WHERE tenant_id = ?"
    params: list[Any] = [tenant_id]
    if since:
        where += " AND created_at >= ?"
        params.append(since)
    params.append(limit)
    rows = conn.execute(
        f"""\
        SELECT scan_id, created_at, node_count, edge_count, risk_summary
        FROM graph_snapshots
        {where}
        ORDER BY created_at DESC LIMIT ?
        """,  # nosec B608 - where clause is composed from static fragments only
        params,
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


def _diff_summary_counts(diff: dict[str, Any]) -> dict[str, int]:
    return {
        "nodes_added": len(diff.get("nodes_added") or []),
        "nodes_removed": len(diff.get("nodes_removed") or []),
        "nodes_changed": len(diff.get("nodes_changed") or []),
        "edges_added": len(diff.get("edges_added") or []),
        "edges_removed": len(diff.get("edges_removed") or []),
        "edges_changed": len(diff.get("edges_changed") or []),
    }


def _snapshot_digests(conn: sqlite3.Connection, *, tenant_id: str, scan_id: str) -> tuple[str, str, dict[str, int]]:
    graph_rows: dict[str, list[dict[str, Any]]] = {"nodes": [], "edges": []}
    finding_rows: dict[str, list[dict[str, Any]]] = {"findings": [], "attack_paths": [], "compliance": []}

    for row in conn.execute(
        """
        SELECT id, entity_type, label, status, severity, severity_id, risk_score,
               compliance_tags, data_sources
        FROM graph_nodes
        WHERE tenant_id = ? AND scan_id = ?
        ORDER BY id
        """,
        (tenant_id, scan_id),
    ):
        node = {
            "id": row["id"],
            "entity_type": row["entity_type"],
            "label": row["label"],
            "status": row["status"],
            "severity": row["severity"] or "",
            "severity_id": int(row["severity_id"] or 0),
            "risk_score": float(row["risk_score"] or 0.0),
            "compliance_tags": json.loads(row["compliance_tags"] or "[]"),
            "data_sources": json.loads(row["data_sources"] or "[]"),
        }
        graph_rows["nodes"].append(node)
        if row["entity_type"] in _FINDING_ENTITY_TYPES:
            finding_rows["findings"].append(node)
        for tag in node["compliance_tags"]:
            finding_rows["compliance"].append({"node_id": row["id"], "tag": tag})

    for row in conn.execute(
        """
        SELECT source_id, target_id, relationship, direction, weight, traversable,
               valid_from, valid_to, confidence, activity_id
        FROM graph_edges
        WHERE tenant_id = ? AND scan_id = ?
        ORDER BY source_id, target_id, relationship
        """,
        (tenant_id, scan_id),
    ):
        graph_rows["edges"].append(
            {
                "source_id": row["source_id"],
                "target_id": row["target_id"],
                "relationship": row["relationship"],
                "direction": row["direction"],
                "weight": float(row["weight"] or 0.0),
                "traversable": bool(row["traversable"]),
                "valid_from": row["valid_from"] or "",
                "valid_to": row["valid_to"] or "",
                "confidence": float(row["confidence"] if row["confidence"] is not None else 1.0),
                "activity_id": int(row["activity_id"] or 1),
            }
        )

    for row in conn.execute(
        """
        SELECT source_node, target_node, hop_count, composite_risk, summary,
               path_nodes, path_edges, tool_exposure, vuln_ids
        FROM attack_paths
        WHERE tenant_id = ? AND scan_id = ?
        ORDER BY source_node, target_node
        """,
        (tenant_id, scan_id),
    ):
        finding_rows["attack_paths"].append(
            {
                "source_node": row["source_node"],
                "target_node": row["target_node"],
                "hop_count": int(row["hop_count"] or 0),
                "composite_risk": float(row["composite_risk"] or 0.0),
                "summary": row["summary"] or "",
                "path_nodes": json.loads(row["path_nodes"] or "[]"),
                "path_edges": json.loads(row["path_edges"] or "[]"),
                "tool_exposure": json.loads(row["tool_exposure"] or "[]"),
                "vuln_ids": json.loads(row["vuln_ids"] or "[]"),
            }
        )

    counts = {
        "nodes": len(graph_rows["nodes"]),
        "edges": len(graph_rows["edges"]),
        "findings": len(finding_rows["findings"]),
        "attack_paths": len(finding_rows["attack_paths"]),
        "compliance_tags": len(finding_rows["compliance"]),
    }
    return _digest_payload(graph_rows), _digest_payload(finding_rows), counts


def graph_evidence_manifest(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
    baseline_scan_id: str = "",
) -> dict[str, Any]:
    """Build a redaction-aware evidence manifest for one retained graph snapshot."""
    tenant_id = normalize_graph_tenant_id(tenant_id)
    effective_scan_id, created_at = _resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
    if not effective_scan_id:
        return {
            "schema_version": "agent-bom.graph_evidence_manifest/v1",
            "tenant_id": tenant_id,
            "scan_id": "",
            "generated_at": _now_iso(),
            "retention_policy": graph_retention_policy(conn),
            "included_tables": list(_GRAPH_EVIDENCE_INCLUDED_TABLES),
            "excluded_private_fields": list(_GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS),
        }

    baseline = baseline_scan_id or previous_snapshot_id(conn, tenant_id=tenant_id, before_scan_id=effective_scan_id)
    graph_digest, findings_digest, counts = _snapshot_digests(conn, tenant_id=tenant_id, scan_id=effective_scan_id)
    diff_summary = _diff_summary_counts(diff_snapshots(conn, baseline, effective_scan_id, tenant_id=tenant_id)) if baseline else {}

    return {
        "schema_version": "agent-bom.graph_evidence_manifest/v1",
        "tenant_id": tenant_id,
        "scan_id": effective_scan_id,
        "generated_at": _now_iso(),
        "scan_created_at": created_at,
        "graph_digest": graph_digest,
        "findings_digest": findings_digest,
        "diff_baseline_scan_id": baseline,
        "diff_summary": diff_summary,
        "counts": counts,
        "included_tables": list(_GRAPH_EVIDENCE_INCLUDED_TABLES),
        "excluded_private_fields": list(_GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS),
        "retention_policy": graph_retention_policy(conn),
    }


def graph_history(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    limit: int = 50,
    since: str | None = None,
) -> dict[str, Any]:
    """Return retained graph snapshot history with adjacent diff summaries.

    ``since`` bounds the returned snapshots to the read window (ISO-8601 cutoff);
    ``None`` returns all retained history.
    """
    tenant_id = normalize_graph_tenant_id(tenant_id)
    snapshots = list_snapshots(conn, tenant_id=tenant_id, limit=limit, since=since)
    history: list[dict[str, Any]] = []
    for snapshot in snapshots:
        scan_id = snapshot["scan_id"]
        baseline = previous_snapshot_id(conn, tenant_id=tenant_id, before_scan_id=scan_id)
        diff_summary = _diff_summary_counts(diff_snapshots(conn, baseline, scan_id, tenant_id=tenant_id)) if baseline else {}
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
        "retention_policy": graph_retention_policy(conn),
        "snapshots": history,
    }
