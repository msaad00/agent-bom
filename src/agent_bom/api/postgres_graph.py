"""PostgreSQL-backed graph and cache stores."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.graph_store import _escape_like_query, _node_search_text, decode_graph_cursor, encode_graph_cursor

from .postgres_common import _ensure_tenant_rls, _get_pool, _tenant_connection


class PostgresGraphStore:
    """PostgreSQL-backed unified graph persistence and query store."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    category_uid INTEGER DEFAULT 0,
                    class_uid INTEGER DEFAULT 0,
                    type_uid INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active',
                    risk_score DOUBLE PRECISION DEFAULT 0.0,
                    severity TEXT DEFAULT '',
                    severity_id INTEGER DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    attributes TEXT DEFAULT '{}',
                    compliance_tags TEXT DEFAULT '[]',
                    data_sources TEXT DEFAULT '[]',
                    dimensions TEXT DEFAULT '{}',
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    PRIMARY KEY (id, scan_id, tenant_id)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_nodes_entity_type ON graph_nodes(entity_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_nodes_scan ON graph_nodes(tenant_id, scan_id)")
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_pg_graph_nodes_scan_order
                ON graph_nodes(tenant_id, scan_id, severity_id DESC, risk_score DESC, label)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS graph_edges (
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relationship TEXT NOT NULL,
                    direction TEXT DEFAULT 'directed',
                    weight DOUBLE PRECISION DEFAULT 1.0,
                    traversable INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    evidence TEXT DEFAULT '{}',
                    activity_id INTEGER DEFAULT 1,
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    PRIMARY KEY (source_id, target_id, relationship, scan_id, tenant_id)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_edges_scan ON graph_edges(tenant_id, scan_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_edges_scan_source ON graph_edges(tenant_id, scan_id, source_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_edges_scan_target ON graph_edges(tenant_id, scan_id, target_id)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS graph_snapshots (
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    created_at TEXT NOT NULL,
                    node_count INTEGER DEFAULT 0,
                    edge_count INTEGER DEFAULT 0,
                    risk_summary TEXT DEFAULT '{}',
                    PRIMARY KEY (scan_id, tenant_id)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_snapshots_recent ON graph_snapshots(tenant_id, created_at DESC)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_paths (
                    source_node TEXT NOT NULL,
                    target_node TEXT NOT NULL,
                    hop_count INTEGER DEFAULT 0,
                    composite_risk DOUBLE PRECISION DEFAULT 0.0,
                    path_nodes TEXT DEFAULT '[]',
                    path_edges TEXT DEFAULT '[]',
                    credential_exposure TEXT DEFAULT '[]',
                    vuln_ids TEXT DEFAULT '[]',
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    computed_at TEXT NOT NULL,
                    PRIMARY KEY (source_node, target_node, scan_id, tenant_id)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_attack_paths_scan ON attack_paths(tenant_id, scan_id)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_pg_attack_paths_scan_risk ON attack_paths(tenant_id, scan_id, composite_risk DESC)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS interaction_risks (
                    pattern TEXT NOT NULL,
                    agents TEXT NOT NULL,
                    risk_score DOUBLE PRECISION DEFAULT 0.0,
                    description TEXT DEFAULT '',
                    owasp_agentic_tag TEXT DEFAULT NULL,
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    PRIMARY KEY (pattern, agents, scan_id, tenant_id)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_interaction_risks_scan ON interaction_risks(tenant_id, scan_id)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS graph_filter_presets (
                    name TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    description TEXT DEFAULT '',
                    filters TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (name, tenant_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS graph_node_search (
                    node_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    scan_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    severity TEXT DEFAULT '',
                    compliance_tags TEXT DEFAULT '',
                    data_sources TEXT DEFAULT '',
                    search_text TEXT NOT NULL,
                    PRIMARY KEY (node_id, scan_id, tenant_id)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_pg_graph_node_search_scope
                ON graph_node_search(tenant_id, scan_id, entity_type)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_pg_graph_node_search_severity
                ON graph_node_search(tenant_id, scan_id, severity)
                """
            )
            try:
                conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_pg_graph_node_search_trgm
                    ON graph_node_search USING gin (search_text gin_trgm_ops)
                    """
                )
            except Exception:
                # Some managed Postgres environments restrict extension installs.
                conn.rollback()
            _ensure_tenant_rls(conn, "graph_nodes", "tenant_id")
            _ensure_tenant_rls(conn, "graph_edges", "tenant_id")
            _ensure_tenant_rls(conn, "graph_snapshots", "tenant_id")
            _ensure_tenant_rls(conn, "attack_paths", "tenant_id")
            _ensure_tenant_rls(conn, "interaction_risks", "tenant_id")
            _ensure_tenant_rls(conn, "graph_filter_presets", "tenant_id")
            _ensure_tenant_rls(conn, "graph_node_search", "tenant_id")
            conn.commit()

    def latest_snapshot_id(self, *, tenant_id: str = "") -> str:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """
                SELECT scan_id
                FROM graph_snapshots
                WHERE tenant_id = %s
                ORDER BY created_at DESC, scan_id DESC
                LIMIT 1
                """,
                (tenant_id,),
            ).fetchone()
            return str(row[0]) if row else ""

    @staticmethod
    def _node_from_row(row):
        from agent_bom.graph import EntityType, NodeDimensions, NodeStatus, UnifiedNode

        return UnifiedNode(
            id=row[0],
            entity_type=EntityType(row[1]),
            label=row[2],
            category_uid=row[3],
            class_uid=row[4],
            type_uid=row[5],
            status=NodeStatus(row[6]),
            risk_score=row[7],
            severity=row[8] or "",
            severity_id=row[9],
            first_seen=row[10],
            last_seen=row[11],
            attributes=json.loads(row[12]),
            compliance_tags=json.loads(row[13]),
            data_sources=json.loads(row[14]),
            dimensions=NodeDimensions.from_dict(json.loads(row[15])),
        )

    def previous_snapshot_id(self, *, tenant_id: str = "", before_scan_id: str = "") -> str:
        if not before_scan_id:
            return ""
        with _tenant_connection(self._pool) as conn:
            current = conn.execute(
                "SELECT created_at FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, before_scan_id),
            ).fetchone()
            if not current:
                return ""
            row = conn.execute(
                """
                SELECT scan_id
                FROM graph_snapshots
                WHERE tenant_id = %s AND created_at < %s
                ORDER BY created_at DESC, scan_id DESC
                LIMIT 1
                """,
                (tenant_id, current[0]),
            ).fetchone()
            return str(row[0]) if row else ""

    def save_graph(self, graph) -> None:
        from agent_bom.graph import RelationshipType

        scan = graph.scan_id or ""
        tenant = graph.tenant_id or "default"
        now = graph.created_at or datetime.now(timezone.utc).isoformat()

        with _tenant_connection(self._pool) as conn:
            for node in graph.nodes.values():
                conn.execute(
                    """
                    INSERT INTO graph_nodes (
                        id, entity_type, label, category_uid, class_uid, type_uid,
                        status, risk_score, severity, severity_id,
                        first_seen, last_seen, attributes, compliance_tags,
                        data_sources, dimensions, scan_id, tenant_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id, scan_id, tenant_id) DO UPDATE SET
                        entity_type = EXCLUDED.entity_type,
                        label = EXCLUDED.label,
                        category_uid = EXCLUDED.category_uid,
                        class_uid = EXCLUDED.class_uid,
                        type_uid = EXCLUDED.type_uid,
                        status = EXCLUDED.status,
                        risk_score = EXCLUDED.risk_score,
                        severity = EXCLUDED.severity,
                        severity_id = EXCLUDED.severity_id,
                        first_seen = EXCLUDED.first_seen,
                        last_seen = EXCLUDED.last_seen,
                        attributes = EXCLUDED.attributes,
                        compliance_tags = EXCLUDED.compliance_tags,
                        data_sources = EXCLUDED.data_sources,
                        dimensions = EXCLUDED.dimensions
                    """,
                    (
                        node.id,
                        node.entity_type.value if hasattr(node.entity_type, "value") else node.entity_type,
                        node.label,
                        node.category_uid,
                        node.class_uid,
                        node.type_uid,
                        node.status.value if hasattr(node.status, "value") else node.status,
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
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO graph_node_search (
                        node_id, tenant_id, scan_id, entity_type, severity, compliance_tags, data_sources, search_text
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (node_id, scan_id, tenant_id) DO UPDATE SET
                        entity_type = EXCLUDED.entity_type,
                        severity = EXCLUDED.severity,
                        compliance_tags = EXCLUDED.compliance_tags,
                        data_sources = EXCLUDED.data_sources,
                        search_text = EXCLUDED.search_text
                    """,
                    (
                        node.id,
                        tenant,
                        scan,
                        node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type),
                        (node.severity or "").lower(),
                        " ".join(node.compliance_tags).lower(),
                        " ".join(node.data_sources).lower(),
                        _node_search_text(node),
                    ),
                )

            for edge in graph.edges:
                rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else edge.relationship
                conn.execute(
                    """
                    INSERT INTO graph_edges (
                        source_id, target_id, relationship, direction, weight,
                        traversable, first_seen, last_seen, evidence,
                        activity_id, scan_id, tenant_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (source_id, target_id, relationship, scan_id, tenant_id) DO UPDATE SET
                        direction = EXCLUDED.direction,
                        weight = EXCLUDED.weight,
                        traversable = EXCLUDED.traversable,
                        first_seen = EXCLUDED.first_seen,
                        last_seen = EXCLUDED.last_seen,
                        evidence = EXCLUDED.evidence,
                        activity_id = EXCLUDED.activity_id
                    """,
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
                    ),
                )

            for ap in graph.attack_paths:
                conn.execute(
                    """
                    INSERT INTO attack_paths (
                        source_node, target_node, hop_count, composite_risk,
                        path_nodes, path_edges, credential_exposure, vuln_ids,
                        scan_id, tenant_id, computed_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (source_node, target_node, scan_id, tenant_id) DO UPDATE SET
                        hop_count = EXCLUDED.hop_count,
                        composite_risk = EXCLUDED.composite_risk,
                        path_nodes = EXCLUDED.path_nodes,
                        path_edges = EXCLUDED.path_edges,
                        credential_exposure = EXCLUDED.credential_exposure,
                        vuln_ids = EXCLUDED.vuln_ids,
                        computed_at = EXCLUDED.computed_at
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

            for ir in graph.interaction_risks:
                conn.execute(
                    """
                    INSERT INTO interaction_risks (
                        pattern, agents, risk_score, description,
                        owasp_agentic_tag, scan_id, tenant_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (pattern, agents, scan_id, tenant_id) DO UPDATE SET
                        risk_score = EXCLUDED.risk_score,
                        description = EXCLUDED.description,
                        owasp_agentic_tag = EXCLUDED.owasp_agentic_tag
                    """,
                    (
                        ir.pattern,
                        json.dumps(sorted(ir.agents)),
                        ir.risk_score,
                        ir.description,
                        ir.owasp_agentic_tag,
                        scan,
                        tenant,
                    ),
                )

            stats = graph.stats()
            conn.execute(
                """
                INSERT INTO graph_snapshots (scan_id, tenant_id, created_at, node_count, edge_count, risk_summary)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (scan_id, tenant_id) DO UPDATE SET
                    created_at = EXCLUDED.created_at,
                    node_count = EXCLUDED.node_count,
                    edge_count = EXCLUDED.edge_count,
                    risk_summary = EXCLUDED.risk_summary
                """,
                (
                    scan,
                    tenant,
                    now,
                    stats["total_nodes"],
                    stats["total_edges"],
                    json.dumps(stats.get("severity_counts", {})),
                ),
            )
            conn.commit()

    def load_graph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ):
        from agent_bom.graph import (
            SEVERITY_RANK,
            AttackPath,
            InteractionRisk,
            RelationshipType,
            UnifiedEdge,
            UnifiedGraph,
        )

        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)

        with _tenant_connection(self._pool) as conn:
            snapshot_row = conn.execute(
                "SELECT created_at FROM graph_snapshots WHERE scan_id = %s AND tenant_id = %s",
                (effective_scan_id, tenant_id),
            ).fetchone()
            graph = UnifiedGraph(scan_id=effective_scan_id, tenant_id=tenant_id, created_at=str(snapshot_row[0]) if snapshot_row else "")

            query = (
                "SELECT id, entity_type, label, category_uid, class_uid, type_uid, status, risk_score, severity, severity_id, "
                "first_seen, last_seen, attributes, compliance_tags, data_sources, dimensions "
                "FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s"
            )
            params: list[Any] = [tenant_id, effective_scan_id]
            if entity_types:
                placeholders = ",".join(["%s"] * len(entity_types))
                query += f" AND entity_type IN ({placeholders})"
                params.extend(sorted(entity_types))

            node_ids: set[str] = set()
            for row in conn.execute(query, params).fetchall():
                severity = row[8] or ""
                if min_severity_rank and SEVERITY_RANK.get(severity, 0) < min_severity_rank:
                    continue
                graph.add_node(self._node_from_row(row))
                node_ids.add(row[0])

            for row in conn.execute(
                """
                SELECT source_id, target_id, relationship, direction, weight, traversable,
                       first_seen, last_seen, evidence, activity_id
                FROM graph_edges
                WHERE tenant_id = %s AND scan_id = %s
                """,
                (tenant_id, effective_scan_id),
            ).fetchall():
                if row[0] not in node_ids or row[1] not in node_ids:
                    continue
                graph.add_edge(
                    UnifiedEdge(
                        source=row[0],
                        target=row[1],
                        relationship=RelationshipType(row[2]),
                        direction=row[3],
                        weight=row[4],
                        traversable=bool(row[5]),
                        first_seen=row[6],
                        last_seen=row[7],
                        evidence=json.loads(row[8]),
                        activity_id=row[9],
                    )
                )

            for row in conn.execute(
                """
                SELECT source_node, target_node, path_nodes, path_edges, composite_risk, credential_exposure, vuln_ids
                FROM attack_paths
                WHERE tenant_id = %s AND scan_id = %s
                """,
                (tenant_id, effective_scan_id),
            ).fetchall():
                graph.attack_paths.append(
                    AttackPath(
                        source=row[0],
                        target=row[1],
                        hops=json.loads(row[2]),
                        edges=json.loads(row[3]),
                        composite_risk=row[4],
                        credential_exposure=json.loads(row[5]),
                        vuln_ids=json.loads(row[6]),
                    )
                )

            for row in conn.execute(
                """
                SELECT pattern, agents, risk_score, description, owasp_agentic_tag
                FROM interaction_risks
                WHERE tenant_id = %s AND scan_id = %s
                """,
                (tenant_id, effective_scan_id),
            ).fetchall():
                graph.interaction_risks.append(
                    InteractionRisk(
                        pattern=row[0],
                        agents=json.loads(row[1]),
                        risk_score=row[2],
                        description=row[3],
                        owasp_agentic_tag=row[4],
                    )
                )

            return graph

    def nodes_by_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[Any]:
        if not node_ids:
            return []
        graph = self.load_graph(tenant_id=tenant_id, scan_id=scan_id)
        return [node for node_id, node in graph.nodes.items() if node_id in node_ids]

    def bfs_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source: str,
        max_depth: int = 4,
        traversable_only: bool = True,
    ) -> tuple[list[list[str]], set[str]]:
        graph = self.load_graph(tenant_id=tenant_id, scan_id=scan_id)
        if not graph.has_node(source):
            return [], set()
        paths = graph.bfs(source, max_depth=max_depth, traversable_only=traversable_only)
        reachable = graph.reachable_from(
            source,
            max_depth=max_depth,
            traversable_only=traversable_only,
            include_source=False,
        )
        return paths, reachable

    def impact_of(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
        max_depth: int = 4,
    ) -> dict[str, Any] | None:
        graph = self.load_graph(tenant_id=tenant_id, scan_id=scan_id)
        if not graph.has_node(node_id):
            return None
        return graph.impact_of(node_id, max_depth=max_depth)

    def traverse_subgraph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        roots: list[str],
        direction: str = "forward",
        max_depth: int = 4,
        max_nodes: int = 500,
        traversable_only: bool = False,
        relationship_types=None,
        static_only: bool = False,
        dynamic_only: bool = False,
        include_roots: bool = True,
    ) -> tuple[Any, dict[str, int], bool]:
        graph = self.load_graph(tenant_id=tenant_id, scan_id=scan_id)
        return graph.traverse_subgraph(
            roots,
            direction=direction,
            max_depth=max_depth,
            max_nodes=max_nodes,
            traversable_only=traversable_only,
            relationship_types=relationship_types,
            static_only=static_only,
            dynamic_only=dynamic_only,
            include_roots=include_roots,
        )

    def attack_paths_for_sources(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source_ids: set[str],
    ) -> list[Any]:
        if not source_ids:
            return []
        graph = self.load_graph(tenant_id=tenant_id, scan_id=scan_id)
        return [attack_path for attack_path in graph.attack_paths if attack_path.source in source_ids]

    def diff_snapshots(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]:
        with _tenant_connection(self._pool) as conn:
            old_nodes = {
                row[0]: {"severity": row[1], "risk_score": row[2]}
                for row in conn.execute(
                    "SELECT id, severity, risk_score FROM graph_nodes WHERE scan_id = %s AND tenant_id = %s",
                    (scan_id_old, tenant_id),
                ).fetchall()
            }
            new_nodes = {
                row[0]: {"severity": row[1], "risk_score": row[2]}
                for row in conn.execute(
                    "SELECT id, severity, risk_score FROM graph_nodes WHERE scan_id = %s AND tenant_id = %s",
                    (scan_id_new, tenant_id),
                ).fetchall()
            }
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
            return {
                "nodes_added": sorted(new_ids - old_ids),
                "nodes_removed": sorted(old_ids - new_ids),
                "nodes_changed": sorted(nid for nid in (old_ids & new_ids) if old_nodes[nid] != new_nodes[nid]),
                "edges_added": sorted(new_edges - old_edges),
                "edges_removed": sorted(old_edges - new_edges),
            }

    def list_snapshots(self, *, tenant_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                """
                SELECT scan_id, created_at, node_count, edge_count, risk_summary
                FROM graph_snapshots
                WHERE tenant_id = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (tenant_id, limit),
            ).fetchall()
            return [
                {
                    "scan_id": row[0],
                    "created_at": row[1],
                    "node_count": row[2],
                    "edge_count": row[3],
                    "risk_summary": json.loads(row[4]),
                }
                for row in rows
            ]

    @staticmethod
    def _space_token_filter(column: str, token: str) -> tuple[str, list[str]]:
        escaped = _escape_like_query(token.lower())
        clause = f"({column} = %s OR {column} LIKE %s ESCAPE '\\' OR {column} LIKE %s ESCAPE '\\' OR {column} LIKE %s ESCAPE '\\')"
        return clause, [escaped, f"{escaped} %%", f"%% {escaped}", f"%% {escaped} %%"]

    @staticmethod
    def _compliance_prefix_filter(column: str, prefix: str) -> tuple[str, list[str]]:
        escaped = _escape_like_query(prefix.lower())
        clause = (
            f"({column} = %s OR {column} LIKE %s ESCAPE '\\' OR "
            f"{column} LIKE %s ESCAPE '\\' OR {column} LIKE %s ESCAPE '\\' OR {column} LIKE %s ESCAPE '\\')"
        )
        return clause, [escaped, f"{escaped}-%%", f"{escaped} %%", f"%% {escaped}-%%", f"%% {escaped} %%"]

    def snapshot_stats(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> dict[str, Any]:
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return {
                "total_nodes": 0,
                "total_edges": 0,
                "node_types": {},
                "severity_counts": {},
                "relationship_types": {},
                "attack_path_count": 0,
                "interaction_risk_count": 0,
                "max_attack_path_risk": 0.0,
                "highest_interaction_risk": 0.0,
            }

        node_where = ["tenant_id = %s", "scan_id = %s"]
        params: list[Any] = [tenant_id, effective_scan_id]
        if entity_types:
            placeholders = ",".join(["%s"] * len(entity_types))
            node_where.append(f"entity_type IN ({placeholders})")
            params.extend(sorted(entity_types))
        if min_severity_rank:
            node_where.append("severity_id >= %s")
            params.append(min_severity_rank)
        where_sql = " AND ".join(node_where)

        with _tenant_connection(self._pool) as conn:
            total_nodes = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM graph_nodes WHERE {where_sql}",  # nosec B608 - where_sql is built from static clause fragments
                    params,
                ).fetchone()[0]
                or 0
            )
            node_type_rows = conn.execute(
                f"SELECT entity_type, COUNT(*) FROM graph_nodes WHERE {where_sql} GROUP BY entity_type",  # nosec B608 - where_sql is built from static clause fragments
                params,
            ).fetchall()
            severity_rows = conn.execute(
                f"SELECT severity, COUNT(*) FROM graph_nodes WHERE {where_sql} AND severity <> '' GROUP BY severity",  # nosec B608 - where_sql is built from static clause fragments
                params,
            ).fetchall()
            total_edges = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM graph_edges
                    WHERE tenant_id = %s AND scan_id = %s
                      AND source_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                      AND target_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                    """,  # nosec B608 - where_sql is built from static clause fragments
                    [tenant_id, effective_scan_id, *params, *params],
                ).fetchone()[0]
                or 0
            )
            rel_rows = conn.execute(
                f"""
                SELECT relationship, COUNT(*)
                FROM graph_edges
                WHERE tenant_id = %s AND scan_id = %s
                  AND source_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                  AND target_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                GROUP BY relationship
                """,  # nosec B608 - where_sql is built from static clause fragments
                [tenant_id, effective_scan_id, *params, *params],
            ).fetchall()
            attack_row = conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(composite_risk), 0.0) FROM attack_paths WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, effective_scan_id),
            ).fetchone()
            interaction_row = conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(risk_score), 0.0) FROM interaction_risks WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, effective_scan_id),
            ).fetchone()
            return {
                "total_nodes": total_nodes,
                "total_edges": total_edges,
                "node_types": {str(row[0]): int(row[1]) for row in node_type_rows},
                "severity_counts": {str(row[0]): int(row[1]) for row in severity_rows},
                "relationship_types": {str(row[0]): int(row[1]) for row in rel_rows},
                "attack_path_count": int((attack_row[0] if attack_row else 0) or 0),
                "interaction_risk_count": int((interaction_row[0] if interaction_row else 0) or 0),
                "max_attack_path_risk": float((attack_row[1] if attack_row else 0.0) or 0.0),
                "highest_interaction_risk": float((interaction_row[1] if interaction_row else 0.0) or 0.0),
            }

    def page_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 500,
    ) -> tuple[str, str, list[Any], int, str | None]:
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return scan_id, "", [], 0, None
        with _tenant_connection(self._pool) as conn:
            created_row = conn.execute(
                "SELECT created_at FROM graph_snapshots WHERE scan_id = %s AND tenant_id = %s",
                (effective_scan_id, tenant_id),
            ).fetchone()
            where = ["tenant_id = %s", "scan_id = %s"]
            params: list[Any] = [tenant_id, effective_scan_id]
            if entity_types:
                placeholders = ",".join(["%s"] * len(entity_types))
                where.append(f"entity_type IN ({placeholders})")
                params.extend(sorted(entity_types))
            if min_severity_rank:
                where.append("severity_id >= %s")
                params.append(min_severity_rank)
            where_sql = " AND ".join(where)
            total = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM graph_nodes WHERE {where_sql}",  # nosec B608 - where_sql is built from static clause fragments
                    params,
                ).fetchone()[0]
                or 0
            )
            row_params = list(params)
            cursor_clause = ""
            if cursor:
                severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
                cursor_clause = """
                AND (
                    severity_id < %s
                    OR (severity_id = %s AND risk_score < %s)
                    OR (severity_id = %s AND risk_score = %s AND label > %s)
                    OR (severity_id = %s AND risk_score = %s AND label = %s AND id > %s)
                )
                """
                row_params.extend(
                    [severity_id, severity_id, risk_score, severity_id, risk_score, label, severity_id, risk_score, label, node_id]
                )
            rows = conn.execute(
                f"""
                SELECT
                    id, entity_type, label, category_uid, class_uid, type_uid,
                    status, risk_score, severity, severity_id, first_seen, last_seen,
                    attributes, compliance_tags, data_sources, dimensions
                FROM graph_nodes
                WHERE {where_sql}
                {cursor_clause}
                ORDER BY severity_id DESC, risk_score DESC, label ASC, id ASC
                LIMIT %s OFFSET %s
                """,  # nosec B608 - where_sql is built from static clause fragments
                [*row_params, limit + 1 if cursor else limit, 0 if cursor else offset],
            ).fetchall()
            has_more = len(rows) > limit if cursor else offset + limit < total
            rows = rows[:limit]
            nodes = [self._node_from_row(row) for row in rows]
            next_cursor = encode_graph_cursor(nodes[-1]) if has_more and nodes else None
            return effective_scan_id, str(created_row[0]) if created_row else "", nodes, total, next_cursor

    def edges_for_node_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[Any]:
        if not node_ids:
            return []
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return []
        placeholders = ",".join(["%s"] * len(node_ids))
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"""
                SELECT source_id, target_id, relationship, direction, weight, traversable, first_seen, last_seen, evidence, activity_id
                FROM graph_edges
                WHERE tenant_id = %s AND scan_id = %s
                  AND source_id IN ({placeholders})
                  AND target_id IN ({placeholders})
                """,  # nosec B608 - placeholders are generated solely from "%s" markers
                [tenant_id, effective_scan_id, *node_ids, *node_ids],
            ).fetchall()
            from agent_bom.graph import RelationshipType, UnifiedEdge

            return [
                UnifiedEdge(
                    source=row[0],
                    target=row[1],
                    relationship=RelationshipType(row[2]),
                    direction=row[3],
                    weight=row[4],
                    traversable=bool(row[5]),
                    first_seen=row[6],
                    last_seen=row[7],
                    evidence=json.loads(row[8]),
                    activity_id=row[9],
                )
                for row in rows
            ]

    def search_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        query: str,
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        compliance_prefixes: set[str] | None = None,
        data_sources: set[str] | None = None,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ):
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return [], 0, None

        with _tenant_connection(self._pool) as conn:
            search_where = [
                "gns.tenant_id = %s",
                "gns.scan_id = %s",
                "LOWER(gns.search_text) LIKE %s ESCAPE '\\'",
            ]
            params: list[Any] = [tenant_id, effective_scan_id, f"%{_escape_like_query(query.lower())}%"]
            if entity_types:
                placeholders = ",".join(["%s"] * len(entity_types))
                search_where.append(f"gn.entity_type IN ({placeholders})")
                params.extend(sorted(entity_types))
            if min_severity_rank:
                search_where.append("gn.severity_id >= %s")
                params.append(min_severity_rank)
            if compliance_prefixes:
                prefix_filters = []
                for prefix in sorted(compliance_prefixes):
                    clause, clause_params = self._compliance_prefix_filter("gns.compliance_tags", prefix)
                    prefix_filters.append(clause)
                    params.extend(clause_params)
                search_where.append("(" + " OR ".join(prefix_filters) + ")")
            if data_sources:
                source_filters = []
                for source in sorted(data_sources):
                    clause, clause_params = self._space_token_filter("gns.data_sources", source)
                    source_filters.append(clause)
                    params.extend(clause_params)
                search_where.append("(" + " OR ".join(source_filters) + ")")
            from_clause = """
                FROM graph_node_search gns
                JOIN graph_nodes gn
                  ON gn.id = gns.node_id
                 AND gn.scan_id = gns.scan_id
                 AND gn.tenant_id = gns.tenant_id
            """
            where_sql = " AND ".join(search_where)
            total = int(conn.execute("SELECT COUNT(*) " + from_clause + " WHERE " + where_sql, params).fetchone()[0] or 0)
            if total == 0:
                return [], 0, None
            row_params = list(params)
            cursor_clause = ""
            if cursor:
                severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
                cursor_clause = """
                AND (
                    gn.severity_id < %s
                    OR (gn.severity_id = %s AND gn.risk_score < %s)
                    OR (gn.severity_id = %s AND gn.risk_score = %s AND gn.label > %s)
                    OR (gn.severity_id = %s AND gn.risk_score = %s AND gn.label = %s AND gn.id > %s)
                )
                """
                row_params.extend(
                    [severity_id, severity_id, risk_score, severity_id, risk_score, label, severity_id, risk_score, label, node_id]
                )
            rows = conn.execute(
                """
                SELECT
                    gn.id, gn.entity_type, gn.label, gn.category_uid, gn.class_uid, gn.type_uid,
                    gn.status, gn.risk_score, gn.severity, gn.severity_id, gn.first_seen, gn.last_seen,
                    gn.attributes, gn.compliance_tags, gn.data_sources, gn.dimensions
                """
                + from_clause
                + " WHERE "
                + where_sql
                + cursor_clause
                + " ORDER BY gn.severity_id DESC, gn.risk_score DESC, gn.label ASC, gn.id ASC LIMIT %s OFFSET %s",
                [*row_params, limit + 1 if cursor else limit, 0 if cursor else offset],
            ).fetchall()
            has_more = len(rows) > limit if cursor else offset + limit < total
            rows = rows[:limit]
            nodes = [self._node_from_row(row) for row in rows]
            next_cursor = encode_graph_cursor(nodes[-1]) if has_more and nodes else None
            return nodes, total, next_cursor

    def save_preset(self, *, tenant_id: str, name: str, description: str, filters: dict[str, Any], created_at: str) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO graph_filter_presets (name, tenant_id, description, filters, created_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (name, tenant_id) DO UPDATE SET
                    description = EXCLUDED.description,
                    filters = EXCLUDED.filters,
                    created_at = EXCLUDED.created_at
                """,
                (name, tenant_id, description, json.dumps(filters), created_at),
            )
            conn.commit()

    def list_presets(self, *, tenant_id: str) -> list[dict[str, Any]]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT name, description, filters, created_at FROM graph_filter_presets WHERE tenant_id = %s ORDER BY name",
                (tenant_id,),
            ).fetchall()
            return [
                {
                    "name": row[0],
                    "description": row[1],
                    "filters": json.loads(row[2]),
                    "created_at": row[3],
                }
                for row in rows
            ]

    def delete_preset(self, *, tenant_id: str, name: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM graph_filter_presets WHERE name = %s AND tenant_id = %s",
                (name, tenant_id),
            )
            conn.commit()
            return (cursor.rowcount or 0) > 0


class PostgresScanCache:
    """PostgreSQL-backed OSV vulnerability scan cache."""

    def __init__(self, pool=None, ttl_seconds: int = 86_400) -> None:
        self._pool = pool or _get_pool()
        self._ttl = ttl_seconds
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS osv_cache (
                    cache_key  TEXT PRIMARY KEY,
                    vulns_json TEXT NOT NULL,
                    cached_at  REAL NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_age ON osv_cache(cached_at)")
            conn.commit()

    def get(self, ecosystem: str, name: str, version: str) -> list[dict] | None:
        key = self._key(ecosystem, name, version)
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT vulns_json, cached_at FROM osv_cache WHERE cache_key = %s",
                (key,),
            ).fetchone()
            if row is None:
                return None
            if time.time() - float(row[1]) > self._ttl:
                conn.execute("DELETE FROM osv_cache WHERE cache_key = %s", (key,))
                conn.commit()
                return None
            return json.loads(row[0])

    def put(self, ecosystem: str, name: str, version: str, vulns: list[dict]) -> None:
        key = self._key(ecosystem, name, version)
        with self._pool.connection() as conn:
            conn.execute(
                """INSERT INTO osv_cache (cache_key, vulns_json, cached_at)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (cache_key) DO UPDATE SET
                     vulns_json = EXCLUDED.vulns_json,
                     cached_at = EXCLUDED.cached_at""",
                (key, json.dumps(vulns), time.time()),
            )
            conn.commit()

    def cleanup_expired(self) -> int:
        cutoff = time.time() - self._ttl
        with self._pool.connection() as conn:
            cursor = conn.execute("DELETE FROM osv_cache WHERE cached_at < %s", (cutoff,))
            conn.commit()
            return cursor.rowcount or 0

    def clear(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("DELETE FROM osv_cache")
            conn.commit()

    @property
    def size(self) -> int:
        with self._pool.connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM osv_cache").fetchone()
            return row[0] if row else 0

    @staticmethod
    def _key(ecosystem: str, name: str, version: str) -> str:
        from agent_bom.package_utils import normalize_package_name

        return f"{ecosystem}:{normalize_package_name(name, ecosystem)}@{version}"
