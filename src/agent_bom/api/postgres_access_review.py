"""Postgres-backed access-review campaign store for horizontal scaling.

Mirrors :class:`agent_bom.api.access_review.SQLiteAccessReviewStore` but keeps
recertification campaigns and their review items in shared Postgres with tenant
RLS, so campaign status and reviewer decisions stay consistent across every
control-plane replica instead of diverging on node-local SQLite. The campaign
and item dataclasses are persisted as JSON ``data`` blobs (matching the SQLite
mirror) with tenant_id / status / decision projected into columns for indexing.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from agent_bom.api.access_review import AccessReviewCampaign, AccessReviewItem
from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresAccessReviewStore:
    """Shared access-review campaign + item store backed by Postgres with tenant RLS."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "access_review_campaigns"):
                return
            conn.execute("""
                CREATE TABLE IF NOT EXISTS access_review_campaigns (
                    campaign_id TEXT NOT NULL,
                    tenant_id   TEXT NOT NULL,
                    status      TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    due_at      TEXT NOT NULL DEFAULT '',
                    data        TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, campaign_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS access_review_items (
                    item_id     TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    tenant_id   TEXT NOT NULL,
                    subject_id  TEXT NOT NULL,
                    decision    TEXT NOT NULL,
                    data        TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, item_id)
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_access_review_campaigns_tenant ON access_review_campaigns(tenant_id, created_at DESC)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_access_review_items_campaign ON access_review_items(tenant_id, campaign_id)")
            _ensure_tenant_rls(conn, "access_review_campaigns", "tenant_id")
            _ensure_tenant_rls(conn, "access_review_items", "tenant_id")
            conn.commit()

    def put_campaign(self, campaign: AccessReviewCampaign) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO access_review_campaigns (campaign_id, tenant_id, status, created_at, due_at, data)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, campaign_id) DO UPDATE
                SET status = EXCLUDED.status, due_at = EXCLUDED.due_at, data = EXCLUDED.data
                """,
                (
                    campaign.campaign_id,
                    campaign.tenant_id,
                    campaign.status,
                    campaign.created_at,
                    campaign.due_at,
                    json.dumps(asdict(campaign), sort_keys=True),
                ),
            )
            conn.commit()

    def get_campaign(self, campaign_id: str, tenant_id: str | None = None) -> AccessReviewCampaign | None:
        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                row = conn.execute("SELECT data FROM access_review_campaigns WHERE campaign_id = %s LIMIT 1", (campaign_id,)).fetchone()
            else:
                row = conn.execute(
                    "SELECT data FROM access_review_campaigns WHERE campaign_id = %s AND tenant_id = %s",
                    (campaign_id, tenant_id),
                ).fetchone()
        return AccessReviewCampaign(**json.loads(row[0])) if row else None

    def list_campaigns(self, tenant_id: str, *, limit: int = 200) -> list[AccessReviewCampaign]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM access_review_campaigns WHERE tenant_id = %s ORDER BY created_at DESC LIMIT %s",
                (tenant_id, limit),
            ).fetchall()
        return [AccessReviewCampaign(**json.loads(r[0])) for r in rows]

    def put_item(self, item: AccessReviewItem) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO access_review_items (item_id, campaign_id, tenant_id, subject_id, decision, data)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, item_id) DO UPDATE
                SET decision = EXCLUDED.decision, data = EXCLUDED.data
                """,
                (
                    item.item_id,
                    item.campaign_id,
                    item.tenant_id,
                    item.subject_id,
                    item.decision,
                    json.dumps(asdict(item), sort_keys=True),
                ),
            )
            conn.commit()

    def get_item(self, item_id: str, tenant_id: str | None = None) -> AccessReviewItem | None:
        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                row = conn.execute("SELECT data FROM access_review_items WHERE item_id = %s LIMIT 1", (item_id,)).fetchone()
            else:
                row = conn.execute(
                    "SELECT data FROM access_review_items WHERE item_id = %s AND tenant_id = %s",
                    (item_id, tenant_id),
                ).fetchone()
        return AccessReviewItem(**json.loads(row[0])) if row else None

    def list_items(self, campaign_id: str, tenant_id: str | None = None, *, limit: int = 1000) -> list[AccessReviewItem]:
        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                rows = conn.execute(
                    "SELECT data FROM access_review_items WHERE campaign_id = %s ORDER BY item_id LIMIT %s",
                    (campaign_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM access_review_items WHERE campaign_id = %s AND tenant_id = %s ORDER BY item_id LIMIT %s",
                    (campaign_id, tenant_id, limit),
                ).fetchall()
        items = [AccessReviewItem(**json.loads(r[0])) for r in rows]
        return sorted(items, key=lambda i: i.subject_name.lower())
