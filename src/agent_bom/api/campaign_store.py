"""Tenant-scoped workflow state for server-derived risk campaigns."""

from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CampaignWorkflow:
    tenant_id: str
    campaign_id: str
    owner: str | None = None
    sla_due_at: str | None = None
    state: str = "open"
    verification_status: str = "unverified"
    updated_at: str = ""

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


class CampaignStore(Protocol):
    def get(self, tenant_id: str, campaign_id: str) -> CampaignWorkflow | None: ...
    def list(self, tenant_id: str) -> list[CampaignWorkflow]: ...
    def upsert(
        self,
        tenant_id: str,
        campaign_id: str,
        *,
        owner: str | None = None,
        sla_due_at: str | None = None,
        state: str = "open",
        verification_status: str = "unverified",
    ) -> CampaignWorkflow: ...


class InMemoryCampaignStore:
    def __init__(self) -> None:
        self._rows: dict[tuple[str, str], CampaignWorkflow] = {}
        self._lock = threading.Lock()

    def get(self, tenant_id: str, campaign_id: str) -> CampaignWorkflow | None:
        with self._lock:
            row = self._rows.get((tenant_id, campaign_id))
            return replace(row) if row else None

    def list(self, tenant_id: str) -> list[CampaignWorkflow]:
        with self._lock:
            return [replace(row) for (row_tenant, _), row in self._rows.items() if row_tenant == tenant_id]

    def upsert(
        self,
        tenant_id: str,
        campaign_id: str,
        *,
        owner: str | None = None,
        sla_due_at: str | None = None,
        state: str = "open",
        verification_status: str = "unverified",
    ) -> CampaignWorkflow:
        row = CampaignWorkflow(
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            owner=owner,
            sla_due_at=sla_due_at,
            state=state,
            verification_status=verification_status,
            updated_at=_now(),
        )
        with self._lock:
            self._rows[(tenant_id, campaign_id)] = row
        return replace(row)


class SQLiteCampaignStore:
    def __init__(self, db_path: str = "agent_bom_jobs.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "risk_campaign_workflows")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS risk_campaign_workflows (
                tenant_id TEXT NOT NULL,
                campaign_id TEXT NOT NULL,
                owner TEXT,
                sla_due_at TEXT,
                state TEXT NOT NULL,
                verification_status TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, campaign_id)
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_risk_campaign_workflows_tenant_state ON risk_campaign_workflows(tenant_id, state, updated_at)"
        )
        self._conn.commit()

    @staticmethod
    def _row(value: tuple[str, ...] | None) -> CampaignWorkflow | None:
        return CampaignWorkflow(*value) if value else None

    def get(self, tenant_id: str, campaign_id: str) -> CampaignWorkflow | None:
        row = self._conn.execute(
            "SELECT tenant_id, campaign_id, owner, sla_due_at, state, verification_status, updated_at "
            "FROM risk_campaign_workflows WHERE tenant_id = ? AND campaign_id = ?",
            (tenant_id, campaign_id),
        ).fetchone()
        return self._row(row)

    def list(self, tenant_id: str) -> list[CampaignWorkflow]:
        rows = self._conn.execute(
            "SELECT tenant_id, campaign_id, owner, sla_due_at, state, verification_status, updated_at "
            "FROM risk_campaign_workflows WHERE tenant_id = ? ORDER BY updated_at DESC, campaign_id",
            (tenant_id,),
        ).fetchall()
        return [CampaignWorkflow(*row) for row in rows]

    def upsert(
        self,
        tenant_id: str,
        campaign_id: str,
        *,
        owner: str | None = None,
        sla_due_at: str | None = None,
        state: str = "open",
        verification_status: str = "unverified",
    ) -> CampaignWorkflow:
        updated_at = _now()
        self._conn.execute(
            """
            INSERT INTO risk_campaign_workflows
                (tenant_id, campaign_id, owner, sla_due_at, state, verification_status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, campaign_id) DO UPDATE SET
                owner = excluded.owner,
                sla_due_at = excluded.sla_due_at,
                state = excluded.state,
                verification_status = excluded.verification_status,
                updated_at = excluded.updated_at
            """,
            (tenant_id, campaign_id, owner, sla_due_at, state, verification_status, updated_at),
        )
        self._conn.commit()
        row = self.get(tenant_id, campaign_id)
        assert row is not None
        return row


_store: CampaignStore | None = None
_store_lock = threading.Lock()


def get_campaign_store() -> CampaignStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                if os.environ.get("AGENT_BOM_POSTGRES_URL"):
                    from agent_bom.api.postgres_campaign import PostgresCampaignStore

                    _store = PostgresCampaignStore()
                else:
                    db_path = os.environ.get("AGENT_BOM_DB")
                    _store = SQLiteCampaignStore(db_path) if db_path else InMemoryCampaignStore()
    return _store


def set_campaign_store(store: CampaignStore | None) -> None:
    global _store
    _store = store
