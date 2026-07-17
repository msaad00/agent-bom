"""Tenant-scoped workflow state for server-derived risk campaigns."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import Any, List, Protocol

from agent_bom.api.durable_store import select_backend, sqlite_path
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
    member_ids: tuple[str, ...] = ()
    membership_fingerprint: str = ""
    generation: int = 1
    active: bool = True
    version: int = 1
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CampaignStore(Protocol):
    def get(self, tenant_id: str, campaign_id: str) -> CampaignWorkflow | None: ...
    def list(self, tenant_id: str) -> List[CampaignWorkflow]: ...
    def reconcile_memberships(
        self, tenant_id: str, memberships: dict[str, str | tuple[str, tuple[str, ...]]], *, complete: bool = True
    ) -> List[CampaignWorkflow]: ...
    def patch(
        self, tenant_id: str, campaign_id: str, *, expected_version: int, fields: dict[str, str | None]
    ) -> CampaignWorkflow | None: ...
    def verify(
        self, tenant_id: str, campaign_id: str, *, expected_version: int, remaining_ids: tuple[str, ...]
    ) -> CampaignWorkflow | None: ...
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

    def list(self, tenant_id: str) -> List[CampaignWorkflow]:
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

    def reconcile_memberships(
        self, tenant_id: str, memberships: dict[str, str | tuple[str, tuple[str, ...]]], *, complete: bool = True
    ) -> List[CampaignWorkflow]:
        if not complete:
            return [row for cid in memberships if (row := self.get(tenant_id, cid)) is not None]
        with self._lock:
            tenant_rows = {cid: row for (tid, cid), row in self._rows.items() if tid == tenant_id}
            for campaign_id, evidence in memberships.items():
                fingerprint, member_ids = _membership(evidence)
                row = tenant_rows.get(campaign_id)
                if row is None:
                    row = CampaignWorkflow(
                        tenant_id, campaign_id, member_ids=member_ids, membership_fingerprint=fingerprint, updated_at=_now()
                    )
                    self._rows[(tenant_id, campaign_id)] = row
                elif not row.active or row.membership_fingerprint != fingerprint or row.member_ids != member_ids:
                    row.membership_fingerprint = fingerprint
                    row.member_ids = member_ids
                    row.generation += 1
                    row.active = True
                    row.state = "open"
                    row.verification_status = "unverified"
                    row.version += 1
                    row.updated_at = _now()
            for campaign_id, row in tenant_rows.items():
                if complete and campaign_id not in memberships and row.active:
                    row.active = False
                    row.version += 1
                    row.updated_at = _now()
            return [replace(self._rows[(tenant_id, cid)]) for cid in memberships]

    def verify(self, tenant_id: str, campaign_id: str, *, expected_version: int, remaining_ids: tuple[str, ...]) -> CampaignWorkflow | None:
        with self._lock:
            row = self._rows.get((tenant_id, campaign_id))
            if row is None or row.version != expected_version:
                return None
            row.verification_status = "failed" if remaining_ids else "verified"
            row.state = "open" if remaining_ids else "done"
            row.version += 1
            row.updated_at = _now()
            return replace(row)

    def patch(self, tenant_id: str, campaign_id: str, *, expected_version: int, fields: dict[str, str | None]) -> CampaignWorkflow | None:
        with self._lock:
            row = self._rows.get((tenant_id, campaign_id))
            if row is None or row.version != expected_version or not row.active:
                return None
            for key, value in fields.items():
                if key not in {"owner", "sla_due_at", "state"}:
                    continue
                setattr(row, key, value)
            row.version += 1
            row.updated_at = _now()
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
                member_ids TEXT NOT NULL DEFAULT '[]',
                membership_fingerprint TEXT NOT NULL DEFAULT '',
                generation INTEGER NOT NULL DEFAULT 1,
                active INTEGER NOT NULL DEFAULT 1,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, campaign_id)
            )
            """
        )
        columns = {str(row[1]) for row in self._conn.execute("PRAGMA table_info(risk_campaign_workflows)").fetchall()}
        for name, ddl in (
            ("membership_fingerprint", "TEXT NOT NULL DEFAULT ''"),
            ("member_ids", "TEXT NOT NULL DEFAULT '[]'"),
            ("generation", "INTEGER NOT NULL DEFAULT 1"),
            ("active", "INTEGER NOT NULL DEFAULT 1"),
            ("version", "INTEGER NOT NULL DEFAULT 1"),
        ):
            if name not in columns:
                self._conn.execute(f"ALTER TABLE risk_campaign_workflows ADD COLUMN {name} {ddl}")  # nosec B608
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_risk_campaign_workflows_tenant_state ON risk_campaign_workflows(tenant_id, state, updated_at)"
        )
        self._conn.commit()

    @staticmethod
    def _row(value: tuple[Any, ...] | None) -> CampaignWorkflow | None:
        if not value:
            return None
        values = list(value)
        values[6] = tuple(json.loads(values[6] or "[]"))
        values[9] = bool(values[9])
        return CampaignWorkflow(*values)

    def get(self, tenant_id: str, campaign_id: str) -> CampaignWorkflow | None:
        row = self._conn.execute(
            "SELECT tenant_id, campaign_id, owner, sla_due_at, state, verification_status, "
            "member_ids, membership_fingerprint, generation, active, version, updated_at "
            "FROM risk_campaign_workflows WHERE tenant_id = ? AND campaign_id = ?",
            (tenant_id, campaign_id),
        ).fetchone()
        return self._row(row)

    def list(self, tenant_id: str) -> List[CampaignWorkflow]:
        rows = self._conn.execute(
            "SELECT tenant_id, campaign_id, owner, sla_due_at, state, verification_status, "
            "member_ids, membership_fingerprint, generation, active, version, updated_at "
            "FROM risk_campaign_workflows WHERE tenant_id = ? ORDER BY updated_at DESC, campaign_id",
            (tenant_id,),
        ).fetchall()
        result = [self._row(row) for row in rows if row]
        return [row for row in result if row is not None]

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

    def reconcile_memberships(
        self, tenant_id: str, memberships: dict[str, str | tuple[str, tuple[str, ...]]], *, complete: bool = True
    ) -> List[CampaignWorkflow]:
        if not complete:
            return [row for cid in memberships if (row := self.get(tenant_id, cid)) is not None]
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            existing = {row.campaign_id: row for row in self.list(tenant_id)}
            now = _now()
            for campaign_id, evidence in memberships.items():
                fingerprint, member_ids = _membership(evidence)
                encoded_ids = json.dumps(member_ids, separators=(",", ":"))
                row = existing.get(campaign_id)
                if row is None:
                    conn.execute(
                        "INSERT INTO risk_campaign_workflows "
                        "(tenant_id,campaign_id,state,verification_status,member_ids,membership_fingerprint,"
                        "generation,active,version,updated_at) "
                        "VALUES (?,?, 'open','unverified',?,?,1,1,1,?)",
                        (tenant_id, campaign_id, encoded_ids, fingerprint, now),
                    )
                elif not row.active or row.membership_fingerprint != fingerprint or row.member_ids != member_ids:
                    conn.execute(
                        "UPDATE risk_campaign_workflows SET member_ids=?, membership_fingerprint=?, generation=generation+1, active=1, "
                        "state='open', verification_status='unverified', version=version+1, updated_at=? "
                        "WHERE tenant_id=? AND campaign_id=?",
                        (encoded_ids, fingerprint, now, tenant_id, campaign_id),
                    )
            if complete:
                for campaign_id in set(existing) - set(memberships):
                    conn.execute(
                        "UPDATE risk_campaign_workflows SET active=0, version=version+1, updated_at=? "
                        "WHERE tenant_id=? AND campaign_id=? AND active=1",
                        (now, tenant_id, campaign_id),
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return [row for cid in memberships if (row := self.get(tenant_id, cid)) is not None]

    def verify(self, tenant_id: str, campaign_id: str, *, expected_version: int, remaining_ids: tuple[str, ...]) -> CampaignWorkflow | None:
        status = "failed" if remaining_ids else "verified"
        state = "open" if remaining_ids else "done"
        cursor = self._conn.execute(
            "UPDATE risk_campaign_workflows SET verification_status=?, state=?, version=version+1, updated_at=? "
            "WHERE tenant_id=? AND campaign_id=? AND version=?",
            (status, state, _now(), tenant_id, campaign_id, expected_version),
        )
        self._conn.commit()
        return self.get(tenant_id, campaign_id) if cursor.rowcount == 1 else None

    def patch(self, tenant_id: str, campaign_id: str, *, expected_version: int, fields: dict[str, str | None]) -> CampaignWorkflow | None:
        current = self.get(tenant_id, campaign_id)
        if current is None:
            return None
        values = {
            "owner": current.owner,
            "sla_due_at": current.sla_due_at,
            "state": current.state,
            **fields,
        }
        cursor = self._conn.execute(
            "UPDATE risk_campaign_workflows SET owner=?, sla_due_at=?, state=?, "
            "version=version+1, updated_at=? WHERE tenant_id=? AND campaign_id=? AND version=? AND active=1",
            (
                values["owner"],
                values["sla_due_at"],
                values["state"],
                _now(),
                tenant_id,
                campaign_id,
                expected_version,
            ),
        )
        self._conn.commit()
        return self.get(tenant_id, campaign_id) if cursor.rowcount == 1 else None


_store: CampaignStore | None = None
_store_lock = threading.Lock()


def get_campaign_store() -> CampaignStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                backend = select_backend()
                if backend == "postgres":
                    from agent_bom.api.postgres_campaign import PostgresCampaignStore

                    _store = PostgresCampaignStore()
                elif backend == "sqlite":
                    _store = SQLiteCampaignStore(sqlite_path())
                else:
                    _store = InMemoryCampaignStore()
    return _store


def set_campaign_store(store: CampaignStore | None) -> None:
    global _store
    _store = store


def _membership(value: str | tuple[str, tuple[str, ...]]) -> tuple[str, tuple[str, ...]]:
    if isinstance(value, tuple):
        return value[0], tuple(sorted(set(value[1])))
    return value, ()
