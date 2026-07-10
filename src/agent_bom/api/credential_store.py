"""Credential reference registry storage backends.

The registry stores only references to customer-managed credentials such as
role ARNs, secret-manager paths, or workload-identity names. It must never
store credential material.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import Protocol

from agent_bom.api.models import CredentialRefRecord
from agent_bom.api.storage_schema import ensure_sqlite_schema_version


class CredentialRefStore(Protocol):
    """Protocol for tenant-scoped credential reference persistence."""

    def put(self, credential: CredentialRefRecord) -> None: ...
    def get(self, credential_ref_id: str, *, tenant_id: str) -> CredentialRefRecord | None: ...
    def delete(self, credential_ref_id: str, *, tenant_id: str) -> bool: ...
    def list_all(self, tenant_id: str | None = None) -> list[CredentialRefRecord]: ...


class InMemoryCredentialRefStore:
    """Dict-backed credential reference registry."""

    def __init__(self) -> None:
        self._credentials: dict[str, CredentialRefRecord] = {}

    def put(self, credential: CredentialRefRecord) -> None:
        self._credentials[credential.credential_ref_id] = credential

    def get(self, credential_ref_id: str, *, tenant_id: str) -> CredentialRefRecord | None:
        credential = self._credentials.get(credential_ref_id)
        if credential is None or credential.tenant_id != tenant_id:
            return None
        return credential

    def delete(self, credential_ref_id: str, *, tenant_id: str) -> bool:
        credential = self._credentials.get(credential_ref_id)
        if credential is None or credential.tenant_id != tenant_id:
            return False
        del self._credentials[credential_ref_id]
        return True

    def list_all(self, tenant_id: str | None = None) -> list[CredentialRefRecord]:
        credentials = list(self._credentials.values())
        if tenant_id is None:
            return sorted(credentials, key=lambda credential: credential.display_name.lower())
        return sorted(
            [credential for credential in credentials if credential.tenant_id == tenant_id],
            key=lambda credential: credential.display_name.lower(),
        )


class SQLiteCredentialRefStore:
    """SQLite-backed credential reference registry."""

    def __init__(self, db_path: str = "agent_bom_credentials.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "credential_refs")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS credential_refs (
                credential_ref_id TEXT PRIMARY KEY,
                enabled INTEGER DEFAULT 1,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                updated_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
        """)
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(credential_refs)").fetchall()}
        if "tenant_id" not in cols:
            self._conn.execute("ALTER TABLE credential_refs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
        if "updated_at" not in cols:
            self._conn.execute("ALTER TABLE credential_refs ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_credential_refs_tenant_updated ON credential_refs(tenant_id, updated_at)")
        self._conn.commit()

    def put(self, credential: CredentialRefRecord) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO credential_refs (credential_ref_id, enabled, tenant_id, updated_at, data)
               VALUES (?, ?, ?, ?, ?)""",
            (
                credential.credential_ref_id,
                int(credential.enabled),
                credential.tenant_id,
                credential.updated_at,
                credential.model_dump_json(),
            ),
        )
        self._conn.commit()

    def get(self, credential_ref_id: str, *, tenant_id: str) -> CredentialRefRecord | None:
        row = self._conn.execute(
            "SELECT data FROM credential_refs WHERE credential_ref_id = ? AND tenant_id = ?",
            (credential_ref_id, tenant_id),
        ).fetchone()
        if row is None:
            return None
        record: CredentialRefRecord = CredentialRefRecord.model_validate_json(row[0])
        return record

    def delete(self, credential_ref_id: str, *, tenant_id: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM credential_refs WHERE credential_ref_id = ? AND tenant_id = ?",
            (credential_ref_id, tenant_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self, tenant_id: str | None = None) -> list[CredentialRefRecord]:
        if tenant_id is None:
            rows = self._conn.execute("SELECT data FROM credential_refs ORDER BY updated_at DESC, credential_ref_id").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM credential_refs WHERE tenant_id = ? ORDER BY updated_at DESC, credential_ref_id",
                (tenant_id,),
            ).fetchall()
        return [CredentialRefRecord.model_validate_json(row[0]) for row in rows]
