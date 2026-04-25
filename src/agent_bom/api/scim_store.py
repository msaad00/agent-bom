"""SCIM user and group stores for enterprise identity provisioning."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from typing import Any, Protocol

from pydantic import BaseModel, Field, field_validator

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.platform_invariants import normalize_tenant_id, now_utc_iso


class SCIMUser(BaseModel):
    """Tenant-bound SCIM user record."""

    tenant_id: str = "default"
    user_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    external_id: str | None = None
    user_name: str
    display_name: str = ""
    active: bool = True
    emails: list[dict[str, Any]] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_utc_iso)
    updated_at: str = Field(default_factory=now_utc_iso)

    @field_validator("tenant_id")
    @classmethod
    def _tenant(cls, value: str) -> str:
        return normalize_tenant_id(value)


class SCIMGroup(BaseModel):
    """Tenant-bound SCIM group record."""

    tenant_id: str = "default"
    group_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    external_id: str | None = None
    display_name: str
    members: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_utc_iso)
    updated_at: str = Field(default_factory=now_utc_iso)

    @field_validator("tenant_id")
    @classmethod
    def _tenant(cls, value: str) -> str:
        return normalize_tenant_id(value)


class SCIMStore(Protocol):
    """Persistence contract for SCIM lifecycle state."""

    def put_user(self, user: SCIMUser) -> SCIMUser: ...
    def get_user(self, tenant_id: str, user_id: str) -> SCIMUser | None: ...
    def list_users(self, tenant_id: str, *, filter_attr: str | None = None, filter_value: str | None = None) -> list[SCIMUser]: ...
    def deactivate_user(self, tenant_id: str, user_id: str) -> SCIMUser | None: ...
    def put_group(self, group: SCIMGroup) -> SCIMGroup: ...
    def get_group(self, tenant_id: str, group_id: str) -> SCIMGroup | None: ...
    def list_groups(self, tenant_id: str, *, filter_attr: str | None = None, filter_value: str | None = None) -> list[SCIMGroup]: ...
    def delete_group(self, tenant_id: str, group_id: str) -> bool: ...


class InMemorySCIMStore:
    """Process-local SCIM store for tests and local development."""

    def __init__(self) -> None:
        self._users: dict[tuple[str, str], SCIMUser] = {}
        self._groups: dict[tuple[str, str], SCIMGroup] = {}
        self._lock = threading.RLock()

    def put_user(self, user: SCIMUser) -> SCIMUser:
        user.updated_at = now_utc_iso()
        with self._lock:
            self._users[(user.tenant_id, user.user_id)] = user.model_copy(deep=True)
        return user

    def get_user(self, tenant_id: str, user_id: str) -> SCIMUser | None:
        with self._lock:
            record = self._users.get((normalize_tenant_id(tenant_id), user_id))
            return record.model_copy(deep=True) if record else None

    def list_users(self, tenant_id: str, *, filter_attr: str | None = None, filter_value: str | None = None) -> list[SCIMUser]:
        tenant = normalize_tenant_id(tenant_id)
        with self._lock:
            users = [u.model_copy(deep=True) for (tid, _), u in self._users.items() if tid == tenant]
        return [u for u in users if _matches_user(u, filter_attr, filter_value)]

    def deactivate_user(self, tenant_id: str, user_id: str) -> SCIMUser | None:
        with self._lock:
            user = self._users.get((normalize_tenant_id(tenant_id), user_id))
            if user is None:
                return None
            user.active = False
            user.updated_at = now_utc_iso()
            return user.model_copy(deep=True)

    def put_group(self, group: SCIMGroup) -> SCIMGroup:
        group.updated_at = now_utc_iso()
        with self._lock:
            self._groups[(group.tenant_id, group.group_id)] = group.model_copy(deep=True)
        return group

    def get_group(self, tenant_id: str, group_id: str) -> SCIMGroup | None:
        with self._lock:
            record = self._groups.get((normalize_tenant_id(tenant_id), group_id))
            return record.model_copy(deep=True) if record else None

    def list_groups(self, tenant_id: str, *, filter_attr: str | None = None, filter_value: str | None = None) -> list[SCIMGroup]:
        tenant = normalize_tenant_id(tenant_id)
        with self._lock:
            groups = [g.model_copy(deep=True) for (tid, _), g in self._groups.items() if tid == tenant]
        return [g for g in groups if _matches_group(g, filter_attr, filter_value)]

    def delete_group(self, tenant_id: str, group_id: str) -> bool:
        with self._lock:
            return self._groups.pop((normalize_tenant_id(tenant_id), group_id), None) is not None


class SQLiteSCIMStore:
    """SQLite-backed SCIM store for single-node pilots."""

    def __init__(self, db_path: str = "agent_bom.db") -> None:
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
        ensure_sqlite_schema_version(self._conn, "identity_scim")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS scim_users (
                tenant_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                external_id TEXT,
                user_name TEXT NOT NULL,
                active INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, user_id)
            )
        """)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_scim_users_lookup ON scim_users(tenant_id, user_name, external_id)")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS scim_groups (
                tenant_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                external_id TEXT,
                display_name TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, group_id)
            )
        """)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_scim_groups_lookup ON scim_groups(tenant_id, display_name, external_id)")
        self._conn.commit()

    def put_user(self, user: SCIMUser) -> SCIMUser:
        user.updated_at = now_utc_iso()
        payload = json.dumps(user.model_dump(mode="json"), sort_keys=True)
        self._conn.execute(
            """
            INSERT OR REPLACE INTO scim_users (tenant_id, user_id, external_id, user_name, active, updated_at, data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user.tenant_id, user.user_id, user.external_id, user.user_name, int(user.active), user.updated_at, payload),
        )
        self._conn.commit()
        return user

    def get_user(self, tenant_id: str, user_id: str) -> SCIMUser | None:
        row = self._conn.execute(
            "SELECT data FROM scim_users WHERE tenant_id = ? AND user_id = ?",
            (normalize_tenant_id(tenant_id), user_id),
        ).fetchone()
        return SCIMUser(**json.loads(row[0])) if row else None

    def list_users(self, tenant_id: str, *, filter_attr: str | None = None, filter_value: str | None = None) -> list[SCIMUser]:
        rows = self._conn.execute(
            "SELECT data FROM scim_users WHERE tenant_id = ? ORDER BY user_name ASC, user_id ASC",
            (normalize_tenant_id(tenant_id),),
        ).fetchall()
        return [user for user in (SCIMUser(**json.loads(row[0])) for row in rows) if _matches_user(user, filter_attr, filter_value)]

    def deactivate_user(self, tenant_id: str, user_id: str) -> SCIMUser | None:
        user = self.get_user(tenant_id, user_id)
        if user is None:
            return None
        user.active = False
        return self.put_user(user)

    def put_group(self, group: SCIMGroup) -> SCIMGroup:
        group.updated_at = now_utc_iso()
        payload = json.dumps(group.model_dump(mode="json"), sort_keys=True)
        self._conn.execute(
            """
            INSERT OR REPLACE INTO scim_groups (tenant_id, group_id, external_id, display_name, updated_at, data)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (group.tenant_id, group.group_id, group.external_id, group.display_name, group.updated_at, payload),
        )
        self._conn.commit()
        return group

    def get_group(self, tenant_id: str, group_id: str) -> SCIMGroup | None:
        row = self._conn.execute(
            "SELECT data FROM scim_groups WHERE tenant_id = ? AND group_id = ?",
            (normalize_tenant_id(tenant_id), group_id),
        ).fetchone()
        return SCIMGroup(**json.loads(row[0])) if row else None

    def list_groups(self, tenant_id: str, *, filter_attr: str | None = None, filter_value: str | None = None) -> list[SCIMGroup]:
        rows = self._conn.execute(
            "SELECT data FROM scim_groups WHERE tenant_id = ? ORDER BY display_name ASC, group_id ASC",
            (normalize_tenant_id(tenant_id),),
        ).fetchall()
        return [group for group in (SCIMGroup(**json.loads(row[0])) for row in rows) if _matches_group(group, filter_attr, filter_value)]

    def delete_group(self, tenant_id: str, group_id: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM scim_groups WHERE tenant_id = ? AND group_id = ?",
            (normalize_tenant_id(tenant_id), group_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0


def _matches_user(user: SCIMUser, attr: str | None, value: str | None) -> bool:
    if not attr:
        return True
    if attr == "userName":
        return user.user_name == value
    if attr == "externalId":
        return user.external_id == value
    if attr == "id":
        return user.user_id == value
    return False


def _matches_group(group: SCIMGroup, attr: str | None, value: str | None) -> bool:
    if not attr:
        return True
    if attr == "displayName":
        return group.display_name == value
    if attr == "externalId":
        return group.external_id == value
    if attr == "id":
        return group.group_id == value
    return False
