"""Postgres-backed SCIM lifecycle store."""

from __future__ import annotations

import json

from agent_bom.api.postgres_common import _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.scim_store import SCIMGroup, SCIMUser
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.platform_invariants import normalize_tenant_id, now_utc_iso


class PostgresSCIMStore:
    """Shared SCIM store for clustered self-hosted deployments."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "identity_scim")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scim_users (
                    tenant_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    external_id TEXT,
                    user_name TEXT NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    data JSONB NOT NULL,
                    PRIMARY KEY (tenant_id, user_id)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scim_users_lookup ON scim_users(tenant_id, user_name, external_id)")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scim_groups (
                    tenant_id TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    external_id TEXT,
                    display_name TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    data JSONB NOT NULL,
                    PRIMARY KEY (tenant_id, group_id)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scim_groups_lookup ON scim_groups(tenant_id, display_name, external_id)")
            _ensure_tenant_rls(conn, "scim_users", "tenant_id")
            _ensure_tenant_rls(conn, "scim_groups", "tenant_id")
            conn.commit()

    def put_user(self, user: SCIMUser) -> SCIMUser:
        user.updated_at = now_utc_iso()
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO scim_users (tenant_id, user_id, external_id, user_name, active, updated_at, data)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, user_id) DO UPDATE SET
                    external_id = EXCLUDED.external_id,
                    user_name = EXCLUDED.user_name,
                    active = EXCLUDED.active,
                    updated_at = EXCLUDED.updated_at,
                    data = EXCLUDED.data
                """,
                (
                    user.tenant_id,
                    user.user_id,
                    user.external_id,
                    user.user_name,
                    user.active,
                    user.updated_at,
                    json.dumps(user.model_dump(mode="json"), sort_keys=True),
                ),
            )
            conn.commit()
        return user

    def get_user(self, tenant_id: str, user_id: str) -> SCIMUser | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM scim_users WHERE tenant_id = %s AND user_id = %s",
                (normalize_tenant_id(tenant_id), user_id),
            ).fetchone()
        return _load_user(row[0]) if row else None

    def list_users(
        self,
        tenant_id: str,
        *,
        filter_attr: str | None = None,
        filter_value: str | None = None,
        include_inactive: bool = False,
    ) -> list[SCIMUser]:
        tenant = normalize_tenant_id(tenant_id)
        query = "SELECT data FROM scim_users WHERE tenant_id = %s ORDER BY user_name ASC, user_id ASC"
        params: tuple[object, ...] = (tenant,)
        if filter_attr == "userName":
            query = "SELECT data FROM scim_users WHERE tenant_id = %s AND user_name = %s ORDER BY user_name ASC, user_id ASC"
            params = (tenant, filter_value)
        elif filter_attr == "externalId":
            query = "SELECT data FROM scim_users WHERE tenant_id = %s AND external_id = %s ORDER BY user_name ASC, user_id ASC"
            params = (tenant, filter_value)
        elif filter_attr == "id":
            query = "SELECT data FROM scim_users WHERE tenant_id = %s AND user_id = %s ORDER BY user_name ASC, user_id ASC"
            params = (tenant, filter_value)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(query, params).fetchall()
        users = [_load_user(row[0]) for row in rows]
        # Bulk listing excludes deactivated users so SCIM DELETE actually
        # removes them from IdP listings (Okta/Azure AD deprovisioning).
        # Precise lookups by userName/externalId/id keep finding deactivated
        # users -- IdP admins rely on those filters to verify a
        # deprovisioning landed. Matches the in-memory store contract.
        if include_inactive or filter_attr in ("active", "userName", "externalId", "id"):
            return users
        return [u for u in users if u.active]

    def deactivate_user(self, tenant_id: str, user_id: str) -> SCIMUser | None:
        user = self.get_user(tenant_id, user_id)
        if user is None:
            return None
        user.active = False
        return self.put_user(user)

    def put_group(self, group: SCIMGroup) -> SCIMGroup:
        group.updated_at = now_utc_iso()
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO scim_groups (tenant_id, group_id, external_id, display_name, updated_at, data)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, group_id) DO UPDATE SET
                    external_id = EXCLUDED.external_id,
                    display_name = EXCLUDED.display_name,
                    updated_at = EXCLUDED.updated_at,
                    data = EXCLUDED.data
                """,
                (
                    group.tenant_id,
                    group.group_id,
                    group.external_id,
                    group.display_name,
                    group.updated_at,
                    json.dumps(group.model_dump(mode="json"), sort_keys=True),
                ),
            )
            conn.commit()
        return group

    def get_group(self, tenant_id: str, group_id: str) -> SCIMGroup | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM scim_groups WHERE tenant_id = %s AND group_id = %s",
                (normalize_tenant_id(tenant_id), group_id),
            ).fetchone()
        return _load_group(row[0]) if row else None

    def list_groups(self, tenant_id: str, *, filter_attr: str | None = None, filter_value: str | None = None) -> list[SCIMGroup]:
        tenant = normalize_tenant_id(tenant_id)
        query = "SELECT data FROM scim_groups WHERE tenant_id = %s ORDER BY display_name ASC, group_id ASC"
        params: tuple[object, ...] = (tenant,)
        if filter_attr == "displayName":
            query = "SELECT data FROM scim_groups WHERE tenant_id = %s AND display_name = %s ORDER BY display_name ASC, group_id ASC"
            params = (tenant, filter_value)
        elif filter_attr == "externalId":
            query = "SELECT data FROM scim_groups WHERE tenant_id = %s AND external_id = %s ORDER BY display_name ASC, group_id ASC"
            params = (tenant, filter_value)
        elif filter_attr == "id":
            query = "SELECT data FROM scim_groups WHERE tenant_id = %s AND group_id = %s ORDER BY display_name ASC, group_id ASC"
            params = (tenant, filter_value)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(query, params).fetchall()
        return [_load_group(row[0]) for row in rows]

    def delete_group(self, tenant_id: str, group_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM scim_groups WHERE tenant_id = %s AND group_id = %s",
                (normalize_tenant_id(tenant_id), group_id),
            )
            conn.commit()
            return cursor.rowcount > 0


def _load_user(raw: object) -> SCIMUser:
    return SCIMUser(**(raw if isinstance(raw, dict) else json.loads(str(raw))))


def _load_group(raw: object) -> SCIMGroup:
    return SCIMGroup(**(raw if isinstance(raw, dict) else json.loads(str(raw))))
