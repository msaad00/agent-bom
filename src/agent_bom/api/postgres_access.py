"""PostgreSQL-backed access control and exception stores."""

from __future__ import annotations

import json

from agent_bom.api.auth import ApiKey, Role, verify_api_key
from agent_bom.api.exception_store import ExceptionStatus, VulnException

from .postgres_common import _ensure_tenant_rls, _get_pool, _tenant_connection, bypass_tenant_rls


class PostgresKeyStore:
    """PostgreSQL-backed API key storage with tenant RLS."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    key_hash TEXT NOT NULL,
                    key_salt TEXT NOT NULL,
                    key_prefix TEXT NOT NULL,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    team_id TEXT NOT NULL DEFAULT 'default',
                    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
                    created_by TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used TEXT,
                    revoked_at TEXT,
                    rotation_overlap_until TEXT,
                    replacement_key_id TEXT,
                    revoked BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
            conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'api_keys' AND column_name = 'team_id'
                    ) THEN
                        ALTER TABLE api_keys ADD COLUMN team_id TEXT NOT NULL DEFAULT 'default';
                    END IF;
                END
                $$;
            """)
            conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'api_keys' AND column_name = 'revoked_at'
                    ) THEN
                        ALTER TABLE api_keys ADD COLUMN revoked_at TEXT;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'api_keys' AND column_name = 'rotation_overlap_until'
                    ) THEN
                        ALTER TABLE api_keys ADD COLUMN rotation_overlap_until TEXT;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'api_keys' AND column_name = 'replacement_key_id'
                    ) THEN
                        ALTER TABLE api_keys ADD COLUMN replacement_key_id TEXT;
                    END IF;
                END
                $$;
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_team ON api_keys(team_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(team_id, revoked)")
            _ensure_tenant_rls(conn, "api_keys", "team_id")
            conn.commit()

    @staticmethod
    def _row_to_key(row) -> ApiKey:
        scopes = row[7] if isinstance(row[7], list) else json.loads(row[7] or "[]")
        return ApiKey(
            key_id=row[0],
            key_hash=row[1],
            key_salt=row[2],
            key_prefix=row[3],
            name=row[4],
            role=Role(row[5]),
            tenant_id=row[6],
            scopes=scopes,
            created_at=row[8],
            expires_at=row[9],
            revoked_at=row[10],
            rotation_overlap_until=row[11],
            replacement_key_id=row[12],
        )

    def add(self, key: ApiKey) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO api_keys
                   (
                     key_id, key_hash, key_salt, key_prefix, name, role, team_id, scopes,
                     created_at, expires_at, revoked_at, rotation_overlap_until, replacement_key_id, revoked
                   )
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE)
                   ON CONFLICT (key_id) DO UPDATE SET
                     key_hash = EXCLUDED.key_hash,
                     key_salt = EXCLUDED.key_salt,
                     key_prefix = EXCLUDED.key_prefix,
                     name = EXCLUDED.name,
                     role = EXCLUDED.role,
                     team_id = EXCLUDED.team_id,
                     scopes = EXCLUDED.scopes,
                     created_at = EXCLUDED.created_at,
                     expires_at = EXCLUDED.expires_at,
                     revoked_at = EXCLUDED.revoked_at,
                     rotation_overlap_until = EXCLUDED.rotation_overlap_until,
                     replacement_key_id = EXCLUDED.replacement_key_id,
                     revoked = FALSE""",
                (
                    key.key_id,
                    key.key_hash,
                    key.key_salt,
                    key.key_prefix,
                    key.name,
                    key.role.value,
                    key.tenant_id,
                    json.dumps(key.scopes),
                    key.created_at,
                    key.expires_at,
                    key.revoked_at,
                    key.rotation_overlap_until,
                    key.replacement_key_id,
                ),
            )
            conn.commit()

    def remove(self, key_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                """UPDATE api_keys
                   SET revoked = TRUE,
                       revoked_at = NOW()::text,
                       rotation_overlap_until = NULL
                   WHERE key_id = %s AND revoked = FALSE""",
                (key_id,),
            )
            conn.commit()
            return cursor.rowcount > 0

    def mark_rotating(self, key_id: str, *, replacement_key_id: str, overlap_until: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                """UPDATE api_keys
                   SET replacement_key_id = %s,
                       rotation_overlap_until = %s
                   WHERE key_id = %s AND revoked = FALSE""",
                (replacement_key_id, overlap_until, key_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get(self, key_id: str) -> ApiKey | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """SELECT
                       key_id, key_hash, key_salt, key_prefix, name, role, team_id, scopes,
                       created_at, expires_at, revoked_at, rotation_overlap_until, replacement_key_id
                   FROM api_keys
                   WHERE key_id = %s""",
                (key_id,),
            ).fetchone()
            return self._row_to_key(row) if row else None

    def list_keys(self, tenant_id: str | None = None) -> list[ApiKey]:
        query = """
            SELECT
                key_id, key_hash, key_salt, key_prefix, name, role, team_id, scopes,
                created_at, expires_at, revoked_at, rotation_overlap_until, replacement_key_id
            FROM api_keys
            WHERE TRUE
        """
        params: tuple[object, ...] = ()
        if tenant_id is not None:
            query += " AND team_id = %s"
            params = (tenant_id,)
        query += " ORDER BY created_at DESC"
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_key(row) for row in rows]

    def verify(self, raw_key: str) -> ApiKey | None:
        prefix = raw_key[:12]
        with bypass_tenant_rls():
            with _tenant_connection(self._pool) as conn:
                rows = conn.execute(
                    """SELECT
                           key_id, key_hash, key_salt, key_prefix, name, role, team_id, scopes,
                           created_at, expires_at, revoked_at, rotation_overlap_until, replacement_key_id
                       FROM api_keys
                       WHERE key_prefix = %s""",
                    (prefix,),
                ).fetchall()
        return verify_api_key(raw_key, [self._row_to_key(row) for row in rows])

    def has_keys(self) -> bool:
        with bypass_tenant_rls():
            with _tenant_connection(self._pool) as conn:
                row = conn.execute("SELECT COUNT(*) FROM api_keys WHERE revoked = FALSE").fetchone()
                return bool(row and row[0] > 0)


class PostgresExceptionStore:
    """PostgreSQL-backed vulnerability exception storage with tenant RLS."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS exceptions (
                    exception_id TEXT PRIMARY KEY,
                    vuln_id TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    server_name TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    requested_by TEXT NOT NULL DEFAULT '',
                    approved_by TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL DEFAULT '',
                    approved_at TEXT NOT NULL DEFAULT '',
                    revoked_at TEXT NOT NULL DEFAULT '',
                    team_id TEXT NOT NULL DEFAULT 'default'
                )
            """)
            conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'exceptions' AND column_name = 'team_id'
                    ) THEN
                        ALTER TABLE exceptions ADD COLUMN team_id TEXT NOT NULL DEFAULT 'default';
                    END IF;
                END
                $$;
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_exc_status ON exceptions(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_exc_team ON exceptions(team_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_exc_vuln ON exceptions(vuln_id)")
            _ensure_tenant_rls(conn, "exceptions", "team_id")
            conn.commit()

    @staticmethod
    def _row_to_exception(row) -> VulnException:
        return VulnException(
            exception_id=row[0],
            vuln_id=row[1],
            package_name=row[2],
            server_name=row[3],
            reason=row[4],
            requested_by=row[5],
            approved_by=row[6],
            status=ExceptionStatus(row[7]),
            created_at=row[8],
            expires_at=row[9],
            approved_at=row[10],
            revoked_at=row[11],
            tenant_id=row[12],
        )

    def put(self, exc: VulnException) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO exceptions
                   (exception_id, vuln_id, package_name, server_name, reason, requested_by, approved_by, status,
                    created_at, expires_at, approved_at, revoked_at, team_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (exception_id) DO UPDATE SET
                     vuln_id = EXCLUDED.vuln_id,
                     package_name = EXCLUDED.package_name,
                     server_name = EXCLUDED.server_name,
                     reason = EXCLUDED.reason,
                     requested_by = EXCLUDED.requested_by,
                     approved_by = EXCLUDED.approved_by,
                     status = EXCLUDED.status,
                     created_at = EXCLUDED.created_at,
                     expires_at = EXCLUDED.expires_at,
                     approved_at = EXCLUDED.approved_at,
                     revoked_at = EXCLUDED.revoked_at,
                     team_id = EXCLUDED.team_id""",
                (
                    exc.exception_id,
                    exc.vuln_id,
                    exc.package_name,
                    exc.server_name,
                    exc.reason,
                    exc.requested_by,
                    exc.approved_by,
                    exc.status.value,
                    exc.created_at,
                    exc.expires_at,
                    exc.approved_at,
                    exc.revoked_at,
                    exc.tenant_id,
                ),
            )
            conn.commit()

    def get(self, exception_id: str) -> VulnException | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """SELECT exception_id, vuln_id, package_name, server_name, reason, requested_by, approved_by,
                          status, created_at, expires_at, approved_at, revoked_at, team_id
                   FROM exceptions
                   WHERE exception_id = %s""",
                (exception_id,),
            ).fetchone()
            return self._row_to_exception(row) if row else None

    def delete(self, exception_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute("DELETE FROM exceptions WHERE exception_id = %s", (exception_id,))
            conn.commit()
            return cursor.rowcount > 0

    def list_all(self, status: str | None = None, tenant_id: str = "default") -> list[VulnException]:
        query = """
            SELECT exception_id, vuln_id, package_name, server_name, reason, requested_by, approved_by,
                   status, created_at, expires_at, approved_at, revoked_at, team_id
            FROM exceptions
            WHERE team_id = %s
        """
        params: list[object] = [tenant_id]
        if status:
            query += " AND status = %s"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [self._row_to_exception(row) for row in rows]

    def find_matching(self, vuln_id: str, package_name: str, server_name: str = "", tenant_id: str = "default") -> VulnException | None:
        active = self.list_all(status="active", tenant_id=tenant_id)
        approved = self.list_all(status="approved", tenant_id=tenant_id)
        for exc in active + approved:
            if exc.matches(vuln_id, package_name, server_name):
                return exc
        return None
