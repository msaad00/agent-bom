"""Migration-owned report jobs with application RLS and separate dispatch identity."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from agent_bom.api.postgres_common import _get_pool, _maintenance_connection, _tenant_connection, bypass_tenant_rls
from agent_bom.api.report_job_store import REPORT_INDEX_SQL, REPORT_TABLE_SQL, SQLReportJobStore
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresReportJobStore(SQLReportJobStore):
    postgres = True

    def __init__(self, pool: Any = None, maintenance_pool: Any = None) -> None:
        self._pool = pool or _get_pool()
        self._maintenance_pool = maintenance_pool
        with self._pool.connection() as conn:
            if ensure_postgres_schema_version(conn, "report_jobs"):
                from agent_bom.api.postgres_common import _ensure_tenant_rls

                conn.execute(REPORT_TABLE_SQL)
                for sql in REPORT_INDEX_SQL:
                    conn.execute(sql)
                _ensure_tenant_rls(conn, "report_jobs", "tenant_id")
            conn.commit()

    @contextmanager
    def _connection(self, tenant_id: str | None, *, write: bool = False) -> Iterator[Any]:
        if tenant_id is None:
            with bypass_tenant_rls(audit=False, warn=False), _maintenance_connection(self._maintenance_pool) as conn:
                yield conn
                conn.commit()
        else:
            # Do not rebind to the argument: the authenticated context must
            # independently authorize the explicit tenant filter in every query.
            with _tenant_connection(self._pool) as conn:
                yield conn
                conn.commit()
