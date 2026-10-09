"""PostgreSQL-backed vulnerability scan cache."""

from __future__ import annotations

import json
import time
from typing import Any, cast

from agent_bom.api.storage_schema import ensure_postgres_schema_version

from .postgres_common import (
    _get_pool,
)


class PostgresScanCache:
    """PostgreSQL-backed OSV vulnerability scan cache."""

    def __init__(self, pool: Any = None, ttl_seconds: int = 86_400) -> None:
        self._pool = pool or _get_pool()
        self._ttl = ttl_seconds
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "scan_cache"):
                return
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
            return cast("list[dict[Any, Any]]", json.loads(row[0]))

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
        from agent_bom.scan_cache import ScanCache

        return ScanCache._key(ecosystem, name, version)
