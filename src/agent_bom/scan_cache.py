"""SQLite-backed scan result cache for OSV vulnerability data.

Caches OSV query results by ``(ecosystem, name, version)`` with a
configurable TTL (default 24 h).  Cache location defaults to
``~/.agent-bom/scan_cache.db`` and can be overridden via the
``AGENT_BOM_SCAN_CACHE`` environment variable.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 86_400  # 24 hours
DEFAULT_CACHE_DIR = Path.home() / ".agent-bom"


class ScanCache:
    """Persistent cache for OSV vulnerability scan results."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        if db_path is None:
            db_path = os.environ.get(
                "AGENT_BOM_SCAN_CACHE",
                str(DEFAULT_CACHE_DIR / "scan_cache.db"),
            )
        self._db_path = str(db_path)
        self._ttl = ttl_seconds
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS osv_cache (
                cache_key  TEXT PRIMARY KEY,
                vulns_json TEXT NOT NULL,
                cached_at  REAL NOT NULL
            )
            """
        )
        self._conn.commit()

    # ── public API ──────────────────────────────────────────────────────

    def get(self, ecosystem: str, name: str, version: str) -> list[dict] | None:
        """Return cached vulns for a package, or *None* on miss / expired."""
        key = self._key(ecosystem, name, version)
        row = self._conn.execute(
            "SELECT vulns_json, cached_at FROM osv_cache WHERE cache_key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        if time.time() - row[1] > self._ttl:
            self._conn.execute("DELETE FROM osv_cache WHERE cache_key = ?", (key,))
            self._conn.commit()
            return None
        return json.loads(row[0])

    def put(self, ecosystem: str, name: str, version: str, vulns: list[dict]) -> None:
        """Store or replace the cached vulns for a package."""
        key = self._key(ecosystem, name, version)
        self._conn.execute(
            "INSERT OR REPLACE INTO osv_cache (cache_key, vulns_json, cached_at) VALUES (?, ?, ?)",
            (key, json.dumps(vulns), time.time()),
        )
        self._conn.commit()

    def cleanup_expired(self) -> int:
        """Delete entries older than the TTL.  Returns the count removed."""
        cutoff = time.time() - self._ttl
        cur = self._conn.execute("DELETE FROM osv_cache WHERE cached_at < ?", (cutoff,))
        self._conn.commit()
        return cur.rowcount or 0

    def clear(self) -> None:
        """Remove all entries."""
        self._conn.execute("DELETE FROM osv_cache")
        self._conn.commit()

    @property
    def size(self) -> int:
        """Number of entries currently cached."""
        row = self._conn.execute("SELECT COUNT(*) FROM osv_cache").fetchone()
        return row[0] if row else 0

    # ── helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _key(ecosystem: str, name: str, version: str) -> str:
        return f"{ecosystem}:{name}@{version}"
