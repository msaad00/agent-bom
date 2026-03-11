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
        max_entries: int | None = None,
    ) -> None:
        if db_path is None:
            db_path = os.environ.get(
                "AGENT_BOM_SCAN_CACHE",
                str(DEFAULT_CACHE_DIR / "scan_cache.db"),
            )
        self._db_path = str(db_path)
        self._ttl = ttl_seconds
        if max_entries is None:
            from agent_bom.config import SCAN_CACHE_MAX_ENTRIES

            max_entries = SCAN_CACHE_MAX_ENTRIES
        self._max_entries = max_entries
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
        self._evict_if_needed()

    def put_many(self, entries: list[tuple[str, str, str, list[dict]]]) -> None:
        """Batch insert/replace multiple cache entries in one transaction."""
        now = time.time()
        rows = [(self._key(eco, name, ver), json.dumps(vulns), now) for eco, name, ver, vulns in entries]
        self._conn.executemany(
            "INSERT OR REPLACE INTO osv_cache (cache_key, vulns_json, cached_at) VALUES (?, ?, ?)",
            rows,
        )
        self._conn.commit()
        self._evict_if_needed()

    def evict(self, ecosystem: str, name: str, version: str) -> None:
        """Remove a single entry from the cache, forcing a fresh fetch."""
        key = self._key(ecosystem, name, version)
        self._conn.execute("DELETE FROM osv_cache WHERE cache_key = ?", (key,))
        self._conn.commit()

    def evict_many(self, entries: list[tuple[str, str, str]]) -> int:
        """Remove specific entries from the cache in one transaction.

        Args:
            entries: List of (ecosystem, name, version) tuples.

        Returns:
            Number of entries removed.
        """
        keys = [(self._key(eco, name, ver),) for eco, name, ver in entries]
        cur = self._conn.executemany("DELETE FROM osv_cache WHERE cache_key = ?", keys)
        self._conn.commit()
        return cur.rowcount or 0

    def cleanup_expired(self) -> int:
        """Delete entries older than the TTL.  Returns the count removed."""
        cutoff = time.time() - self._ttl
        cur = self._conn.execute("DELETE FROM osv_cache WHERE cached_at < ?", (cutoff,))
        self._conn.commit()
        return cur.rowcount or 0

    def _evict_if_needed(self) -> None:
        """Remove the oldest entries when the cache exceeds *max_entries*.

        Uses a single DELETE … WHERE cache_key IN (SELECT … ORDER BY cached_at
        ASC LIMIT ?) so only one round-trip is needed.  No-op when *max_entries*
        is 0 (unbounded mode).
        """
        if self._max_entries <= 0:
            return
        row = self._conn.execute("SELECT COUNT(*) FROM osv_cache").fetchone()
        count = row[0] if row else 0
        excess = count - self._max_entries
        if excess > 0:
            self._conn.execute(
                """
                DELETE FROM osv_cache WHERE cache_key IN (
                    SELECT cache_key FROM osv_cache ORDER BY cached_at ASC LIMIT ?
                )
                """,
                (excess,),
            )
            self._conn.commit()
            logger.debug("scan_cache: evicted %d oldest entries (limit=%d)", excess, self._max_entries)

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
        from agent_bom.models import normalize_package_name

        return f"{ecosystem}:{normalize_package_name(name, ecosystem)}@{version}"
