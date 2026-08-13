"""Durable persistence for skills-scan REST runs (#4790 REST parity).

Mirrors :mod:`agent_bom.api.kspm_posture_store`: two interchangeable backends
behind one contract —

* :class:`InMemorySkillsScanStore` — the default, non-durable tier.
* :class:`SQLiteSkillsScanStore` — node-local, restart-safe, and safe under
  cross-process writers (WAL + busy timeout).

Tenant isolation is application-level: ``tenant_id`` leads every WHERE clause and
is part of the primary key ``(tenant_id, run_id)``, so two tenants can carry a
run with the SAME logical run_id without one dropping or leaking into the other.
Only the already-redacted skills-scan envelope is stored (per-file trust verdict,
provenance status, and audit findings) — never a secret value and never the raw
skill body.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass
class SkillsScanRun:
    """One persisted skills-scan run for a tenant."""

    tenant_id: str
    run_id: str
    created_at: str
    payload: dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> tuple[str, str, str, str]:
        return (
            self.tenant_id,
            self.run_id,
            self.created_at,
            json.dumps(self.payload, sort_keys=True, separators=(",", ":")),
        )

    @classmethod
    def from_row(cls, row: tuple[Any, ...]) -> "SkillsScanRun":
        return cls(
            tenant_id=str(row[0]),
            run_id=str(row[1]),
            created_at=str(row[2]),
            payload=json.loads(str(row[3])) if row[3] else {},
        )


class SkillsScanStore(Protocol):
    """Contract shared by every skills-scan backend."""

    def init_schema(self) -> None: ...

    def put(self, run: SkillsScanRun) -> None:
        """Persist (upsert) one scan run, keyed on ``(tenant_id, run_id)``."""
        ...

    def list_for_tenant(self, tenant_id: str, *, limit: int = 100) -> list[SkillsScanRun]:
        """Return one tenant's runs, most recent first."""
        ...

    def latest_for_tenant(self, tenant_id: str) -> SkillsScanRun | None:
        """Return the tenant's most recent run, or ``None`` when there is none."""
        ...


def _sort_key(run: SkillsScanRun) -> tuple[str, str]:
    return (run.created_at, run.run_id)


class InMemorySkillsScanStore:
    """Process-local, non-durable store (default tier)."""

    def __init__(self) -> None:
        self._rows: dict[tuple[str, str], SkillsScanRun] = {}
        self._lock = threading.Lock()

    def init_schema(self) -> None:  # pragma: no cover - nothing to create
        return None

    def put(self, run: SkillsScanRun) -> None:
        with self._lock:
            self._rows[(run.tenant_id, run.run_id)] = run

    def list_for_tenant(self, tenant_id: str, *, limit: int = 100) -> list[SkillsScanRun]:
        with self._lock:
            rows = [r for r in self._rows.values() if r.tenant_id == tenant_id]
        rows.sort(key=_sort_key, reverse=True)
        return rows[:limit]

    def latest_for_tenant(self, tenant_id: str) -> SkillsScanRun | None:
        rows = self.list_for_tenant(tenant_id, limit=1)
        return rows[0] if rows else None


class SQLiteSkillsScanStore:
    """Node-local, restart-safe, cross-process-safe SQLite backend."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self.init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def init_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS skills_scan_run (
                    tenant_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, run_id)
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_skills_scan_tenant_time ON skills_scan_run (tenant_id, created_at DESC, run_id DESC)"
            )

    def put(self, run: SkillsScanRun) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO skills_scan_run (tenant_id, run_id, created_at, payload_json) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT (tenant_id, run_id) DO UPDATE SET "
                "created_at=excluded.created_at, payload_json=excluded.payload_json",
                run.to_row(),
            )

    def list_for_tenant(self, tenant_id: str, *, limit: int = 100) -> list[SkillsScanRun]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT tenant_id, run_id, created_at, payload_json "
                "FROM skills_scan_run WHERE tenant_id = ? "
                "ORDER BY created_at DESC, run_id DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [SkillsScanRun.from_row(tuple(row)) for row in rows]

    def latest_for_tenant(self, tenant_id: str) -> SkillsScanRun | None:
        rows = self.list_for_tenant(tenant_id, limit=1)
        return rows[0] if rows else None


# ── process-global default store ─────────────────────────────────────────────

_default_store: SkillsScanStore | None = None
_default_lock = threading.Lock()


def get_skills_scan_store() -> SkillsScanStore:
    """Return the process default skills-scan store (in-memory until configured)."""
    global _default_store
    with _default_lock:
        if _default_store is None:
            _default_store = InMemorySkillsScanStore()
        return _default_store


def set_skills_scan_store(store: SkillsScanStore | None) -> None:
    global _default_store
    with _default_lock:
        _default_store = store


__all__ = [
    "InMemorySkillsScanStore",
    "SQLiteSkillsScanStore",
    "SkillsScanRun",
    "SkillsScanStore",
    "get_skills_scan_store",
    "set_skills_scan_store",
]
