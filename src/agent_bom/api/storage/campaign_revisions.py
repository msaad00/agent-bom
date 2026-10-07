"""Durable campaign reconciliation checkpoints and source-write fences.

Source revision triggers enqueue work in the evidence writer's transaction.
Campaign writes lock the same tenant row, so an older collection cannot replace
membership after another replica has committed newer evidence.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from typing import Any

from agent_bom.api.postgres_common import _maintenance_connection, _tenant_connection, bypass_tenant_rls
from agent_bom.api.storage_schema import ensure_sqlite_schema_version


class CampaignEvidenceChangedError(RuntimeError):
    """The collected source no longer matches committed evidence."""


class CampaignAlreadyReconciledError(RuntimeError):
    """A replica has already checkpointed this complete source generation."""


def initialize_sqlite_campaign_evidence(conn: Any) -> None:
    ensure_sqlite_schema_version(conn, "campaign_evidence_state")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS campaign_evidence_state "
        "(tenant_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, reconciled_revision INTEGER NOT NULL DEFAULT 0)"
    )
    for table in ("job_overview_revisions", "hub_overview_revisions"):
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
            continue
        for event in ("INSERT", "UPDATE", "DELETE"):
            alias = "OLD" if event == "DELETE" else "NEW"
            conn.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_campaign_{event.lower()} AFTER {event} ON {table} BEGIN "  # nosec B608 - fixed table and event tuples
                f"INSERT INTO campaign_evidence_state(tenant_id,revision) VALUES ({alias}.tenant_id,1) "
                "ON CONFLICT(tenant_id) DO UPDATE SET revision=revision+1; END"
            )
        conn.execute(f"INSERT OR IGNORE INTO campaign_evidence_state(tenant_id,revision) SELECT tenant_id,1 FROM {table}")  # nosec B608


class MemoryCampaignEvidenceState:
    def __init__(self) -> None:
        self.revisions: dict[str, int] = {}
        self.checkpoints: dict[str, int] = {}

    def revision(self, tenant_id: str) -> int:
        return self.revisions.get(tenant_id, 0)

    def changed(self, tenant_id: str) -> None:
        self.revisions[tenant_id] = self.revision(tenant_id) + 1

    def pending_tenants(self, limit: int = 100, after: str = "") -> list[str]:
        return sorted(t for t, r in self.revisions.items() if t > after and r != self.checkpoints.get(t, 0))[:limit]

    def guard(self, tenant_id: str, expected: int | None, conn: Any = None) -> None:
        if expected is not None and self.revision(tenant_id) != expected:
            raise CampaignEvidenceChangedError("Campaign evidence changed; collect a fresh source.")

    def claim(self, tenant_id: str, revision: int | None, conn: Any = None) -> None:
        if revision is not None and self.checkpoints.get(tenant_id) == revision:
            raise CampaignAlreadyReconciledError("Campaign source already reconciled.")

    def checkpoint(self, tenant_id: str, revision: int | None, conn: Any = None) -> None:
        if revision is not None:
            self.checkpoints[tenant_id] = revision


class SQLiteCampaignEvidenceState:
    def __init__(self, connection: Callable[[], Any]) -> None:
        self.connection = connection

    @contextmanager
    def write(self, tenant_id: str, expected: int | None):
        conn = self.connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            self.guard(tenant_id, expected, conn)
            yield conn
            conn.commit()
        except Exception:  # broad-except: Roll back the entire transaction on every failure, then re-raise unchanged.
            conn.rollback()
            raise

    def revision(self, tenant_id: str) -> int:
        row = self.connection().execute("SELECT revision FROM campaign_evidence_state WHERE tenant_id=?", (tenant_id,)).fetchone()
        return int(row[0]) if row else 0

    def pending_tenants(self, limit: int = 100, after: str = "") -> list[str]:
        return [
            r[0]
            for r in self.connection().execute(
                "SELECT tenant_id FROM campaign_evidence_state WHERE revision!=reconciled_revision "
                "AND tenant_id>? ORDER BY tenant_id LIMIT ?",
                (
                    after,
                    limit,
                ),
            )
        ]

    def guard(self, tenant_id: str, expected: int | None, conn: Any = None) -> None:
        if expected is not None and self.revision(tenant_id) != expected:
            raise CampaignEvidenceChangedError("Campaign evidence changed; collect a fresh source.")

    def claim(self, tenant_id: str, revision: int | None, conn: Any = None) -> None:
        if revision is None:
            return
        row = conn.execute("SELECT reconciled_revision FROM campaign_evidence_state WHERE tenant_id=?", (tenant_id,)).fetchone()
        if row and revision > 0 and int(row[0]) == revision:
            raise CampaignAlreadyReconciledError("Campaign source already reconciled.")
        conn.execute("INSERT OR IGNORE INTO campaign_evidence_state VALUES (?,0,0)", (tenant_id,))

    def checkpoint(self, tenant_id: str, revision: int | None, conn: Any = None) -> None:
        if revision is not None:
            conn.execute("UPDATE campaign_evidence_state SET reconciled_revision=? WHERE tenant_id=?", (revision, tenant_id))


class PostgresCampaignEvidenceState:
    def __init__(self, pool: Any) -> None:
        self.pool = pool

    def revision(self, tenant_id: str) -> int:
        with _tenant_connection(self.pool) as conn:
            row = conn.execute("SELECT revision FROM campaign_evidence_state WHERE tenant_id=%s", (tenant_id,)).fetchone()
        return int(row[0]) if row else 0

    def pending_tenants(self, limit: int = 100, after: str = "") -> list[str]:
        with bypass_tenant_rls(audit=False, warn=False), _maintenance_connection() as conn:
            return [
                r[0]
                for r in conn.execute(
                    "SELECT tenant_id FROM campaign_evidence_state WHERE revision!=reconciled_revision "
                    "AND tenant_id>%s ORDER BY tenant_id LIMIT %s",
                    (
                        after,
                        limit,
                    ),
                )
            ]

    def guard(self, tenant_id: str, expected: int | None, conn: Any = None) -> None:
        if expected is None:
            return
        conn.execute("INSERT INTO campaign_evidence_state(tenant_id,revision) VALUES (%s,0) ON CONFLICT DO NOTHING", (tenant_id,))
        row = conn.execute("SELECT revision FROM campaign_evidence_state WHERE tenant_id=%s FOR UPDATE", (tenant_id,)).fetchone()
        if not row or int(row[0]) != expected:
            raise CampaignEvidenceChangedError("Campaign evidence changed; collect a fresh source.")

    def claim(self, tenant_id: str, revision: int | None, conn: Any = None) -> None:
        if revision is None:
            return
        row = conn.execute("SELECT reconciled_revision FROM campaign_evidence_state WHERE tenant_id=%s", (tenant_id,)).fetchone()
        if row and revision > 0 and int(row[0]) == revision:
            raise CampaignAlreadyReconciledError("Campaign source already reconciled.")

    def checkpoint(self, tenant_id: str, revision: int | None, conn: Any = None) -> None:
        if revision is not None:
            conn.execute("UPDATE campaign_evidence_state SET reconciled_revision=%s WHERE tenant_id=%s", (revision, tenant_id))
