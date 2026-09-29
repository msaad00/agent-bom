"""Transaction-owned ledger counts and SQLite ordinal allocation.

Callers hold the hub tenant write lock before reading or updating this state.
Every supported ledger mutation updates it in the same transaction as the rows.
An upgrade must drain older writers, whose process-local counters are incompatible.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from agent_bom.api.storage.sql import SqlSession
from agent_bom.core.tenancy import require_explicit_tenant_id

INGEST_STATE_DDL = """CREATE TABLE IF NOT EXISTS hub_ledger_ingest_state (
    tenant_id TEXT PRIMARY KEY,
    finding_count BIGINT NOT NULL CHECK (finding_count >= 0),
    next_ordinal BIGINT NOT NULL CHECK (next_ordinal >= 1)
)"""


@dataclass(frozen=True)
class LedgerIngestState:
    finding_count: int
    next_ordinal: int


def read_ingest_state(tx: SqlSession, tenant_id: str) -> LedgerIngestState:
    """Bootstrap an existing tenant once, then use a primary-key lookup per batch."""
    tenant = require_explicit_tenant_id(tenant_id)
    row = tx.execute("SELECT finding_count, next_ordinal FROM hub_ledger_ingest_state WHERE tenant_id = ?", (tenant,)).fetchone()
    if row is None:
        row = tx.execute(
            """INSERT INTO hub_ledger_ingest_state (tenant_id, finding_count, next_ordinal)
            SELECT ?, COUNT(*), COALESCE(MAX(ordinal), 0) + 1 FROM compliance_hub_findings WHERE tenant_id = ?
            RETURNING finding_count, next_ordinal""",
            (tenant, tenant),
        ).fetchone()
    if row is None:
        raise RuntimeError("Ledger ingest state could not be initialized")
    return LedgerIngestState(int(row[0]), int(row[1]))


def write_ingest_state(tx: SqlSession, tenant_id: str, state: LedgerIngestState) -> None:
    tenant = require_explicit_tenant_id(tenant_id)
    tx.execute(
        "UPDATE hub_ledger_ingest_state SET finding_count = ?, next_ordinal = ? WHERE tenant_id = ?",
        (state.finding_count, state.next_ordinal, tenant),
    )


def ensure_sqlite_ingest_state(conn: sqlite3.Connection) -> None:
    """Repair historical ordinal ties once, preserving payloads and ledger pointers.

    SQLite's old per-instance ordinal cache could reuse an ordinal. Move only
    duplicate rows above that tenant's high-water mark, preserving the earliest
    stable finding-id winner. Old cursors must be restarted after this upgrade.
    The caller's schema transaction excludes writers during repair/index creation.
    """
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'hub_ledger_ingest_state'").fetchone():
        return
    conn.execute("""CREATE TEMP TABLE hub_ordinal_repair AS
        WITH ranked AS (
            SELECT tenant_id, finding_id, ordinal,
                   ROW_NUMBER() OVER (PARTITION BY tenant_id, ordinal ORDER BY finding_id) AS tie,
                   MAX(ordinal) OVER (PARTITION BY tenant_id) AS high_water
            FROM compliance_hub_findings
        )
        SELECT tenant_id, finding_id,
               high_water + ROW_NUMBER() OVER (PARTITION BY tenant_id ORDER BY ordinal, finding_id) AS ordinal
        FROM ranked WHERE tie > 1""")
    conn.execute("CREATE UNIQUE INDEX hub_ordinal_repair_key ON hub_ordinal_repair(tenant_id, finding_id)")
    conn.execute("""UPDATE compliance_hub_findings SET ordinal = (
        SELECT r.ordinal FROM hub_ordinal_repair r
        WHERE r.tenant_id = compliance_hub_findings.tenant_id AND r.finding_id = compliance_hub_findings.finding_id
    ) WHERE (tenant_id, finding_id) IN (SELECT tenant_id, finding_id FROM hub_ordinal_repair)""")
    conn.execute("""UPDATE hub_findings_current SET ledger_ordinal = (
        SELECT r.ordinal FROM hub_ordinal_repair r
        WHERE r.tenant_id = hub_findings_current.tenant_id AND r.finding_id = hub_findings_current.ledger_finding_id
    ) WHERE (tenant_id, ledger_finding_id) IN (SELECT tenant_id, finding_id FROM hub_ordinal_repair)""")
    conn.execute("DROP TABLE hub_ordinal_repair")
    conn.execute("DROP INDEX IF EXISTS idx_hub_findings_tenant_order")
    conn.execute("CREATE UNIQUE INDEX idx_hub_findings_tenant_order ON compliance_hub_findings(tenant_id, ordinal)")
    conn.execute(INGEST_STATE_DDL)
