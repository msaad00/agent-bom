"""Tenant-RLS backstop parity for two tenant-adjacent Postgres tables.

Defect: ``audit_chain_checkpoint`` (has tenant_id PK) and ``scan_dispatch_queue``
(has tenant_id) sat outside the FORCE-ROW-LEVEL-SECURITY backstop that ~47 other
tables use. No live leak today (queries filter by tenant manually) but they lost
the systematic backstop.

Resolution:
  * ``audit_chain_checkpoint`` is now registered with ``_ensure_tenant_rls`` for
    parity — its append path already runs under the request tenant context and
    its cross-tenant startup rebuild runs under an explicit ``bypass_tenant_rls``.
  * ``scan_dispatch_queue`` is global-by-design routing metadata (job_id +
    tenant_id + timing; the confidential payload lives in the RLS-protected
    ``scan_jobs.data``). It is intentionally NOT RLS'd because the background
    claim-loop must see pending jobs across all tenants. This test locks that
    intent: it stays out of RLS AND must never grow a confidential column.

A live Postgres is not required — a mock connection captures the emitted DDL and
records every ``_ensure_tenant_rls`` registration.
"""

from __future__ import annotations

import re

from agent_bom.api import postgres_audit as audit_mod
from agent_bom.api import postgres_job_store as job_mod


class _FakeCursor:
    def __init__(self, rows=None):
        self._rows = rows or []
        self.rowcount = len(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class _FakeConn:
    def __init__(self):
        self.executed: list[tuple[str, object]] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def commit(self):
        return None

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        low = " ".join(sql.split()).lower()
        if low.startswith("select count(*)"):
            return _FakeCursor([(0,)])
        if low.startswith("select"):
            return _FakeCursor([])
        return _FakeCursor()


class _FakePool:
    def __init__(self):
        self.conn = _FakeConn()

    def connection(self):
        return self.conn


def _rls_registrations(monkeypatch, module) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(module, "_ensure_tenant_rls", lambda conn, table, column: calls.append((table, column)))
    return calls


def _create_table_columns(ddl: str, table: str) -> set[str]:
    """Extract column names from a ``CREATE TABLE ... table ( ... )`` block."""
    marker = ddl.lower().find(f"create table if not exists {table}")
    assert marker != -1, f"{table} CREATE TABLE not found"
    open_paren = ddl.index("(", marker)
    depth = 0
    end = open_paren
    for i in range(open_paren, len(ddl)):
        if ddl[i] == "(":
            depth += 1
        elif ddl[i] == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    body = ddl[open_paren + 1 : end]
    cols: set[str] = set()
    depth = 0
    for raw in body.split("\n"):
        line = raw.strip()
        # Only split on commas at paren-depth 0 by scanning char state per line.
        segment = line.strip().rstrip(",").strip()
        if not segment or segment.startswith("--"):
            continue
        first = segment.split()[0]
        if first.upper() in ("PRIMARY", "CONSTRAINT", "UNIQUE", "FOREIGN", "CHECK"):
            continue
        if re.match(r"^[a-z_][a-z0-9_]*$", first):
            cols.add(first.lower())
    return cols


# ── audit_chain_checkpoint: now under the RLS backstop ───────────────────────


def test_audit_chain_checkpoint_registered_for_rls(monkeypatch):
    calls = _rls_registrations(monkeypatch, audit_mod)
    pool = _FakePool()

    audit_mod.PostgresAuditLog(pool=pool)

    assert ("audit_chain_checkpoint", "tenant_id") in calls
    # audit_log parity (already present) must remain.
    assert ("audit_log", "team_id") in calls

    ddl = "\n".join(sql for sql, _ in pool.conn.executed).lower()
    assert "create table if not exists audit_chain_checkpoint" in ddl
    cols = _create_table_columns(ddl, "audit_chain_checkpoint")
    assert "tenant_id" in cols


# ── scan_dispatch_queue: global-by-design routing metadata, no RLS ───────────

# The full, intentional column set. If a future change adds a column it must
# fail here first, forcing an explicit decision: is the new column confidential
# (then RLS the table) or still pure routing metadata (then widen this set)?
_DISPATCH_QUEUE_ALLOWED_COLUMNS = {
    "job_id",
    "tenant_id",
    "created_at",
    "status",
    "claimed_by",
    "lease_expires_at",
}


def test_scan_dispatch_queue_is_global_routing_metadata_only(monkeypatch):
    calls = _rls_registrations(monkeypatch, job_mod)
    pool = _FakePool()

    job_mod.PostgresJobStore(pool=pool)

    registered = {table for table, _ in calls}
    # scan_jobs / cis_benchmark_checks stay RLS-registered; the dispatch queue does not.
    assert "scan_jobs" in registered
    assert "scan_dispatch_queue" not in registered

    ddl = "\n".join(sql for sql, _ in pool.conn.executed).lower()
    cols = _create_table_columns(ddl, "scan_dispatch_queue")
    assert cols == _DISPATCH_QUEUE_ALLOWED_COLUMNS, (
        "scan_dispatch_queue grew/lost a column; confirm it is still pure routing "
        "metadata (widen the allow-set) or RLS-protect it if it now holds "
        f"tenant-confidential data. Got: {sorted(cols)}"
    )
