"""Tenant-scoped governance audit chain: isolation + integrity.

These tests pin the invariants that a single, global audit chain violated:

* Two tenants performing the *same* logical lifecycle action on a same-named
  target must not collide — neither row may be silently dropped, and each
  tenant's chain must verify independently.
* Concurrent same-tenant appends must not fork the chain (two rows sharing one
  ``prev_hash``), which ``verify_chain`` would report as tampered.
* Appending an identical action twice remains an idempotent no-op.
* An existing DB written under the old single-column ``UNIQUE(action_id)``
  schema migrates to the composite ``UNIQUE(tenant_id, action_id)`` without
  data loss, and new appends keep verifying.

Every behavioural test runs against *both* the in-memory and SQLite backends so
the two implementations cannot drift apart.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict
from datetime import datetime, timezone

import pytest

from agent_bom.api.governance_audit_log import (
    GovernanceAuditRecord,
    InMemoryGovernanceAuditLog,
    SQLiteGovernanceAuditLog,
    _seal_record,
    make_governance_audit_record,
)

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(params=["memory", "sqlite"])
def audit(request, tmp_path):
    if request.param == "memory":
        return InMemoryGovernanceAuditLog()
    return SQLiteGovernanceAuditLog(str(tmp_path / "gov.db"))


def _rec(
    tenant: str,
    *,
    target: str = "jit_1",
    action: str = "jit_grant_expired",
    window: str = "w1",
) -> GovernanceAuditRecord:
    return make_governance_audit_record(
        tenant_id=tenant,
        actor="system",
        action=action,
        target_type="jit_grant",
        target_id=target,
        reason="expired",
        before_state="active",
        after_state="revoked",
        observed_at=T0.isoformat(),
        window_key=window,
    )


def test_cross_tenant_same_action_both_persist(audit):
    """Same (action, target_id, window_key) for two tenants must not collide."""
    acme = _rec("acme")
    globex = _rec("globex")
    # tenant is folded into the derived id, so the two ids differ.
    assert acme.action_id != globex.action_id

    audit.append(acme)
    audit.append(globex)

    acme_rows = audit.list(tenant_id="acme")
    globex_rows = audit.list(tenant_id="globex")
    assert len(acme_rows) == 1
    assert len(globex_rows) == 1
    assert acme_rows[0].tenant_id == "acme"
    assert globex_rows[0].tenant_id == "globex"
    # Neither tenant's row was dropped.
    assert len(audit.list()) == 2

    result = audit.verify_chain()
    assert result["tampered"] == 0
    assert result["verified"] == 2


def test_cross_tenant_chains_are_independent(audit):
    """Each tenant is its own chain: a per-tenant verify sees only its rows."""
    audit.append(_rec("acme", target="a", window="1"))
    audit.append(_rec("globex", target="b", window="1"))
    audit.append(_rec("acme", target="a", window="2"))

    assert audit.verify_chain(tenant_id="acme")["verified"] == 2
    assert audit.verify_chain(tenant_id="acme")["tampered"] == 0
    assert audit.verify_chain(tenant_id="globex")["verified"] == 1
    assert audit.verify_chain(tenant_id="globex")["tampered"] == 0
    # A tenant's head is scoped to that tenant.
    assert audit.head_hash("acme") != audit.head_hash("globex")
    assert audit.head_hash("acme") == audit.list(tenant_id="acme")[0].record_hash


def test_concurrent_same_tenant_append_no_fork(audit):
    """Threads racing appends must not fork the chain; dups stay idempotent."""
    recs = [_rec("acme", target=f"t{i}", window=str(i)) for i in range(20)]

    def worker(rec: GovernanceAuditRecord) -> None:
        audit.append(rec)

    threads = [threading.Thread(target=worker, args=(r,)) for r in recs * 3]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly the 20 distinct actions persisted (true duplicates deduped).
    assert len(audit.list(tenant_id="acme")) == 20
    result = audit.verify_chain()
    assert result["tampered"] == 0
    assert result["verified"] == 20


def test_idempotent_append_is_noop(audit):
    rec = _rec("acme")
    first = audit.append(rec)
    second = audit.append(rec)
    assert first.record_hash == second.record_hash
    assert len(audit.list()) == 1
    assert audit.verify_chain()["tampered"] == 0


def _old_schema_ddl() -> str:
    # The pre-fix schema: single-column global UNIQUE(action_id).
    return """
        CREATE TABLE governance_audit_log (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id TEXT NOT NULL UNIQUE,
            tenant_id TEXT NOT NULL,
            action TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            record_hash TEXT NOT NULL,
            data TEXT NOT NULL
        )
    """


def test_migration_from_old_single_column_unique(tmp_path):
    db = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db)
    conn.execute(_old_schema_ddl())
    # Seed a valid single-tenant chain the old way (one global chain == that
    # tenant's chain when only one tenant is present).
    prev = ""
    seeded = []
    for i in range(3):
        sealed = _seal_record(_rec("acme", target=f"t{i}", window=str(i)), prev)
        conn.execute(
            "INSERT INTO governance_audit_log (action_id, tenant_id, action, observed_at, record_hash, data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                sealed.action_id,
                sealed.tenant_id,
                sealed.action,
                sealed.observed_at,
                sealed.record_hash,
                json.dumps(asdict(sealed), sort_keys=True),
            ),
        )
        seeded.append(sealed.action_id)
        prev = sealed.record_hash
    conn.commit()
    conn.close()

    # Reopen with the new code — migration runs in _init_db.
    log = SQLiteGovernanceAuditLog(db)

    # No data loss.
    rows = log.list(tenant_id="acme")
    assert len(rows) == 3
    assert {r.action_id for r in rows} == set(seeded)
    # Legacy single-tenant chain still verifies clean.
    assert log.verify_chain()["tampered"] == 0

    # Schema is now the composite unique.
    sql = log._conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='governance_audit_log'"
    ).fetchone()[0]
    normalized = sql.replace(" ", "").lower()
    assert "unique(tenant_id,action_id)" in normalized

    # New appends chain onto the migrated head and stay verifiable.
    log.append(_rec("acme", target="t9", window="9"))
    assert len(log.list(tenant_id="acme")) == 4
    assert log.verify_chain()["tampered"] == 0

    # Migration is idempotent: reopening again is a no-op with no data loss.
    reopened = SQLiteGovernanceAuditLog(db)
    assert len(reopened.list(tenant_id="acme")) == 4
    assert reopened.verify_chain()["tampered"] == 0


def test_public_get_still_resolves_by_action_id(audit):
    rec = _rec("acme")
    audit.append(rec)
    fetched = audit.get(rec.action_id)
    assert fetched is not None
    assert fetched.tenant_id == "acme"
    assert audit.get("gov_does_not_exist") is None
