"""NHI lifecycle-enforcement sweeps: JIT cleanup, dormant deprovision, rotation,
quota data, and the hash-chained governance audit log.

These tests pin the cross-cutting acceptance criteria: determinism (injected
``now``, derived ids), idempotency (run-twice => identical end-state + no dup
audit rows), and fail-open error handling (a store that raises must not abort
the sweep).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
    cleanup_expired_grants,
    deny_jit_grant,
    deprovision_dormant_identities,
    flag_rotation_due_identities,
    issue_identity,
    issue_jit_grant,
    quota_state,
    request_jit_grant,
    run_nhi_lifecycle_cleanup,
    set_identity_quota,
)
from agent_bom.api.governance_audit_log import (
    InMemoryGovernanceAuditLog,
    derive_action_id,
    make_governance_audit_record,
)

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture()
def store():
    return InMemoryAgentIdentityStore()


@pytest.fixture()
def audit():
    return InMemoryGovernanceAuditLog()


def _issue(store, *, agent_id="agent-a", tenant="t1", ttl=3600, issued_at=None):
    identity, _ = issue_identity(store, agent_id=agent_id, tenant_id=tenant, ttl_seconds=ttl)
    if issued_at is not None:
        identity.issued_at = issued_at
        store.put(identity)
    return identity


# ── JIT-grant auto-cleanup ───────────────────────────────────────────────────


def test_expired_active_grant_revoked_with_audit(store, audit):
    grant = issue_jit_grant(store, identity_id="id1", agent_id="a", tenant_id="t1", tool_name="tool", ttl_seconds=60)
    later = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00")) + timedelta(minutes=5)

    counts = cleanup_expired_grants(store, now=later, audit_log=audit)

    assert counts["expired"] == 1
    refreshed = store.get_jit_grant(grant.grant_id)
    assert refreshed.status == "revoked"
    assert refreshed.revoked_reason == "expired"
    rows = audit.list()
    assert len(rows) == 1
    assert rows[0].action == "jit_grant_expired"
    assert rows[0].observed_at == later.isoformat()


def test_denied_grant_pruned(store, audit):
    g = request_jit_grant(store, identity_id="id1", agent_id="a", tenant_id="t1", tool_name="tool")
    deny_jit_grant(store, g.grant_id, reason="not approved")

    counts = cleanup_expired_grants(store, now=T0, audit_log=audit)

    assert counts["pruned"] == 1
    assert store.get_jit_grant(g.grant_id).status == "revoked"
    assert audit.list()[0].action == "jit_grant_denied_pruned"


def test_live_grant_untouched(store, audit):
    issue_jit_grant(store, identity_id="id1", agent_id="a", tenant_id="t1", tool_name="tool", ttl_seconds=86400)
    counts = cleanup_expired_grants(store, now=T0, audit_log=audit)
    assert counts == {"expired": 0, "pruned": 0, "errors": 0}
    assert audit.list() == []


def test_cleanup_grants_idempotent_no_duplicate_audit(store, audit):
    grant = issue_jit_grant(store, identity_id="id1", agent_id="a", tenant_id="t1", tool_name="tool", ttl_seconds=60)
    later = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00")) + timedelta(minutes=5)

    first = cleanup_expired_grants(store, now=later, audit_log=audit)
    snapshot = store.get_jit_grant(grant.grant_id)
    head_after_first = audit.head_hash()

    second = cleanup_expired_grants(store, now=later + timedelta(hours=1), audit_log=audit)

    assert first["expired"] == 1
    assert second["expired"] == 0  # already revoked => skipped
    assert len(audit.list()) == 1  # no duplicate audit row
    assert audit.head_hash() == head_after_first
    # End-state identical (no double transition).
    again = store.get_jit_grant(grant.grant_id)
    assert again.revoked_at == snapshot.revoked_at


# ── dormant auto-deprovision (opt-in) ────────────────────────────────────────


def test_dormant_disabled_by_default(store, audit):
    ident = _issue(store)
    ident.last_used_at = (T0 - timedelta(days=365)).isoformat()
    store.put(ident)
    counts = deprovision_dormant_identities(store, now=T0, audit_log=audit)
    assert counts["disabled"] == 1
    assert store.get(ident.identity_id, tenant_id="t1").status == "active"
    assert audit.list() == []


def test_dormant_revoked_when_opted_in(store, audit):
    ident = _issue(store)
    ident.last_used_at = (T0 - timedelta(days=120)).isoformat()
    store.put(ident)

    counts = deprovision_dormant_identities(store, now=T0, dormant_days=90, audit_log=audit)

    assert counts["revoked"] == 1
    refreshed = store.get(ident.identity_id, tenant_id="t1")
    assert refreshed.status == "revoked"
    assert refreshed.revoked_reason == "dormant_auto_revoke"
    assert audit.list()[0].action == "identity_dormant_auto_revoke"


def test_dormant_never_used_not_revoked(store, audit):
    ident = _issue(store)  # last_used_at == ""
    counts = deprovision_dormant_identities(store, now=T0, dormant_days=90, audit_log=audit)
    assert counts["revoked"] == 0
    assert store.get(ident.identity_id, tenant_id="t1").status == "active"


def test_dormant_recent_use_not_revoked(store, audit):
    ident = _issue(store)
    ident.last_used_at = (T0 - timedelta(days=10)).isoformat()
    store.put(ident)
    counts = deprovision_dormant_identities(store, now=T0, dormant_days=90, audit_log=audit)
    assert counts["revoked"] == 0


def test_dormant_idempotent(store, audit):
    ident = _issue(store)
    ident.last_used_at = (T0 - timedelta(days=120)).isoformat()
    store.put(ident)

    deprovision_dormant_identities(store, now=T0, dormant_days=90, audit_log=audit)
    deprovision_dormant_identities(store, now=T0 + timedelta(days=1), dormant_days=90, audit_log=audit)

    assert len(audit.list()) == 1  # revoked once, skipped on second sweep


# ── rotation-due flagging (advisory) ─────────────────────────────────────────


def test_rotation_due_flagged(store, audit):
    ident = _issue(store, issued_at=(T0 - timedelta(days=120)).isoformat())
    counts = flag_rotation_due_identities(store, now=T0, rotation_days=90, audit_log=audit)
    assert counts["flagged"] == 1
    refreshed = store.get(ident.identity_id, tenant_id="t1")
    assert refreshed.rotation_due is True
    assert refreshed.rotation_due_at == T0.isoformat()
    # Secret was NOT rotated: token hash unchanged.
    assert refreshed.token_hash == ident.token_hash
    assert audit.list()[0].action == "token_rotation_due"


def test_rotation_recent_not_flagged(store, audit):
    _issue(store, issued_at=(T0 - timedelta(days=10)).isoformat())
    counts = flag_rotation_due_identities(store, now=T0, rotation_days=90, audit_log=audit)
    assert counts["flagged"] == 0


def test_rotation_idempotent(store, audit):
    _issue(store, issued_at=(T0 - timedelta(days=120)).isoformat())
    flag_rotation_due_identities(store, now=T0, rotation_days=90, audit_log=audit)
    flag_rotation_due_identities(store, now=T0 + timedelta(days=1), rotation_days=90, audit_log=audit)
    assert len(audit.list()) == 1


# ── per-identity quota DATA ──────────────────────────────────────────────────


def test_quota_state_defaults_unenforced(store):
    ident = _issue(store)
    qs = quota_state(ident)
    assert qs["enforced"] is False
    assert qs["max_requests_per_window"] == 0


def test_set_and_read_quota(store):
    ident = _issue(store)
    set_identity_quota(store, ident.identity_id, tenant_id="t1", max_requests_per_window=100, window_seconds=60)
    qs = quota_state(store.get(ident.identity_id, tenant_id="t1"))
    assert qs["enforced"] is True
    assert qs["max_requests_per_window"] == 100
    assert qs["window_seconds"] == 60


# ── deterministic ids + hash chain ───────────────────────────────────────────


def test_action_id_deterministic():
    a = derive_action_id(tenant_id="t1", target_id="jit_1", action="jit_grant_expired", window_key="2026-01-01T00:00:00")
    b = derive_action_id(tenant_id="t1", target_id="jit_1", action="jit_grant_expired", window_key="2026-01-01T00:00:00")
    c = derive_action_id(tenant_id="t1", target_id="jit_1", action="jit_grant_expired", window_key="2026-02-01T00:00:00")
    # Same inputs but a different tenant derives a different id (no collision).
    d = derive_action_id(tenant_id="t2", target_id="jit_1", action="jit_grant_expired", window_key="2026-01-01T00:00:00")
    assert a == b
    assert a != c
    assert a != d
    assert a.startswith("gov_")


def test_audit_append_idempotent_and_chain_verifies(audit):
    rec = make_governance_audit_record(
        tenant_id="t1",
        actor="system",
        action="jit_grant_expired",
        target_type="jit_grant",
        target_id="jit_1",
        reason="expired",
        before_state="active",
        after_state="revoked",
        observed_at=T0.isoformat(),
        window_key="w1",
    )
    first = audit.append(rec)
    second = audit.append(rec)  # same action_id => no-op
    assert first.record_hash == second.record_hash
    assert len(audit.list()) == 1
    assert audit.verify_chain()["tampered"] == 0


def test_audit_chain_detects_tamper(audit):
    for i in range(3):
        audit.append(
            make_governance_audit_record(
                tenant_id="t1",
                actor="system",
                action="token_rotation_due",
                target_type="agent_identity",
                target_id=f"id_{i}",
                reason="age",
                before_state="rotation_current",
                after_state="rotation_due",
                observed_at=T0.isoformat(),
                window_key=str(i),
            )
        )
    # Tamper with a stored record's reason in place.
    victim = audit.list()[1]
    victim.reason = "mutated"
    result = audit.verify_chain()
    assert result["tampered"] >= 1


# ── combined sweep + error survival ──────────────────────────────────────────


def test_run_all_sweeps_idempotent(store, audit):
    grant = issue_jit_grant(store, identity_id="id1", agent_id="a", tenant_id="t1", tool_name="tool", ttl_seconds=60)
    later = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00")) + timedelta(days=300)
    # Dormant identity (will be revoked): last used long before `later`.
    dormant = _issue(store, agent_id="dormant", issued_at=(T0 - timedelta(days=200)).isoformat())
    dormant.last_used_at = (later - timedelta(days=200)).isoformat()
    store.put(dormant)
    # Old token but recently used (rotation-flagged, NOT revoked).
    aging = _issue(store, agent_id="aging", issued_at=(later - timedelta(days=200)).isoformat())
    aging.last_used_at = (later - timedelta(days=1)).isoformat()
    store.put(aging)

    first = run_nhi_lifecycle_cleanup(store, now=later, audit_log=audit, dormant_days=90, rotation_days=90)
    rows_after_first = len(audit.list())
    head_first = audit.head_hash()

    second = run_nhi_lifecycle_cleanup(store, now=later + timedelta(days=1), audit_log=audit, dormant_days=90, rotation_days=90)

    assert first["grants"]["expired"] == 1
    assert first["dormant"]["revoked"] == 1
    assert first["rotation"]["flagged"] == 1
    # Second run is a no-op: same audit head, no new rows, no double transition.
    assert len(audit.list()) == rows_after_first
    assert audit.head_hash() == head_first
    assert second["grants"]["expired"] == 0
    assert second["dormant"]["revoked"] == 0
    assert second["rotation"]["flagged"] == 0


class _RaisingStore(InMemoryAgentIdentityStore):
    def iter_all_jit_grants(self, *, limit=10000):
        raise RuntimeError("db unreachable")

    def iter_all_identities(self, *, limit=10000):
        raise RuntimeError("db unreachable")


def test_store_error_does_not_crash_sweep(caplog):
    bad = _RaisingStore()
    audit = InMemoryGovernanceAuditLog()
    # No exception escapes; each sweep records an error and the loop survives.
    result = run_nhi_lifecycle_cleanup(bad, now=T0, audit_log=audit, dormant_days=90, rotation_days=90)
    assert result["grants"]["errors"] == 1
    assert result["dormant"]["errors"] == 1
    assert result["rotation"]["errors"] == 1
    assert audit.list() == []


def test_audit_sink_error_does_not_crash_sweep(store):
    grant = issue_jit_grant(store, identity_id="id1", agent_id="a", tenant_id="t1", tool_name="tool", ttl_seconds=60)
    later = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00")) + timedelta(minutes=5)

    class _BadAudit:
        def append(self, record):
            raise RuntimeError("audit disk full")

    counts = cleanup_expired_grants(store, now=later, audit_log=_BadAudit())
    # Transition still happened; the audit failure was swallowed.
    assert counts["expired"] == 1
    assert store.get_jit_grant(grant.grant_id).status == "revoked"


# ── SQLite durability + idempotency across connections ───────────────────────


def test_sqlite_audit_durable_and_idempotent(tmp_path):
    from agent_bom.api.governance_audit_log import SQLiteGovernanceAuditLog

    db = str(tmp_path / "gov.db")
    log = SQLiteGovernanceAuditLog(db)
    rec = make_governance_audit_record(
        tenant_id="t1",
        actor="system",
        action="identity_dormant_auto_revoke",
        target_type="agent_identity",
        target_id="id_x",
        reason="dormant_auto_revoke",
        before_state="active",
        after_state="revoked",
        observed_at=T0.isoformat(),
        window_key=T0.isoformat(),
    )
    log.append(rec)
    log.append(rec)  # idempotent across same connection

    # Reopen (new instance / connection) — row survives, chain verifies.
    reopened = SQLiteGovernanceAuditLog(db)
    assert len(reopened.list()) == 1
    reopened.append(rec)  # idempotent across a fresh connection too
    assert len(reopened.list()) == 1
    assert reopened.verify_chain()["tampered"] == 0


# ── lifecycle posture surface ────────────────────────────────────────────────


def test_lifecycle_posture_reports_rotation_and_quota(store):
    from agent_bom.api.agent_identity_store import set_agent_identity_store
    from agent_bom.graph.nhi_governance import describe_nhi_lifecycle_posture

    aging = _issue(store, issued_at=(T0 - timedelta(days=200)).isoformat())
    flag_rotation_due_identities(store, now=T0, rotation_days=90)
    set_identity_quota(store, aging.identity_id, tenant_id="t1", max_requests_per_window=10, window_seconds=60)
    set_agent_identity_store(store)
    try:
        posture = describe_nhi_lifecycle_posture(now=T0)
    finally:
        set_agent_identity_store(None)

    assert posture["status"] == "attention_required"
    assert posture["rotation_due"] == 1
    assert posture["quota_covered"] == 1
    assert posture["dormant_deprovision_enabled"] is False
    assert posture["secret_values_included"] is False
