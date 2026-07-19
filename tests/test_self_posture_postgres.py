"""Real-Postgres reconciliation for the self-posture audit-chain integrity check.

Opt-in (``AGENT_BOM_POSTGRES_URL`` → the NOSUPERUSER ``agent_bom_app`` role).
Proves the tenant-scoped governance audit-chain integrity surfaced by
``self_posture(audit_chain=...)`` reconciles to the *real* Postgres store's
``verify_chain`` — and stays tenant-isolated — not just an in-memory fake.
"""

from __future__ import annotations

import os
import uuid

import pytest

from agent_bom.self_posture import self_posture

pg_only = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="AGENT_BOM_POSTGRES_URL (agent_bom_app role) is required for real Postgres tests",
)


@pytest.fixture(autouse=True)
def _reset_postgres_pool():
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        yield
        return
    from agent_bom.api import postgres_common

    postgres_common.reset_pool()
    yield
    pool = postgres_common._pool
    if pool is not None:
        pool.close()
    postgres_common.reset_pool()


def _seed(store, tenant_id: str, target_id: str) -> None:
    from agent_bom.api.governance_audit_log import (
        ACTION_IDENTITY_DORMANT_REVOKE,
        make_governance_audit_record,
    )

    store.append(
        make_governance_audit_record(
            tenant_id=tenant_id,
            actor="cleanup-loop",
            action=ACTION_IDENTITY_DORMANT_REVOKE,
            target_type="agent_identity",
            target_id=target_id,
            reason="dormant beyond retention",
            before_state="active",
            after_state="revoked",
            observed_at="2026-07-18T00:00:00Z",
            window_key="2026-07-18T00:00:00Z",
        )
    )


@pg_only
def test_self_posture_reconciles_to_real_postgres_chain_and_is_tenant_isolated() -> None:
    from agent_bom.api.postgres_governance_audit import PostgresGovernanceAuditLog

    store = PostgresGovernanceAuditLog()
    tenant_a = f"selfposture-a-{uuid.uuid4().hex[:12]}"
    tenant_b = f"selfposture-b-{uuid.uuid4().hex[:12]}"

    _seed(store, tenant_a, "agent-1")
    _seed(store, tenant_a, "agent-2")

    chain_a = store.verify_chain(tenant_id=tenant_a)
    assert chain_a["checked"] == 2 and chain_a["tampered"] == 0

    report_a = self_posture(audit_chain=chain_a)
    check_a = {c["id"]: c for c in report_a["checks"]}["governance.audit_chain_integrity"]  # type: ignore[union-attr]
    assert check_a["status"] == "pass"

    # A tenant with no recorded actions must read as unknown, never as healthy,
    # and never inherit tenant A's chain (real RLS-scoped verify).
    chain_b = store.verify_chain(tenant_id=tenant_b)
    assert chain_b["checked"] == 0
    report_b = self_posture(audit_chain=chain_b)
    check_b = {c["id"]: c for c in report_b["checks"]}["governance.audit_chain_integrity"]  # type: ignore[union-attr]
    assert check_b["status"] == "unknown"
