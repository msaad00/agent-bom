"""A tenant passed to an audit read must be the tenant that is read.

``PostgresAuditLog`` filters by Postgres RLS, which reads the tenant from a
``ContextVar`` bound on the connection. Four methods in the class bind that
context from their ``tenant_id`` argument; six others accept the same argument
and never bind it, so the row filter comes from whatever the calling thread
happened to have set.

The visible consequence is a **false tamper report**. ``verify_integrity``
compares the rows it can see against a signed checkpoint. Called from a thread
with no ambient tenant -- a background job, a worker pool, an admin route that
resolved the tenant from a path parameter rather than the request context -- it
sees zero rows, compares that to a checkpoint counting N, and reports the audit
log as tampered. The chain itself is intact; only the read was mis-scoped.

That is the worst failure mode available to this subsystem: an integrity check
that cries wolf teaches operators to ignore it.
"""

from __future__ import annotations

import os
import threading
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="requires a live Postgres (AGENT_BOM_POSTGRES_URL)",
)


def _fresh_store_and_tenant():
    from agent_bom.api import postgres_audit as pa

    return pa.PostgresAuditLog(), f"t-{uuid.uuid4().hex[:12]}"


def _append_entries(store, tenant: str, count: int) -> None:
    """Append as the tenant, then leave the calling thread unbound again."""
    from agent_bom.api import postgres_audit as pa
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant)
    try:
        for index in range(count):
            store.append(
                pa.AuditEntry(
                    action="scan",
                    actor="probe",
                    resource=f"pkg-{index}",
                    details={"tenant_id": tenant},
                )
            )
    finally:
        reset_current_tenant(token)


def test_verify_integrity_does_not_report_a_clean_log_as_tampered() -> None:
    """The regression: called without an ambient tenant, it saw nothing and blamed the log."""
    store, tenant = _fresh_store_and_tenant()
    _append_entries(store, tenant, 8)

    # No ambient tenant here -- the argument is the only tenant on offer.
    verified, tampered = store.verify_integrity(tenant_id=tenant)

    assert tampered == 0, f"clean audit log reported {tampered} tampered rows"
    assert verified == 8, f"expected to verify 8 rows, saw {verified}"


def test_reads_scoped_by_argument_see_the_rows() -> None:
    """``list_entries`` and ``count`` must honour the tenant they are handed."""
    store, tenant = _fresh_store_and_tenant()
    _append_entries(store, tenant, 5)

    assert store.count(tenant_id=tenant) == 5
    assert len(store.list_entries(limit=100, tenant_id=tenant)) == 5


def test_the_argument_wins_over_a_conflicting_ambient_tenant() -> None:
    """Binding must not merely default -- an explicit argument overrides context.

    Without this, the fix could be satisfied by falling back to the ambient
    tenant, which would read the wrong tenant's rows rather than none of them.
    """
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    store, tenant_a = _fresh_store_and_tenant()
    _, tenant_b = _fresh_store_and_tenant()
    _append_entries(store, tenant_a, 3)
    _append_entries(store, tenant_b, 7)

    token = set_current_tenant(tenant_b)
    try:
        assert store.count(tenant_id=tenant_a) == 3
        assert len(store.list_entries(limit=100, tenant_id=tenant_a)) == 3
        verified, tampered = store.verify_integrity(tenant_id=tenant_a)
        assert (verified, tampered) == (3, 0)
    finally:
        reset_current_tenant(token)


def test_verify_integrity_is_clean_after_concurrent_appends() -> None:
    """Concurrency was the suspected cause; it is not. Pin that it stays fine."""
    import sys

    from agent_bom.api import postgres_audit as pa
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    store, tenant = _fresh_store_and_tenant()

    def worker(index: int) -> None:
        token = set_current_tenant(tenant)
        try:
            store.append(pa.AuditEntry(action="scan", actor="probe", resource=f"pkg-{index}", details={"tenant_id": tenant}))
        finally:
            reset_current_tenant(token)

    original = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        sys.setswitchinterval(original)

    verified, tampered = store.verify_integrity(tenant_id=tenant)
    assert (verified, tampered) == (8, 0)
