"""Managed-trial completion contracts.

These tests intentionally exercise the security boundaries directly: durable
worker revalidation, secret-minimal invitations, and the tenant lifecycle grace
period.  All identifiers and credentials are synthetic.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request


def test_managed_invitation_is_hashed_email_bound_single_use_and_48_hours() -> None:
    from agent_bom.api.managed_trial_invitation import (
        InMemoryManagedTrialInvitationStore,
        ManagedTrialInvitationError,
        issue_managed_trial_invitation,
    )

    now = datetime(2026, 7, 25, 4, 0, tzinfo=timezone.utc)
    store = InMemoryManagedTrialInvitationStore()
    issued = issue_managed_trial_invitation(
        store,
        email="  Developer@Example.COM ",
        tenant_id="trial-synthetic-001",
        team_name="Synthetic Trial",
        now=now,
    )

    assert issued.invitation.email == "developer@example.com"
    assert issued.invitation.expires_at == now + timedelta(hours=48)
    assert issued.raw_token not in repr(issued.invitation)
    accepted = store.accept_digest(
        issued.invitation.token_digest,
        verified_email="DEVELOPER@example.com",
        verified_subject="oidc|synthetic-subject",
        now=now + timedelta(minutes=5),
    )
    assert accepted.verified_subject == "oidc|synthetic-subject"
    with pytest.raises(ManagedTrialInvitationError, match="Invalid or expired"):
        store.accept_digest(
            issued.invitation.token_digest,
            verified_email="developer@example.com",
            verified_subject="oidc|synthetic-subject",
            now=now + timedelta(minutes=6),
        )


def test_tenant_lifecycle_expiry_revokes_immediately_and_cleans_after_grace() -> None:
    from agent_bom.api.tenant_lifecycle import (
        InMemoryTenantLifecycleStore,
        TenantLifecycleState,
        expire_due_tenants,
        run_due_tenant_cleanup,
    )

    now = datetime(2026, 7, 25, 4, 0, tzinfo=timezone.utc)
    store = InMemoryTenantLifecycleStore()
    store.create(
        tenant_id="trial-synthetic-001",
        trial_ends_at=now,
        cleanup_after=now + timedelta(days=7),
        now=now,
    )
    revoked: list[str] = []
    deleted: list[str] = []

    assert expire_due_tenants(store, now=now, revoke=revoked.append) == 1
    assert revoked == ["trial-synthetic-001"]
    assert store.get("trial-synthetic-001").state is TenantLifecycleState.EXPIRED
    assert run_due_tenant_cleanup(
        store,
        now=now + timedelta(days=6, hours=23),
        delete=deleted.append,
    ) == 0
    assert run_due_tenant_cleanup(
        store,
        now=now + timedelta(days=7),
        delete=deleted.append,
    ) == 1
    assert deleted == ["trial-synthetic-001"]
    assert store.get("trial-synthetic-001").state is TenantLifecycleState.DELETED
    # Cleanup is idempotent: a retry after success does not delete twice.
    assert run_due_tenant_cleanup(
        store,
        now=now + timedelta(days=8),
        delete=deleted.append,
    ) == 0


def test_durable_connection_worker_revalidates_stored_trial_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_bom.api import managed_trial
    from agent_bom.api.connection_store import (
        CloudConnectionRecord,
        InMemoryConnectionStore,
        set_connection_store,
    )
    from agent_bom.api.models import ScanJob, ScanRequest
    from agent_bom.api.routes import cloud_connections

    store = InMemoryConnectionStore()
    record = CloudConnectionRecord(
        id="connection-synthetic-001",
        tenant_id="trial-synthetic-001",
        provider="aws",
        display_name="Synthetic read-only",
        role_ref="arn:aws:iam::000000000000:role/SyntheticReadOnly",
        external_id_encrypted="synthetic-ciphertext",
        regions=["us-east-1"],
    )
    store.put(record)
    set_connection_store(store)
    job = ScanJob(
        job_id="job-synthetic-001",
        tenant_id=record.tenant_id,
        source_id=f"cloud-connection:{record.id}",
        triggered_by="synthetic-operator",
        created_at="2026-07-25T04:00:00+00:00",
        request=ScanRequest(),
    )
    calls: list[str] = []

    def _guard(stored: CloudConnectionRecord) -> None:
        calls.append(stored.id)
        raise RuntimeError("stored envelope rejected")

    monkeypatch.setattr(managed_trial, "enforce_stored_connection_envelope", _guard)
    monkeypatch.setattr(
        cloud_connections,
        "_run_connection_scan",
        lambda *_args, **_kwargs: pytest.fail("worker ran provider I/O before validation"),
    )

    with pytest.raises(RuntimeError, match="stored envelope rejected"):
        cloud_connections.execute_queued_connection_scan(job)
    assert calls == [record.id]


def test_operator_cleanup_cannot_delete_an_active_trial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_bom.api.routes import enterprise
    from agent_bom.api.tenant_lifecycle import InMemoryTenantLifecycleStore, set_tenant_lifecycle_store_for_tests

    now = datetime.now(timezone.utc)
    store = InMemoryTenantLifecycleStore()
    store.create(
        tenant_id="trial-synthetic-001",
        trial_ends_at=now + timedelta(days=14),
        cleanup_after=now + timedelta(days=21),
        now=now,
    )
    set_tenant_lifecycle_store_for_tests(store)
    deleted: list[str] = []
    monkeypatch.setattr("agent_bom.api.tenant_lifecycle.delete_tenant_records", deleted.append)
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": [], "query_string": b""})
    request.state.tenant_id = "default"
    request.state.api_key_name = "synthetic-operator"

    try:
        with pytest.raises(HTTPException) as rejected:
            asyncio.run(
                enterprise.retry_managed_trial_tenant_cleanup(
                    request,
                    "trial-synthetic-001",
                )
            )
        assert rejected.value.status_code == 409
        assert deleted == []
    finally:
        set_tenant_lifecycle_store_for_tests(None)


def test_postgres_cleanup_discovers_all_tenant_tables_but_retains_audit_tombstones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_bom.api.tenant_lifecycle import delete_tenant_records

    discovered = [
        ("cloud_connections",),
        ("runtime_sessions",),
        ("managed_trial_invitations",),
        ("governance_audit_log",),
        ("managed_trial_tenants",),
    ]
    deleted_queries: list[str] = []

    class _Connection:
        def execute(self, query: object, params: object = None) -> object:
            if isinstance(query, str) and "information_schema.columns" in query:
                return SimpleNamespace(fetchall=lambda: discovered)
            if isinstance(query, str) and query.startswith("DELETE FROM teams"):
                return SimpleNamespace(rowcount=1)
            deleted_queries.append(repr(query))
            return SimpleNamespace(rowcount=1)

        def commit(self) -> None:
            return None

    class _Pool:
        @contextmanager
        def connection(self):
            yield _Connection()

    monkeypatch.setattr("agent_bom.api.routes.privacy._delete_records", lambda tenant_id: {})
    monkeypatch.setattr("agent_bom.api.storage_schema.postgres_deployment_configured", lambda: True)
    monkeypatch.setattr("agent_bom.api.postgres_common._get_pool", lambda: _Pool())

    result = delete_tenant_records("trial-synthetic-001")

    rendered = "\n".join(deleted_queries)
    assert "cloud_connections" in rendered
    assert "runtime_sessions" in rendered
    assert "managed_trial_invitations" in rendered
    assert "governance_audit_log" not in rendered
    assert "managed_trial_tenants" not in rendered
    assert result == {"postgres_tenant_rows": 3, "tenant_root": 1}
