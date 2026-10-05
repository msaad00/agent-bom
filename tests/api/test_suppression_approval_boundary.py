"""Every suppressing entry needs separate authenticated approval and bounded scope."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.exception_store import ExceptionStatus, InMemoryExceptionStore, VulnException
from agent_bom.api.server import app, configure_api

FUTURE = "2099-01-01T00:00:00+00:00"


@pytest.fixture
def ctx(monkeypatch):
    old_keys = get_key_store()
    old_exceptions = stores._get_exception_store()
    keys = KeyStore()
    exceptions = InMemoryExceptionStore()
    set_key_store(keys)
    stores.set_exception_store(exceptions)
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    raw_admin, admin = create_api_key(name="admin", role=Role.ADMIN, scopes=["*"], tenant_id="tenant-a")
    raw_analyst, analyst = create_api_key(name="analyst", role=Role.ANALYST, scopes=["*"], tenant_id="tenant-a")
    keys.add(admin)
    keys.add(analyst)
    configure_api(api_key=None, allow_unauthenticated=False)
    try:
        yield SimpleNamespace(client=TestClient(app), store=exceptions, admin={"X-API-Key": raw_admin}, analyst={"X-API-Key": raw_analyst})
    finally:
        set_key_store(old_keys)
        stores.set_exception_store(old_exceptions)
        configure_api(api_key=None)


@pytest.mark.parametrize(
    "path,body",
    [
        ("exceptions", {"vuln_id": "CVE-2024-1", "package_name": "demo", "expires_at": FUTURE}),
        ("findings/feedback", {"vulnerability_id": "CVE-2024-1", "package": "demo", "state": "accepted_risk", "expires_at": FUTURE}),
        ("findings/false-positive", {"vulnerability_id": "CVE-2024-1", "package": "demo"}),
        (
            "findings/triage",
            {
                "vulnerability_id": "CVE-2024-1",
                "package": "demo",
                "decision": "not_affected",
                "justification": "vulnerable_code_not_present",
                "expires_at": FUTURE,
            },
        ),
    ],
)
def test_request_never_activates_a_suppression(ctx, path, body):
    response = ctx.client.post("/v1/" + path, json=body, headers=ctx.admin if path == "findings/triage" else ctx.analyst)
    assert response.status_code == 201, response.text
    entries = ctx.store.list_all(tenant_id="tenant-a")
    assert len(entries) == 1 and entries[0].status is ExceptionStatus.PENDING
    assert ctx.store.find_matching("CVE-2024-1", "demo", tenant_id="tenant-a") is None
    assert response.json().get("status") != "suppressed"
    assert not response.json().get("vex_eligible", False)


@pytest.mark.parametrize("expiry", ["", "not-a-date", "2099-01-01T00:00:00", "2020-01-01T00:00:00Z"])
def test_approval_refuses_missing_malformed_naive_or_expired_expiry(ctx, expiry):
    exc = VulnException(vuln_id="CVE-2024-1", package_name="demo", expires_at=expiry, tenant_id="tenant-a")
    ctx.store.put(exc, tenant_id="tenant-a")
    response = ctx.client.put(f"/v1/exceptions/{exc.exception_id}/approve", headers=ctx.admin)
    assert response.status_code == 400, response.text
    assert ctx.store.get(exc.exception_id, tenant_id="tenant-a").status is ExceptionStatus.PENDING


@pytest.mark.parametrize("vuln,package", [("*", "demo"), ("CVE-2024-1", "*"), ("", "demo"), ("CVE-2024-1", "")])
def test_approval_refuses_non_exact_finding_package_scope(ctx, vuln, package):
    exc = VulnException(vuln_id=vuln, package_name=package, expires_at=FUTURE, tenant_id="tenant-a")
    ctx.store.put(exc, tenant_id="tenant-a")
    response = ctx.client.put(f"/v1/exceptions/{exc.exception_id}/approve", headers=ctx.admin)
    assert response.status_code == 400
    assert ctx.store.get(exc.exception_id, tenant_id="tenant-a").status is ExceptionStatus.PENDING


def test_separate_admin_approval_is_required_and_activates_only_exact_scope(ctx):
    response = ctx.client.post(
        "/v1/exceptions", json={"vuln_id": "CVE-2024-1", "package_name": "demo", "expires_at": FUTURE}, headers=ctx.analyst
    )
    exception_id = response.json()["exception_id"]
    path = f"/v1/exceptions/{exception_id}/approve"
    assert ctx.client.put(path, headers=ctx.analyst).status_code == 403
    assert ctx.client.put(path, headers=ctx.admin).status_code == 200
    assert ctx.store.find_matching("CVE-2024-1", "demo", tenant_id="tenant-a") is not None
    assert ctx.store.find_matching("CVE-2024-2", "demo", tenant_id="tenant-a") is None
    assert ctx.store.find_matching("CVE-2024-1", "other", tenant_id="tenant-a") is None


def test_legacy_autoactivated_row_never_suppresses_after_upgrade():
    exc = VulnException(
        vuln_id="CVE-2024-1",
        package_name="demo",
        status=ExceptionStatus.ACTIVE,
        approved_by="analyst",
        approved_at="2026-01-01T00:00:00Z",
        expires_at=FUTURE,
    )
    assert not exc.matches("CVE-2024-1", "demo")


def test_timezone_offset_is_compared_as_an_instant():
    expires = datetime.now(timezone.utc) - timedelta(minutes=1)
    rendered = expires.astimezone(timezone(timedelta(hours=12))).isoformat()
    exc = VulnException(vuln_id="CVE-2024-1", package_name="demo", status=ExceptionStatus.ACTIVE, expires_at=rendered)
    assert exc.is_expired()


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_approval_survives_restart_with_exact_scope_and_expiry(tmp_path, backend):
    from agent_bom.api.exception_store import SQLiteExceptionStore
    from agent_bom.api.suppression_approval import activate_suppression

    path = str(tmp_path / "exceptions.sqlite")
    store = SQLiteExceptionStore(path) if backend == "sqlite" else InMemoryExceptionStore()
    exc = VulnException(vuln_id="CVE-2024-1", package_name="demo", tenant_id="tenant-a", expires_at=FUTURE)
    activate_suppression(exc, actor="admin")
    store.put(exc, tenant_id="tenant-a")
    restored = SQLiteExceptionStore(path) if backend == "sqlite" else store
    assert restored.find_matching("CVE-2024-1", "demo", tenant_id="tenant-a").approval_version == 1
    assert restored.find_matching("CVE-2024-1", "demo", tenant_id="tenant-b") is None
    expired = restored.get(exc.exception_id, tenant_id="tenant-a")
    expired.expires_at = "2020-01-01T00:00:00Z"
    restored.put(expired, tenant_id="tenant-a")
    assert restored.find_matching("CVE-2024-1", "demo", tenant_id="tenant-a") is None
    assert restored.get(exc.exception_id, tenant_id="tenant-a") is not None


def test_existing_sqlite_rows_require_reapproval_without_history_loss(tmp_path):
    import sqlite3

    from agent_bom.api.exception_store import SQLiteExceptionStore

    path = str(tmp_path / "old.sqlite")
    store = SQLiteExceptionStore(path)
    legacy = VulnException(
        vuln_id="CVE-2024-1", package_name="demo", status=ExceptionStatus.ACTIVE, approved_by="analyst", expires_at=FUTURE
    )
    store.put(legacy, tenant_id="default")
    # Reproduce the pre-upgrade table shape; migration must restore the column
    # conservatively instead of treating the historical active flag as approval.
    with sqlite3.connect(path) as conn:
        conn.execute("ALTER TABLE exceptions DROP COLUMN approval_version")
    upgraded = SQLiteExceptionStore(path)
    assert upgraded.get(legacy.exception_id, tenant_id="default").approved_by == "analyst"
    assert upgraded.find_matching("CVE-2024-1", "demo", tenant_id="default") is None


def test_approval_can_supply_expiry_for_a_pending_false_positive(ctx):
    response = ctx.client.post(
        "/v1/findings/false-positive", json={"vulnerability_id": "CVE-2024-1", "package": "demo"}, headers=ctx.analyst
    )
    path = "/v1/exceptions/" + response.json()["id"] + "/approve"
    assert ctx.client.put(path, json={"expires_at": FUTURE}, headers=ctx.admin).status_code == 200
    assert ctx.store.find_matching("CVE-2024-1", "demo", tenant_id="tenant-a")


@pytest.mark.skipif(not __import__("os").environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires isolated live Postgres")
def test_live_postgres_approval_persistence_rls_and_failed_write():
    from uuid import uuid4

    from agent_bom.api import postgres_common
    from agent_bom.api.postgres_access import PostgresExceptionStore
    from agent_bom.api.suppression_approval import activate_suppression

    postgres_common.reset_pool()
    tenant = "approval-" + uuid4().hex
    token = postgres_common.set_current_tenant(tenant)
    try:
        store = PostgresExceptionStore()
        with store._pool.connection() as conn:
            assert conn.execute("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone() == (False, False)
        with postgres_common._tenant_connection(store._pool) as conn:
            conn.execute("INSERT INTO teams (team_id,name,slug) VALUES (%s,%s,%s)", (tenant, tenant, tenant))
            conn.commit()
        exc = VulnException(vuln_id="CVE-2024-1", package_name="demo", tenant_id=tenant, expires_at=FUTURE)
        store.put(exc, tenant_id=tenant)
        assert store.find_matching(exc.vuln_id, exc.package_name, tenant_id=tenant) is None
        activate_suppression(exc, actor="admin")
        store.put(exc, tenant_id=tenant)
        postgres_common.reset_pool()
        restored = PostgresExceptionStore()
        assert restored.find_matching(exc.vuln_id, exc.package_name, tenant_id=tenant).approval_version == 1
        assert restored.list_all(tenant_id="other") == []
        with pytest.raises(ValueError):
            restored.put(exc, tenant_id="other")
        assert restored.get(exc.exception_id, tenant_id=tenant).approval_version == 1
        with restored._pool.connection() as conn:
            conn.execute("SELECT set_config('app.tenant_id','other',true)")
            assert conn.execute("SELECT count(*) FROM exceptions WHERE exception_id=%s", (exc.exception_id,)).fetchone()[0] == 0
    finally:
        postgres_common.reset_pool()
        postgres_common.reset_current_tenant(token)


def test_current_finding_does_not_trust_historical_suppression(ctx):
    from agent_bom.api.models import ScanJob
    from agent_bom.api.routes.scan import _iter_scan_findings

    job = ScanJob(
        job_id="historical",
        tenant_id="tenant-a",
        created_at="2026-10-05T00:00:00Z",
        request={},
        result={
            "findings": [
                {
                    "id": "CVE-2024-1:demo",
                    "vulnerability_id": "CVE-2024-1",
                    "package": "demo",
                    "severity": "critical",
                    "suppressed": True,
                    "suppression_id": "unapproved",
                    "risk_score": 0.0,
                    "unsuppressed_risk_score": 9.8,
                    "actionable": False,
                }
            ]
        },
    )
    row = _iter_scan_findings(job)[0]
    assert row["suppressed"] is False
    assert row["actionable"] is True
    assert row["risk_score"] == 9.8
    assert job.result["findings"][0]["suppressed"] is True  # preserve original receipt


def test_approval_audit_failure_leaves_request_pending(ctx, monkeypatch):
    from agent_bom.api import audit_log

    exc = VulnException(vuln_id="CVE-2024-1", package_name="demo", tenant_id="tenant-a", expires_at=FUTURE)
    ctx.store.put(exc, tenant_id="tenant-a")

    def unavailable(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(audit_log, "log_action", unavailable)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.put(f"/v1/exceptions/{exc.exception_id}/approve", headers=ctx.admin)
    assert response.status_code == 503
    assert ctx.store.get(exc.exception_id, tenant_id="tenant-a").status is ExceptionStatus.PENDING


def test_failed_approval_write_retains_pending_record_and_authorization_receipt(ctx, monkeypatch):
    from agent_bom.api import audit_log

    exc = VulnException(vuln_id="CVE-2024-1", package_name="demo", tenant_id="tenant-a", expires_at=FUTURE)
    ctx.store.put(exc, tenant_id="tenant-a")
    receipts = []
    monkeypatch.setattr(audit_log, "log_action", lambda action, **details: receipts.append((action, details)))

    def unavailable(*args, **kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(ctx.store, "put", unavailable)
    response = ctx.client.put(f"/v1/exceptions/{exc.exception_id}/approve", headers=ctx.admin)
    assert response.status_code == 503
    assert ctx.store.get(exc.exception_id, tenant_id="tenant-a").status is ExceptionStatus.PENDING
    assert receipts[0][0] == "exception.approval_authorized"
    assert receipts[0][1]["actor"] == "admin"
