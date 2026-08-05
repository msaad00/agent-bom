"""Managed-trial guardrails stay explicit, fail closed, and opt-in."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from starlette.testclient import TestClient

from agent_bom.api import managed_trial
from agent_bom.api.connection_scheduler import connections_scheduler_enabled
from agent_bom.api.connection_store import (
    SCAN_MODE_FULL,
    CloudConnectionRecord,
    InMemoryConnectionStore,
    get_connection_store,
    set_connection_store,
)
from agent_bom.api.middleware import APIKeyMiddleware, RateLimitMiddleware
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.routes import cloud_connections
from agent_bom.api.routes.cloud_connections import CloudConnectionCreate
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store, _get_tenant_quota_store, set_job_store, set_tenant_quota_store
from agent_bom.api.tenant_quota import (
    consume_managed_trial_scan_credit,
    current_managed_trial_scan_credits,
    effective_tenant_quotas,
    get_tenant_quota_runtime,
    reset_managed_trial_scan_credit_store,
    set_tenant_quota_overrides,
)
from agent_bom.api.tenant_quota_store import InMemoryTenantQuotaStore


@pytest.fixture(autouse=True)
def _isolated_stores(monkeypatch: pytest.MonkeyPatch):
    original_connection_store = get_connection_store()
    original_job_store = _get_store()
    original_quota_store = _get_tenant_quota_store()
    monkeypatch.setenv("AGENT_BOM_MANAGED_TRIAL_MODE", "1")
    set_connection_store(InMemoryConnectionStore())
    set_job_store(InMemoryJobStore())
    set_tenant_quota_store(InMemoryTenantQuotaStore())
    reset_managed_trial_scan_credit_store()
    monkeypatch.setattr(cloud_connections, "connections_key_configured", lambda: True)
    monkeypatch.setattr(cloud_connections, "encrypt_secret", lambda value: f"encrypted:{value}")
    monkeypatch.setattr(cloud_connections, "log_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(cloud_connections, "_tenant", lambda request: "tenant-trial")
    monkeypatch.setattr(cloud_connections, "_actor", lambda request: "trial-user")
    try:
        yield
    finally:
        reset_managed_trial_scan_credit_store()
        set_connection_store(original_connection_store)
        set_job_store(original_job_store)
        set_tenant_quota_store(original_quota_store)


def _body(**updates: object) -> CloudConnectionCreate:
    payload: dict[str, object] = {
        "provider": "aws",
        "display_name": "sandbox",
        "role_ref": "arn:aws:iam::000000000000:role/agent-bom-readonly",
        "external_id": "write-only-secret",
        "regions": ["us-east-1"],
    }
    payload.update(updates)
    return CloudConnectionCreate.model_validate(payload)


def _stored_connection(**updates: object) -> CloudConnectionRecord:
    payload: dict[str, object] = {
        "id": "connection-stale",
        "tenant_id": "tenant-trial",
        "provider": "aws",
        "display_name": "stale connection",
        "role_ref": "arn:aws:iam::000000000000:role/agent-bom-readonly",
        "external_id_encrypted": "encrypted:synthetic",
        "regions": ["us-east-1"],
        "inventory_scope": "account",
        "scan_mode": SCAN_MODE_FULL,
        "scan_interval_minutes": None,
        "auto_scan_on_create": False,
    }
    payload.update(updates)
    record = CloudConnectionRecord(**payload)  # type: ignore[arg-type]
    get_connection_store().put(record)
    return record


def test_managed_trial_defaults_are_bounded() -> None:
    quotas = effective_tenant_quotas("tenant-trial")

    assert quotas["active_scan_jobs"] == 1
    assert quotas["retained_scan_jobs"] == 20
    assert quotas["cloud_connections"] == 2
    assert quotas["cloud_connections_per_provider"] == 2
    assert quotas["scan_credits_24h"] == 8


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/auth/me"),
        ("POST", "/v1/auth/session"),
        ("DELETE", "/v1/auth/session"),
        ("GET", "/v1/auth/oidc/login"),
        ("GET", "/v1/auth/oidc/callback"),
        ("GET", "/v1/auth/trial-tenants/trial-example-123"),
        ("POST", "/v1/auth/trial-tenants/trial-example-123/suspend"),
        ("POST", "/v1/auth/trial-tenants/trial-example-123/cleanup/retry"),
        ("GET", "/v1/cloud/connections"),
        ("POST", "/v1/cloud/connections"),
        ("GET", "/v1/cloud/connections/connection-one"),
        ("POST", "/v1/cloud/connections/connection-one/test"),
        ("POST", "/v1/cloud/connections/connection-one/scan"),
        ("GET", "/v1/findings"),
        ("GET", "/v1/graph/node/node-one"),
        ("POST", "/v1/graph/query"),
    ],
)
def test_managed_trial_route_allowlist_is_explicit(method: str, path: str) -> None:
    assert managed_trial.managed_trial_route_allowed(method, path) is True


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/auth/keys"),
        ("POST", "/v1/scan"),
        ("PATCH", "/v1/cloud/connections/connection-one"),
        ("DELETE", "/v1/cloud/connections/connection-one"),
        ("POST", "/v1/cloud/connections/events/ingest"),
        ("POST", "/v1/findings/bulk"),
        ("POST", "/v1/graph/presets"),
        ("GET", "/v1/schedules"),
        ("POST", "/scim/v2/Users"),
    ],
)
def test_managed_trial_route_policy_defaults_to_deny(method: str, path: str) -> None:
    assert managed_trial.managed_trial_route_allowed(method, path) is False


def test_managed_trial_route_denial_precedes_every_principal_resolver() -> None:
    app = FastAPI()

    @app.get("/v1/auth/keys")
    async def _forbidden_surface() -> dict[str, bool]:
        return {"reached": True}

    app.add_middleware(APIKeyMiddleware, api_key="")
    client = TestClient(app)

    attempts = (
        {"headers": {"x-api-key": "synthetic-api-key"}},
        {"headers": {"authorization": "Bearer synthetic.oidc.token"}},
        {"headers": {"cookie": "agent_bom_session=synthetic-browser-session"}},
    )
    for attempt in attempts:
        response = client.get("/v1/auth/keys", **attempt)
        assert response.status_code == 403
        assert response.json() == {"detail": "This API route is disabled in managed trial mode."}


def test_managed_trial_disables_connection_scheduler_even_when_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_CONNECTIONS_SCHEDULER", "1")
    assert connections_scheduler_enabled() is False


@pytest.mark.parametrize(
    "updates,detail",
    [
        ({"provider": "azure"}, "AWS"),
        ({"provider": "database"}, "AWS"),
        ({"inventory_scope": "organization"}, "account"),
        ({"scan_mode": "continuous"}, "continuous"),
        ({"scan_interval_minutes": 60}, "schedules"),
        ({"regions": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2"]}, "5"),
        ({"regions": ["all"]}, "explicit"),
    ],
)
def test_managed_trial_rejects_out_of_envelope_connection(updates: dict[str, object], detail: str) -> None:
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(cloud_connections.create_connection(request=object(), body=_body(**updates)))

    assert exc_info.value.status_code == 403
    assert detail.lower() in str(exc_info.value.detail).lower()


def test_managed_trial_forces_manual_scan_and_atomically_caps_connections() -> None:
    first = asyncio.run(cloud_connections.create_connection(request=object(), body=_body(display_name="one")))
    second = asyncio.run(cloud_connections.create_connection(request=object(), body=_body(display_name="two")))

    assert first["auto_scan_on_create"] is False
    assert second["auto_scan_on_create"] is False
    assert first["last_scan_id"] is None

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(cloud_connections.create_connection(request=object(), body=_body(display_name="three")))
    assert exc_info.value.status_code == 429
    assert "cloud_connections" in str(exc_info.value.detail)


def test_connection_mutations_use_write_bucket_and_narrow_scopes() -> None:
    assert RateLimitMiddleware._is_write_rate_limited("/v1/cloud/connections", "POST") is True
    assert RateLimitMiddleware._is_write_rate_limited("/v1/cloud/connections/abc/test", "POST") is True
    assert RateLimitMiddleware._is_write_rate_limited("/v1/cloud/connections/abc/scan", "POST") is True

    middleware = APIKeyMiddleware(app=lambda *_args: None, api_key="")
    assert middleware._required_scope("GET", "/v1/cloud/connections") == "cloud.connection:read"
    assert middleware._required_scope("POST", "/v1/cloud/connections") == "cloud.connection:write"
    assert middleware._required_scope("GET", "/v1/findings") == "finding:read"
    assert middleware._required_scope("GET", "/v1/graph") == "graph:read"


def test_managed_trial_scan_credits_are_atomic_and_do_not_charge_denials() -> None:
    def _consume() -> int:
        try:
            consume_managed_trial_scan_credit("tenant-trial")
        except HTTPException as exc:
            return exc.status_code
        return 200

    with ThreadPoolExecutor(max_workers=10) as executor:
        statuses = list(executor.map(lambda _index: _consume(), range(10)))

    assert statuses.count(200) == 8
    assert statuses.count(429) == 2
    assert current_managed_trial_scan_credits("tenant-trial") == 8


def test_concurrent_idempotent_connection_scan_reserves_one_job_and_one_credit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_bom.api.idempotency_store import InMemoryIdempotencyStore
    from agent_bom.api.routes import scan as scan_routes
    from agent_bom.api.stores import set_idempotency_store

    record = _stored_connection(id="connection-idempotent")
    set_idempotency_store(InMemoryIdempotencyStore())
    monkeypatch.setattr(scan_routes, "dispatch_scan_job", lambda job: None)

    def _scan() -> str:
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": f"/v1/cloud/connections/{record.id}/scan",
                "headers": [(b"idempotency-key", b"same-request")],
                "query_string": b"",
            }
        )
        accepted = asyncio.run(cloud_connections.scan_connection(request, record.id))
        return accepted.job_id

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            job_ids = list(executor.map(lambda _index: _scan(), range(2)))
        assert job_ids[0] == job_ids[1]
        assert len(_get_store().list_all("tenant-trial")) == 1
        assert current_managed_trial_scan_credits("tenant-trial") == 1
    finally:
        set_idempotency_store(None)


def test_managed_trial_runtime_reports_the_same_clamped_quotas_as_enforcement() -> None:
    set_tenant_quota_overrides(
        "tenant-trial",
        {
            "active_scan_jobs": 9,
            "retained_scan_jobs": 200,
            "cloud_connections": 99,
            "cloud_connections_per_provider": 50,
            "scan_credits_24h": 100,
        },
    )

    effective = effective_tenant_quotas("tenant-trial")
    runtime = get_tenant_quota_runtime("tenant-trial")

    for quota_name, enforced_limit in effective.items():
        assert runtime["usage"][quota_name]["limit"] == enforced_limit  # type: ignore[index]


@pytest.mark.parametrize(
    "updates",
    [
        {"provider": "database", "regions": []},
        {"inventory_scope": "organization"},
        {"regions": []},
        {"regions": ["ALL"]},
        {"regions": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2"]},
    ],
)
def test_connection_test_and_scan_revalidate_stale_trial_records_before_execution(
    monkeypatch: pytest.MonkeyPatch,
    updates: dict[str, object],
) -> None:
    record = _stored_connection(**updates)
    broker_calls: list[str] = []
    scan_calls: list[str] = []
    monkeypatch.setattr(cloud_connections, "_test_connection_broker", lambda _record: broker_calls.append("test"))
    monkeypatch.setattr(
        cloud_connections,
        "_run_connection_scan",
        lambda _record, _tenant_id: scan_calls.append("scan"),
    )

    with pytest.raises(HTTPException) as test_exc:
        asyncio.run(cloud_connections.test_connection(request=object(), connection_id=record.id))
    with pytest.raises(HTTPException) as scan_exc:
        asyncio.run(cloud_connections.scan_connection(request=object(), connection_id=record.id))

    assert test_exc.value.status_code == 403
    assert scan_exc.value.status_code == 403
    assert broker_calls == []
    assert scan_calls == []
    assert current_managed_trial_scan_credits("tenant-trial") == 0


def test_worker_time_validator_rejects_stale_trial_connection() -> None:
    record = _stored_connection(inventory_scope="organization")

    with pytest.raises(HTTPException) as exc_info:
        managed_trial.enforce_stored_connection_envelope(record)

    assert exc_info.value.status_code == 403
    assert "account scope" in str(exc_info.value.detail)


def test_self_hosted_provider_quota_is_configurable_without_trial_restrictions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_MANAGED_TRIAL_MODE", raising=False)
    set_tenant_quota_overrides(
        "tenant-trial",
        {"cloud_connections": 10, "cloud_connections_per_provider": 2},
    )

    for name in ("aws-one", "aws-two"):
        created = asyncio.run(
            cloud_connections.create_connection(request=object(), body=_body(display_name=name, auto_scan_on_create=False))
        )
        assert created["provider"] == "aws"

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(cloud_connections.create_connection(request=object(), body=_body(display_name="aws-three", auto_scan_on_create=False)))
    assert exc_info.value.status_code == 429
    assert "cloud_connections_per_provider" in str(exc_info.value.detail)

    azure = asyncio.run(
        cloud_connections.create_connection(
            request=object(),
            body=_body(provider="azure", display_name="azure-one", regions=[], auto_scan_on_create=False),
        )
    )
    assert azure["provider"] == "azure"


def test_connection_scan_reservation_enforces_active_and_retained_job_quotas() -> None:
    store = InMemoryJobStore()
    set_job_store(store)
    pending = ScanJob(
        job_id="existing-active",
        tenant_id="tenant-trial",
        status=JobStatus.PENDING,
        created_at="2026-07-24T00:00:00+00:00",
        request=ScanRequest(),
    )
    store.put(pending)

    record = _stored_connection(id="connection-one")
    with pytest.raises(HTTPException) as exc_info:
        cloud_connections.queue_connection_scan_record(record, actor="trial-user")

    assert exc_info.value.status_code == 429
    assert "concurrent scan jobs" in str(exc_info.value.detail).lower()
    assert current_managed_trial_scan_credits("tenant-trial") == 0

    retained_store = InMemoryJobStore()
    set_job_store(retained_store)
    for index in range(20):
        retained_store.put(
            ScanJob(
                job_id=f"retained-{index}",
                tenant_id="tenant-trial",
                status=JobStatus.DONE,
                created_at="2026-07-24T00:00:00+00:00",
                completed_at="2026-07-24T00:01:00+00:00",
                request=ScanRequest(),
            )
        )

    with pytest.raises(HTTPException) as retained_exc:
        cloud_connections.queue_connection_scan_record(record, actor="trial-user")

    assert retained_exc.value.status_code == 429
    assert "retained_scan_jobs" in str(retained_exc.value.detail)
    assert current_managed_trial_scan_credits("tenant-trial") == 0
