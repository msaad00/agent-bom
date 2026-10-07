"""HTTP tenant-context rejection happens before SQLite or PostgreSQL reads."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api.auth import KeyStore, create_api_key, get_key_store, set_key_store
from agent_bom.api.middleware import APIKeyMiddleware
from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.api.tenant_worker import run_tenant_bound
from agent_bom.rbac import Role


@pytest.fixture(params=["sqlite", "postgres"])
def job_store(request, tmp_path, monkeypatch):
    if request.param == "sqlite":
        from agent_bom.api.store import SQLiteJobStore

        monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
        yield SQLiteJobStore(str(tmp_path / "jobs.db"))
    else:
        if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
            pytest.skip("AGENT_BOM_POSTGRES_URL required for live backend parity")
        from agent_bom.api.postgres_job_store import PostgresJobStore

        yield PostgresJobStore()


@pytest.mark.parametrize("role", list(Role))
def test_invalid_verified_key_context_never_reads_default_tenant(job_store, role):
    job_id = uuid4().hex
    job = ScanJob(job_id=job_id, tenant_id="default", created_at="2026-09-27T00:00:00Z", request=ScanRequest())
    run_tenant_bound("default", job_store.put, job)
    reads = []

    async def read_job(request):
        tenant = require_request_tenant_id(request)
        reads.append(tenant)
        result = job_store.get(job_id, tenant_id=tenant)
        return JSONResponse({"tenant": result.tenant_id if result else None})

    keys = KeyStore()
    old_keys = get_key_store()
    set_key_store(keys)
    app = Starlette(routes=[Route("/v1/jobs/context-probe", read_job)])
    app.add_middleware(APIKeyMiddleware, api_key="")
    try:
        with TestClient(app) as client:
            for bad in (None, "", " \t "):
                raw, key = create_api_key("invalid-context", role, tenant_id="default")
                key.tenant_id = bad
                keys.add(key)
                response = client.get("/v1/jobs/context-probe", headers={"Authorization": f"Bearer {raw}"})
                assert response.status_code == 500
                assert response.json()["detail"] == "Authenticated tenant context is unavailable"
                assert response.json()["error"]["code"] == "INTERNAL_ERROR"
            assert reads == []
            for tenant, expected in (("default", "default"), (f"other-{uuid4().hex}", None)):
                raw, key = create_api_key("valid-context", role, tenant_id=tenant)
                keys.add(key)
                response = client.get("/v1/jobs/context-probe", headers={"Authorization": f"Bearer {raw}"})
                assert response.status_code == 200
                assert response.json() == {"tenant": expected}
            assert len(reads) == 2
    finally:
        set_key_store(old_keys)
        run_tenant_bound("default", job_store.delete, job_id, tenant_id="default")
