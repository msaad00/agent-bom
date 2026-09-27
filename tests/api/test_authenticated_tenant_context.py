"""Incomplete authenticated context must never turn into default-tenant access."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse

from agent_bom.api.middleware import APIKeyMiddleware
from agent_bom.api.postgres_common import _current_tenant, reset_current_tenant, set_current_tenant
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.api.tenant_worker import run_tenant_bound, submit_tenant_bound
from agent_bom.rbac import Role, require_authenticated_permission

_INVALID_TENANTS = [None, "", " \t ", 0, False, [], {}]


def _request(tenant):
    request = Request({"type": "http", "method": "GET", "path": "/v1/fleet", "headers": []})
    request.state.api_key_role = "admin"
    request.state.auth_method = "api_key"
    request.state.tenant_id = tenant
    return request


@pytest.mark.parametrize("tenant", _INVALID_TENANTS)
def test_request_tenant_rejects_non_string_or_blank_context(tenant):
    with pytest.raises(HTTPException) as exc:
        require_request_tenant_id(_request(tenant))
    assert exc.value.status_code == 500
    assert exc.value.detail == "Authenticated tenant context is unavailable"


@pytest.mark.parametrize("tenant", _INVALID_TENANTS)
@pytest.mark.asyncio
async def test_rbac_dependency_cannot_supply_default_for_authenticated_role(tenant):
    request = _request(tenant)
    check = require_authenticated_permission("fleet_write").dependency
    with pytest.raises(HTTPException) as exc:
        await check(request, x_role=None, x_tenant_id=None, x_proxy_secret=None)
    assert exc.value.status_code == 500
    assert request.state.tenant_id == tenant


@pytest.mark.asyncio
async def test_rbac_dependency_rejects_missing_tenant_attribute():
    request = _request("tenant-a")
    del request.state.tenant_id
    with pytest.raises(HTTPException) as exc:
        await require_authenticated_permission("read").dependency(request, x_role=None, x_tenant_id=None, x_proxy_secret=None)
    assert exc.value.status_code == 500
    assert not hasattr(request.state, "tenant_id")


@pytest.mark.parametrize("postgres", [False, True])
@pytest.mark.parametrize("tenant", _INVALID_TENANTS)
@pytest.mark.asyncio
async def test_middleware_rejects_bad_tenant_before_handler_or_database(monkeypatch, tenant, postgres):
    if postgres:
        monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://app@localhost/test")
    else:
        monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    next_handler = AsyncMock(return_value=JSONResponse({"unexpected": True}))
    token = set_current_tenant("outer")
    try:
        response = await APIKeyMiddleware._call_with_tenant_context(None, _request(tenant), next_handler)
        assert response.status_code == 500
        assert _current_tenant.get() == "outer"
        next_handler.assert_not_called()
    finally:
        reset_current_tenant(token)


@pytest.mark.parametrize("tenant", _INVALID_TENANTS)
def test_worker_rejects_missing_tenant_before_running_work(tenant):
    work = Mock()
    token = set_current_tenant("outer")
    try:
        with pytest.raises(ValueError, match="tenant"):
            run_tenant_bound(tenant, work)
        work.assert_not_called()
        assert _current_tenant.get() == "outer"
    finally:
        reset_current_tenant(token)


@pytest.mark.parametrize("tenant", _INVALID_TENANTS)
def test_submission_rejects_missing_tenant_before_queueing(tenant):
    executor = Mock()
    with pytest.raises(ValueError, match="tenant"):
        submit_tenant_bound(executor, tenant, Mock())
    executor.submit.assert_not_called()


@pytest.mark.parametrize("tenant,expected", [("default", "default"), (" tenant-a ", "tenant-a")])
@pytest.mark.asyncio
async def test_explicit_single_tenant_and_named_tenant_remain_valid(tenant, expected):
    request = _request(tenant)
    assert require_request_tenant_id(request) == expected
    role = await require_authenticated_permission("fleet_write").dependency(request, x_role=None, x_tenant_id=None, x_proxy_secret=None)
    assert role == Role.ADMIN
    token = set_current_tenant("outer")
    try:
        assert run_tenant_bound(tenant, _current_tenant.get) == expected
        assert _current_tenant.get() == "outer"
        with ThreadPoolExecutor(max_workers=1) as executor:
            assert submit_tenant_bound(executor, tenant, _current_tenant.get).result() == expected
            assert executor.submit(_current_tenant.get).result() == "default"
    finally:
        reset_current_tenant(token)


@pytest.mark.parametrize("raises", [False, True])
@pytest.mark.asyncio
async def test_middleware_restores_outer_context_after_handler(monkeypatch, raises):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://app@localhost/test")
    seen = []

    async def handler(request):
        seen.append(_current_tenant.get())
        if raises:
            raise RuntimeError("handler failed")
        return JSONResponse({"tenant": request.state.tenant_id})

    token = set_current_tenant("outer")
    try:
        if raises:
            with pytest.raises(RuntimeError, match="handler failed"):
                await APIKeyMiddleware._call_with_tenant_context(None, _request("tenant-a"), handler)
        else:
            assert (await APIKeyMiddleware._call_with_tenant_context(None, _request("tenant-a"), handler)).status_code == 200
        assert seen == ["tenant-a"]
        assert _current_tenant.get() == "outer"
    finally:
        reset_current_tenant(token)


@pytest.mark.asyncio
async def test_attested_proxy_rejects_blank_tenant(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "tenant-context-test-attestation")
    request = Request({"type": "http", "method": "GET", "path": "/v1/fleet", "headers": []})
    with pytest.raises(HTTPException) as exc:
        await require_authenticated_permission("read").dependency(
            request, x_role="admin", x_tenant_id=" \t ", x_proxy_secret="tenant-context-test-attestation"
        )
    assert exc.value.status_code == 401
    assert not hasattr(request.state, "tenant_id")


@pytest.mark.asyncio
async def test_middleware_rejects_absent_tenant_attribute():
    request = _request("tenant-a")
    del request.state.tenant_id
    next_handler = AsyncMock(return_value=JSONResponse({"unexpected": True}))
    response = await APIKeyMiddleware._call_with_tenant_context(None, request, next_handler)
    assert response.status_code == 500
    next_handler.assert_not_called()
