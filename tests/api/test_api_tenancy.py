from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from agent_bom.api.routes import credentials as credential_routes
from agent_bom.api.tenancy import require_request_tenant_id


def _request_with_state(**state: object) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(**state))


def test_require_request_tenant_id_uses_middleware_state() -> None:
    request = _request_with_state(tenant_id=" tenant-alpha ")

    assert require_request_tenant_id(request) == "tenant-alpha"  # type: ignore[arg-type]


def test_require_request_tenant_id_fails_closed_without_state() -> None:
    request = _request_with_state()

    with pytest.raises(HTTPException) as exc:
        require_request_tenant_id(request)  # type: ignore[arg-type]

    assert exc.value.status_code == 500
    assert exc.value.detail == "Authenticated tenant context is unavailable"


def test_route_tenant_helpers_do_not_invent_default_tenant() -> None:
    request = _request_with_state()

    with pytest.raises(HTTPException) as exc:
        credential_routes._tenant_id(request)  # type: ignore[arg-type]

    assert exc.value.status_code == 500
