"""API-key scope ceilings must not be bypassed by session metadata."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from agent_bom.api.auth import Role, create_api_key
from agent_bom.api.models import CreateKeyRequest
from agent_bom.api.routes import enterprise


@pytest.mark.parametrize("marker", ["saml-session", "browser-session", "oidc-session"])
def test_session_markers_are_not_scope_wildcards(marker: str) -> None:
    _, key = create_api_key(name="operator-key", role=Role.ANALYST, scopes=[marker])
    assert key.has_scope("scan:write") is False
    assert key.has_scope("privacy.data:delete") is False


@pytest.mark.parametrize("marker", ["saml-session", "browser-session", "oidc-session"])
def test_operator_key_request_rejects_reserved_session_markers(marker: str) -> None:
    with pytest.raises(ValidationError, match="reserved session marker"):
        CreateKeyRequest(name="operator-key", role="analyst", scopes=[marker])


def _request(*, role: str = "admin", scopes: list[str] | None = None):
    return SimpleNamespace(
        state=SimpleNamespace(
            tenant_id="default",
            api_key_name="parent",
            api_key_role=role,
            api_key_scopes=list(scopes or []),
        )
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("child_scopes", [[], ["privacy.data:delete"], ["*"]])
async def test_scoped_caller_cannot_delegate_unrestricted_or_broader_key(child_scopes: list[str]) -> None:
    with pytest.raises(HTTPException) as exc:
        await enterprise.create_key(
            _request(scopes=["auth.keys:write"]),
            CreateKeyRequest(name="child", role="viewer", scopes=child_scopes),
        )
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_scoped_caller_can_delegate_equal_or_narrower_scope() -> None:
    result = await enterprise.create_key(
        _request(scopes=["auth.*"]),
        CreateKeyRequest(name="child-narrow", role="viewer", scopes=["auth.keys:write"]),
    )
    assert result["role"] == "viewer"


@pytest.mark.asyncio
async def test_caller_cannot_delegate_higher_role() -> None:
    with pytest.raises(HTTPException) as exc:
        await enterprise.create_key(
            _request(role="analyst"),
            CreateKeyRequest(name="child-admin", role="admin"),
        )
    assert exc.value.status_code == 403
