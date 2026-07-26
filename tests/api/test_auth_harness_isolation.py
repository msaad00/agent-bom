"""Regression coverage for per-test API auth middleware isolation."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import app

_PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"


@pytest.fixture(autouse=True)
def _auth_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Declare this module's final auth posture after shared fixture setup."""
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", _PROXY_SECRET)
    yield


def test_module_auth_fixture_is_applied_before_request_dispatch() -> None:
    """Late fixture env must rebuild the cached middleware configuration."""
    client = TestClient(app)

    assert client.get("/v1/overview").status_code == 401
    response = client.get(
        "/v1/overview",
        headers={
            "X-Agent-Bom-Role": "viewer",
            "X-Agent-Bom-Tenant-ID": "tenant-alpha",
            "X-Agent-Bom-Proxy-Secret": _PROXY_SECRET,
        },
    )
    assert response.status_code == 200
