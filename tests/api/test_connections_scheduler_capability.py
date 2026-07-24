"""Read-only connections_scheduler_enabled capability (health + connections meta)."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from agent_bom.api import connection_crypto
from agent_bom.api.connection_store import InMemoryConnectionStore, set_connection_store
from agent_bom.api.server import app, configure_api

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
_TEST_KEY = Fernet.generate_key().decode("ascii")


def _proxy_headers(role: str = "admin", tenant: str = "tenant-alpha") -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


@pytest.fixture(autouse=True)
def _env() -> Iterator[None]:
    prior = {
        "AGENT_BOM_TRUST_PROXY_AUTH": os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH"),
        "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH_SECRET"),
        "AGENT_BOM_CONNECTIONS_SCHEDULER": os.environ.get("AGENT_BOM_CONNECTIONS_SCHEDULER"),
        connection_crypto.CONNECTIONS_KEY_ENV: os.environ.get(connection_crypto.CONNECTIONS_KEY_ENV),
    }
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = _TEST_KEY
    os.environ.pop("AGENT_BOM_CONNECTIONS_SCHEDULER", None)
    connection_crypto.reset_key_cache()
    set_connection_store(InMemoryConnectionStore())
    configure_api(api_key=None)
    try:
        yield
    finally:
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        connection_crypto.reset_key_cache()
        set_connection_store(None)


def test_system_health_reports_scheduler_disabled_by_default() -> None:
    client = TestClient(app)
    resp = client.get("/v1/system/health", headers=_proxy_headers())
    assert resp.status_code == 200
    assert resp.json()["connections_scheduler_enabled"] is False


def test_system_health_reports_scheduler_enabled_when_flag_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_CONNECTIONS_SCHEDULER", "1")
    client = TestClient(app)
    resp = client.get("/v1/system/health", headers=_proxy_headers())
    assert resp.status_code == 200
    assert resp.json()["connections_scheduler_enabled"] is True


def test_connections_list_includes_scheduler_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_CONNECTIONS_SCHEDULER", "true")
    client = TestClient(app)
    resp = client.get("/v1/cloud/connections", headers=_proxy_headers(role="viewer"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["schema_version"] == "cloud.connections.v1"
    assert body["connections_scheduler_enabled"] is True


def test_public_health_omits_scheduler_capability() -> None:
    """Anonymous /health must not advertise operator scheduler posture."""
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert "connections_scheduler_enabled" not in resp.json()
