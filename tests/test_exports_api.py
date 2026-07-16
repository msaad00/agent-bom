"""API tests for the scheduled findings-export routes (#4040).

Verifies RBAC, connect-once secret handling (never echoed), tenant scoping, and
the destination -> schedule wiring over HTTP.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from agent_bom.api import connection_crypto
from agent_bom.api.export_destination_store import InMemoryExportDestinationStore, set_export_destination_store
from agent_bom.api.export_schedule_store import InMemoryExportScheduleStore, set_export_schedule_store

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
_TEST_KEY = Fernet.generate_key().decode("ascii")


def _headers(role: str = "admin", tenant: str = "tenant-alpha") -> dict[str, str]:
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
        connection_crypto.CONNECTIONS_KEY_ENV: os.environ.get(connection_crypto.CONNECTIONS_KEY_ENV),
        f"{connection_crypto.CONNECTIONS_KEY_ENV}_FILE": os.environ.get(f"{connection_crypto.CONNECTIONS_KEY_ENV}_FILE"),
        connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV: os.environ.get(connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV),
    }
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = _TEST_KEY
    os.environ.pop(f"{connection_crypto.CONNECTIONS_KEY_ENV}_FILE", None)
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV, None)
    connection_crypto.reset_key_cache()
    set_export_destination_store(InMemoryExportDestinationStore())
    set_export_schedule_store(InMemoryExportScheduleStore())
    try:
        yield
    finally:
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        connection_crypto.reset_key_cache()
        set_export_destination_store(None)
        set_export_schedule_store(None)


def _app() -> Any:
    from agent_bom.api.server import app

    return app


def test_requires_auth_and_rejects_viewer_mutation():
    client = TestClient(_app())
    assert client.get("/v1/exports/destinations").status_code == 401
    body = {"kind": "clickhouse", "display_name": "Lake", "config": {"url": "http://ch:8123"}, "secret": "tok"}
    assert client.post("/v1/exports/destinations", json=body, headers=_headers(role="viewer")).status_code == 403


def test_create_destination_never_echoes_secret_and_is_tenant_scoped():
    client = TestClient(_app())
    body = {"kind": "clickhouse", "display_name": "Lake", "config": {"url": "http://ch:8123"}, "secret": "super-secret-token"}
    resp = client.post("/v1/exports/destinations", json=body, headers=_headers())
    assert resp.status_code == 201
    data = resp.json()
    assert "super-secret-token" not in str(data)
    assert "secret_encrypted" not in data
    assert data["has_secret"] is True
    dest_id = data["id"]

    # Another tenant cannot see it.
    assert client.get(f"/v1/exports/destinations/{dest_id}", headers=_headers(tenant="tenant-beta")).status_code == 404
    assert client.get(f"/v1/exports/destinations/{dest_id}", headers=_headers()).status_code == 200


def test_create_destination_rejects_unsupported_kind():
    client = TestClient(_app())
    body = {"kind": "bigquery", "display_name": "BQ", "config": {}}
    resp = client.post("/v1/exports/destinations", json=body, headers=_headers())
    assert resp.status_code == 400


def test_schedule_requires_existing_destination_and_valid_cron():
    client = TestClient(_app())
    # Missing destination.
    bad = {"name": "n", "cron_expression": "0 3 * * *", "destination_id": "ghost"}
    assert client.post("/v1/exports/schedules", json=bad, headers=_headers()).status_code == 400

    dest = client.post(
        "/v1/exports/destinations",
        json={"kind": "s3", "display_name": "Bucket", "config": {"bucket": "b"}},
        headers=_headers(),
    ).json()
    # Invalid cron.
    bad_cron = {"name": "n", "cron_expression": "not-a-cron", "destination_id": dest["id"]}
    assert client.post("/v1/exports/schedules", json=bad_cron, headers=_headers()).status_code == 422

    good = {"name": "nightly", "cron_expression": "0 3 * * *", "destination_id": dest["id"], "since_days": 90}
    resp = client.post("/v1/exports/schedules", json=good, headers=_headers())
    assert resp.status_code == 201
    sched = resp.json()
    assert sched["destination_id"] == dest["id"]
    assert sched["next_run"]

    listed = client.get("/v1/exports/schedules", headers=_headers()).json()
    assert len(listed) == 1
    # Cross-tenant list is empty.
    assert client.get("/v1/exports/schedules", headers=_headers(tenant="tenant-beta")).json() == []
