"""Contract tests for POST /v1/cloud/connections/events/ingest (event-collector Phase 2)."""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from agent_bom.api import connection_crypto
from agent_bom.api.connection_store import (
    CloudConnectionRecord,
    InMemoryConnectionStore,
    set_connection_store,
)
from agent_bom.api.server import app, configure_api
from agent_bom.cloud.event_ingest import CloudChangeEvent

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
_TEST_KEY = Fernet.generate_key().decode("ascii")
_ACCOUNT = "123456789012"
_TENANT = "tenant-alpha"


def _proxy_headers(role: str = "admin", tenant: str = _TENANT) -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


def _event(**overrides: Any) -> dict[str, Any]:
    body = {
        "provider": "aws",
        "account": _ACCOUNT,
        "region": "us-east-1",
        "resource_type": "s3",
        "resource_id": "my-bucket",
        "action": "PutBucketPolicy",
        "arn": "",
        "raw": {},
    }
    body.update(overrides)
    return body


@pytest.fixture(autouse=True)
def _env() -> Iterator[None]:
    prior = {
        "AGENT_BOM_TRUST_PROXY_AUTH": os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH"),
        "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH_SECRET"),
        connection_crypto.CONNECTIONS_KEY_ENV: os.environ.get(connection_crypto.CONNECTIONS_KEY_ENV),
    }
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = _TEST_KEY
    connection_crypto.reset_key_cache()
    store = InMemoryConnectionStore()
    store.put(
        CloudConnectionRecord(
            id="conn-1",
            tenant_id=_TENANT,
            provider="aws",
            display_name="prod",
            role_ref=f"arn:aws:iam::{_ACCOUNT}:role/agent-bom-readonly",
            external_id_encrypted="cipher",
            regions=["us-east-1"],
            scan_mode="continuous",
        )
    )
    set_connection_store(store)
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


def test_ingest_requires_auth() -> None:
    prior = os.environ.pop("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", None)
    try:
        configure_api(api_key=None)
        client = TestClient(app)
        resp = client.post("/v1/cloud/connections/events/ingest", json={"events": [_event()]})
        assert resp.status_code == 401
    finally:
        if prior is not None:
            os.environ["AGENT_BOM_ALLOW_UNAUTHENTICATED_API"] = prior
        configure_api(api_key=None)


def test_ingest_rejects_viewer() -> None:
    client = TestClient(app)
    resp = client.post(
        "/v1/cloud/connections/events/ingest",
        headers=_proxy_headers(role="viewer"),
        json={"events": [_event()]},
    )
    assert resp.status_code == 403


def test_ingest_dispatches_matching_connection() -> None:
    client = TestClient(app)
    dispatched: list[CloudChangeEvent] = []

    def _fake_dispatch(event: CloudChangeEvent, record: CloudConnectionRecord, **kwargs: Any) -> dict[str, Any]:
        dispatched.append(event)
        assert record.id == "conn-1"
        assert kwargs.get("tenant_id") == _TENANT
        return {"connection_id": record.id, "resource_type": event.resource_type, "action": event.action}

    with patch(
        "agent_bom.api.routes.cloud_connections.dispatch_change_event",
        side_effect=_fake_dispatch,
    ):
        resp = client.post(
            "/v1/cloud/connections/events/ingest",
            headers=_proxy_headers(role="admin"),
            json={"events": [_event()]},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["schema_version"] == "cloud.connections.events.ingest.v1"
    assert body["accepted"] == 1
    assert body["dispatched"] == 1
    assert body["skipped"] == 0
    assert len(dispatched) == 1
    assert dispatched[0].account == _ACCOUNT
    assert dispatched[0].resource_id == "my-bucket"


def test_ingest_skips_unmatched_account_fail_closed() -> None:
    client = TestClient(app)
    with patch(
        "agent_bom.api.routes.cloud_connections.dispatch_change_event",
        side_effect=AssertionError("must not dispatch"),
    ) as mock_dispatch:
        resp = client.post(
            "/v1/cloud/connections/events/ingest",
            headers=_proxy_headers(),
            json={"events": [_event(account="999999999999")]},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["accepted"] == 1
    assert body["dispatched"] == 0
    assert body["skipped"] == 1
    mock_dispatch.assert_not_called()


def test_ingest_sanitizes_dispatch_failures() -> None:
    client = TestClient(app)

    def _boom(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("secret=arn:aws:iam::123:role/leak password=hunter2")

    with patch("agent_bom.api.routes.cloud_connections.dispatch_change_event", side_effect=_boom):
        resp = client.post(
            "/v1/cloud/connections/events/ingest",
            headers=_proxy_headers(),
            json={"events": [_event()]},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["dispatched"] == 0
    assert body["skipped"] == 1
    detail = body["results"][0]["detail"]
    assert "hunter2" not in detail
    assert "password=" not in detail.lower() or "hunter2" not in detail


def test_ingest_rejects_empty_events() -> None:
    client = TestClient(app)
    resp = client.post(
        "/v1/cloud/connections/events/ingest",
        headers=_proxy_headers(),
        json={"events": []},
    )
    assert resp.status_code == 422
