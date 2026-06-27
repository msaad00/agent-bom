"""Tests for the per-tenant cloud connections plane (Phase A).

Covers the store (CRUD + tenant isolation), at-rest encryption (ciphertext in
the DB column, decrypt round-trip, missing-key refuses to persist), the CRUD API
(RBAC, no-secret responses, tenant scoping), and the credential broker (AWS
AssumeRole with the decrypted ExternalId; non-AWS providers raise the planned
error).
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from agent_bom.api import connection_crypto
from agent_bom.api.connection_store import (
    STATUS_PENDING,
    CloudConnectionRecord,
    InMemoryConnectionStore,
    SQLiteConnectionStore,
    set_connection_store,
)

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
_TEST_KEY = Fernet.generate_key().decode("ascii")


def _proxy_headers(role: str = "admin", tenant: str = "tenant-alpha") -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


@pytest.fixture(autouse=True)
def _connection_env() -> Iterator[None]:
    """Configure trusted-proxy auth + an encryption key, isolated per test."""
    prior = {
        "AGENT_BOM_TRUST_PROXY_AUTH": os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH"),
        "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH_SECRET"),
        connection_crypto.CONNECTIONS_KEY_ENV: os.environ.get(connection_crypto.CONNECTIONS_KEY_ENV),
    }
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = _TEST_KEY
    set_connection_store(InMemoryConnectionStore())
    try:
        yield
    finally:
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        set_connection_store(None)


def _record(tenant_id: str, *, provider: str = "aws") -> CloudConnectionRecord:
    return CloudConnectionRecord(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        provider=provider,
        display_name="prod-readonly",
        role_ref="arn:aws:iam::123456789012:role/agent-bom-readonly",
        external_id_encrypted=connection_crypto.encrypt_secret("super-secret-external-id"),
        regions=["us-east-1"],
        status=STATUS_PENDING,
        created_at="2026-06-26T00:00:00+00:00",
        updated_at="2026-06-26T00:00:00+00:00",
    )


# --------------------------------------------------------------------------- #
# Store: CRUD + tenant isolation
# --------------------------------------------------------------------------- #


def test_store_crud_round_trip() -> None:
    store = InMemoryConnectionStore()
    record = _record("tenant-a")
    store.put(record)

    fetched = store.get("tenant-a", record.id)
    assert fetched is not None
    assert fetched.display_name == "prod-readonly"
    assert [r.id for r in store.list_for_tenant("tenant-a")] == [record.id]

    assert store.delete("tenant-a", record.id) is True
    assert store.get("tenant-a", record.id) is None
    assert store.list_for_tenant("tenant-a") == []


def test_store_tenant_isolation() -> None:
    store = InMemoryConnectionStore()
    a = _record("tenant-a")
    b = _record("tenant-b")
    store.put(a)
    store.put(b)

    # Tenant A cannot read tenant B's connection by id, nor see it in its list.
    assert store.get("tenant-a", b.id) is None
    assert [r.id for r in store.list_for_tenant("tenant-a")] == [a.id]
    # Cross-tenant delete is a no-op.
    assert store.delete("tenant-a", b.id) is False
    assert store.get("tenant-b", b.id) is not None


def test_sqlite_store_crud_and_isolation(tmp_path: Any) -> None:
    db_path = str(tmp_path / "connections.db")
    store = SQLiteConnectionStore(db_path)
    a = _record("tenant-a")
    b = _record("tenant-b")
    store.put(a)
    store.put(b)

    assert store.get("tenant-a", a.id) is not None
    assert store.get("tenant-a", b.id) is None
    assert [r.id for r in store.list_for_tenant("tenant-b")] == [b.id]
    assert store.delete("tenant-b", b.id) is True
    assert store.get("tenant-b", b.id) is None


# --------------------------------------------------------------------------- #
# Encryption: ciphertext at rest, round-trip, missing-key refusal
# --------------------------------------------------------------------------- #


def test_db_column_holds_ciphertext_not_plaintext(tmp_path: Any) -> None:
    db_path = str(tmp_path / "connections.db")
    store = SQLiteConnectionStore(db_path)
    record = _record("tenant-a")
    store.put(record)

    raw = sqlite3.connect(db_path).execute("SELECT external_id_encrypted FROM cloud_connections WHERE id = ?", (record.id,)).fetchone()
    stored = raw[0]
    assert "super-secret-external-id" not in stored
    assert stored == record.external_id_encrypted
    # And it decrypts back to the plaintext.
    assert connection_crypto.decrypt_secret(stored) == "super-secret-external-id"


def test_encrypt_decrypt_round_trip() -> None:
    token = connection_crypto.encrypt_secret("value-123")
    assert token != "value-123"
    assert connection_crypto.decrypt_secret(token) == "value-123"


def test_missing_key_refuses_to_encrypt() -> None:
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_ENV, None)
    assert connection_crypto.connections_key_configured() is False
    with pytest.raises(connection_crypto.ConnectionSecretError):
        connection_crypto.encrypt_secret("would-be-plaintext")


def test_invalid_key_raises_clear_error() -> None:
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = "not-a-valid-fernet-key"
    with pytest.raises(connection_crypto.ConnectionSecretError):
        connection_crypto.encrypt_secret("x")


# --------------------------------------------------------------------------- #
# API: RBAC, no-secret responses, tenant scoping
# --------------------------------------------------------------------------- #


def _app() -> Any:
    # Trusted-proxy auth + tenant are resolved per request by the middleware, so
    # the module-level app singleton is sufficient (matches the cloud parity tests).
    from agent_bom.api.server import app

    return app


def _create_body() -> dict[str, Any]:
    return {
        "provider": "aws",
        "display_name": "prod-readonly",
        "role_ref": "arn:aws:iam::123456789012:role/agent-bom-readonly",
        "external_id": "super-secret-external-id",
        "regions": ["us-east-1"],
    }


def test_api_requires_authentication() -> None:
    client = TestClient(_app())
    assert client.get("/v1/cloud/connections").status_code == 401
    assert client.post("/v1/cloud/connections", json=_create_body()).status_code == 401


def test_api_rejects_underprivileged_role() -> None:
    client = TestClient(_app())
    resp = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers(role="viewer"))
    assert resp.status_code == 403


def test_api_create_response_never_contains_secret() -> None:
    client = TestClient(_app())
    resp = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers())
    assert resp.status_code == 201
    body = resp.json()
    flat = str(body)
    assert "super-secret-external-id" not in flat
    assert "external_id" not in body
    assert "external_id_encrypted" not in body
    assert body["has_external_id"] is True
    assert body["provider"] == "aws"
    assert body["status"] == STATUS_PENDING


def test_api_list_get_delete_tenant_scoped() -> None:
    client = TestClient(_app())
    created = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers(tenant="tenant-alpha")).json()
    cid = created["id"]

    # Same tenant can read it; another tenant cannot.
    assert client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).status_code == 200
    assert client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-beta")).status_code == 404

    listing = client.get("/v1/cloud/connections", headers=_proxy_headers(tenant="tenant-beta")).json()
    assert listing["connections"] == []

    # Cross-tenant delete is a 404; same-tenant delete works.
    assert client.delete(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-beta")).status_code == 404
    assert client.delete(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).status_code == 204
    assert client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).status_code == 404


def test_api_unsupported_provider_400() -> None:
    client = TestClient(_app())
    body = _create_body()
    body["provider"] = "digitalocean"
    resp = client.post("/v1/cloud/connections", json=body, headers=_proxy_headers())
    assert resp.status_code == 400


def test_api_missing_key_fails_closed_503() -> None:
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_ENV, None)
    client = TestClient(_app())
    resp = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers())
    assert resp.status_code == 503
    # And nothing was persisted.
    listing = client.get("/v1/cloud/connections", headers=_proxy_headers()).json()
    assert listing["connections"] == []


# --------------------------------------------------------------------------- #
# Broker: AWS AssumeRole with the decrypted ExternalId; non-AWS planned
# --------------------------------------------------------------------------- #


def test_broker_aws_assume_role_uses_decrypted_external_id(monkeypatch: pytest.MonkeyPatch) -> None:
    boto3 = pytest.importorskip("boto3")
    from agent_bom.cloud import connection_broker

    captured: dict[str, Any] = {}

    class _FakeSTS:
        def assume_role(self, **kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {
                "Credentials": {
                    "AccessKeyId": "ASIA-TEST",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                }
            }

    sessions: dict[str, Any] = {}

    def _fake_client(service: str, *args: Any, **kwargs: Any) -> Any:
        assert service == "sts"
        return _FakeSTS()

    def _fake_session(**kwargs: Any) -> Any:
        sessions.update(kwargs)
        return object()

    monkeypatch.setattr(boto3, "client", _fake_client)
    monkeypatch.setattr(boto3, "Session", _fake_session)

    record = _record("tenant-a")
    connection_broker.broker_session(record)

    assert captured["RoleArn"] == record.role_ref
    assert captured["ExternalId"] == "super-secret-external-id"
    assert sessions["aws_access_key_id"] == "ASIA-TEST"
    assert sessions["aws_session_token"] == "token"
    assert sessions["region_name"] == "us-east-1"


def test_broker_non_aws_provider_planned_error() -> None:
    from agent_bom.cloud import connection_broker

    for provider in ("azure", "gcp", "snowflake"):
        record = _record("tenant-a", provider=provider)
        with pytest.raises(NotImplementedError):
            connection_broker.broker_session(record)


def test_broker_unknown_provider_value_error() -> None:
    from agent_bom.cloud import connection_broker

    record = _record("tenant-a", provider="bogus")
    with pytest.raises(ValueError):
        connection_broker.broker_session(record)


def test_broker_secret_failure_does_not_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("boto3")
    from agent_bom.cloud import connection_broker

    record = _record("tenant-a")
    # Corrupt the ciphertext so decryption fails; error must not contain plaintext.
    record.external_id_encrypted = "garbage-token"
    with pytest.raises(connection_broker.ConnectionBrokerError) as exc:
        connection_broker.broker_session(record)
    assert "super-secret-external-id" not in str(exc.value)


# --------------------------------------------------------------------------- #
# Phase B: launch a read-only scan from a stored connection via the broker
# --------------------------------------------------------------------------- #


_BROKER_SESSION_SENTINEL = object()


def _install_scan_mocks(monkeypatch: pytest.MonkeyPatch, *, fail: bool = False) -> dict[str, Any]:
    """Patch the broker + AWS inventory/CIS the scan route reuses.

    Captures the session each discovery call receives so a test can assert the
    brokered session (not the local default chain) is what runs the scan.
    """
    from agent_bom.cloud import aws_cis_benchmark, aws_inventory, connection_broker

    calls: dict[str, Any] = {}

    def _fake_broker(record: CloudConnectionRecord, **kwargs: Any) -> Any:
        calls["broker_record_id"] = record.id
        if fail:
            raise connection_broker.ConnectionBrokerError(f"AssumeRole failed for connection {record.id}.")
        return _BROKER_SESSION_SENTINEL

    def _fake_inventory(region: str | None = None, force: bool = False, session: Any = None, **kwargs: Any) -> dict[str, Any]:
        calls["inventory_session"] = session
        calls["inventory_force"] = force
        return {
            "provider": "aws",
            "status": "ok",
            "account_id": "123456789012",
            "region": region or "us-east-1",
            "buckets": [],
            "instances": [],
            "security_groups": [],
            "roles": [],
            "users": [],
            "warnings": [],
        }

    class _FakeCISReport:
        def to_dict(self) -> dict[str, Any]:
            return {
                "benchmark": "CIS AWS Foundations",
                "benchmark_version": "3.0.0",
                "account_id": "123456789012",
                "region": "us-east-1",
                "pass_rate": 50.0,
                "passed": 1,
                "failed": 1,
                "total": 2,
                "checks": [],
            }

    def _fake_cis(region: str | None = None, session: Any = None, **kwargs: Any) -> Any:
        calls["cis_session"] = session
        return _FakeCISReport()

    monkeypatch.setattr(connection_broker, "broker_session", _fake_broker)
    monkeypatch.setattr(aws_inventory, "discover_inventory", _fake_inventory)
    monkeypatch.setattr(aws_cis_benchmark, "run_benchmark", _fake_cis)
    return calls


def _seed_connection(tenant: str = "tenant-alpha", *, provider: str = "aws") -> str:
    """Create a connection through the API and return its id."""
    client = TestClient(_app())
    body = _create_body()
    body["provider"] = provider
    created = client.post("/v1/cloud/connections", json=body, headers=_proxy_headers(tenant=tenant)).json()
    return str(created["id"])


def test_scan_launch_brokers_runs_persists_and_marks_active(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_scan_mocks(monkeypatch)
    client = TestClient(_app())
    cid = _seed_connection("tenant-alpha")

    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(tenant="tenant-alpha"))
    assert resp.status_code == 200
    body = resp.json()

    # The broker was used and the brokered session (not the default chain) ran both scans.
    assert calls["broker_record_id"] == cid
    assert calls["inventory_session"] is _BROKER_SESSION_SENTINEL
    assert calls["cis_session"] is _BROKER_SESSION_SENTINEL
    assert calls["inventory_force"] is True

    assert body["provider"] == "aws"
    scan_id = body["scan_id"]
    assert scan_id
    assert body["cis_benchmark"]["total"] == 2
    assert body["inventory"]["status"] == "ok"

    # Results persisted through the existing scan store (no parallel path).
    from agent_bom.api.stores import _get_store

    job = _get_store().get(scan_id, "tenant-alpha")
    assert job is not None
    assert job.result is not None
    assert job.result.get("cloud_inventory", {}).get("provider") == "aws"
    assert job.result.get("cis_benchmark", {}).get("total") == 2

    # Connection status flipped to active with last_scan_at set, no error detail.
    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == "active"
    assert fetched["last_scan_at"]
    assert fetched["status_detail"] == ""
    # No secret anywhere in the response surface.
    assert "super-secret-external-id" not in str(body)


def test_scan_failure_marks_error_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_scan_mocks(monkeypatch, fail=True)
    client = TestClient(_app())
    cid = _seed_connection("tenant-alpha")

    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(tenant="tenant-alpha"))
    assert resp.status_code == 502
    assert "super-secret-external-id" not in str(resp.json())

    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == "error"
    assert fetched["status_detail"]
    assert "super-secret-external-id" not in fetched["status_detail"]
    assert fetched["last_scan_at"] is None


def test_scan_requires_scan_permission(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_scan_mocks(monkeypatch)
    cid = _seed_connection("tenant-alpha")
    client = TestClient(_app())
    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(role="viewer", tenant="tenant-alpha"))
    assert resp.status_code == 403


def test_scan_is_tenant_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_scan_mocks(monkeypatch)
    cid = _seed_connection("tenant-alpha")
    client = TestClient(_app())
    # Another tenant cannot scan (or even resolve) this connection.
    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(tenant="tenant-beta"))
    assert resp.status_code == 404


def test_scan_missing_connection_404(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_scan_mocks(monkeypatch)
    client = TestClient(_app())
    resp = client.post(f"/v1/cloud/connections/{uuid.uuid4()}/scan", headers=_proxy_headers(tenant="tenant-alpha"))
    assert resp.status_code == 404


@pytest.mark.parametrize("provider", ["azure", "gcp", "snowflake"])
def test_scan_non_aws_provider_returns_planned(provider: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_scan_mocks(monkeypatch)
    cid = _seed_connection("tenant-alpha", provider=provider)
    client = TestClient(_app())
    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(tenant="tenant-alpha"))
    assert resp.status_code == 501
    assert "planned" in resp.json()["detail"].lower()
    # The connection was not touched (still pending, no scan).
    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == STATUS_PENDING


def test_summarize_inventory_payload_redacts_raw_warnings() -> None:
    """Inventory summary must not echo exception-derived warnings (py/stack-trace-exposure)."""
    from agent_bom.mcp_tools.posture import _summarize_inventory_payload

    payload = {
        "status": "ok",
        "account_id": "030225640638",
        "warnings": [
            "Could not list roles: Traceback (most recent call last): RuntimeError boom",
            "AccessDenied: arn:aws:iam::...:user/x — assume failed: <stack>",
        ],
    }
    summary = _summarize_inventory_payload("aws", payload)
    warnings = summary["warnings"]
    assert warnings == ["2 provider discovery warning(s) — see server logs for detail."]
    blob = " ".join(warnings)
    assert "Traceback" not in blob and "AccessDenied" not in blob and "arn:aws:iam" not in blob
