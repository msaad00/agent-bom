"""Per-connection org inventory fan-out for Connections scans.

StackSet / "Whole organization" onboarding is grant-only until the connection
stores ``inventory_scope=organization``; the scan path then fans out across
member accounts without requiring ``AGENT_BOM_AWS_ORG_INVENTORY``.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from agent_bom.api import connection_crypto
from agent_bom.api.connection_store import (
    STATUS_ACTIVE,
    CloudConnectionRecord,
    InMemoryConnectionStore,
    connection_org_fanout_enabled,
    set_connection_store,
)
from agent_bom.api.routes import cloud_connections as routes
from agent_bom.cloud import aws_inventory, aws_organizations

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
_TEST_KEY = Fernet.generate_key().decode("ascii")


@pytest.fixture(autouse=True)
def _connection_env() -> Iterator[None]:
    prior = {
        "AGENT_BOM_TRUST_PROXY_AUTH": os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH"),
        "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH_SECRET"),
        connection_crypto.CONNECTIONS_KEY_ENV: os.environ.get(connection_crypto.CONNECTIONS_KEY_ENV),
    }
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = _TEST_KEY
    connection_crypto.reset_key_cache()
    set_connection_store(InMemoryConnectionStore())
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


def _aws_record(*, inventory_scope: str = "account", auth_params: dict[str, Any] | None = None) -> CloudConnectionRecord:
    return CloudConnectionRecord(
        id=str(uuid.uuid4()),
        tenant_id="tenant-alpha",
        provider="aws",
        display_name="mgmt-readonly",
        role_ref="arn:aws:iam::111111111111:role/agent-bom-readonly",
        external_id_encrypted=connection_crypto.encrypt_secret("ext-id-for-tests"),
        regions=["us-east-1"],
        status=STATUS_ACTIVE,
        created_at="2026-07-24T00:00:00+00:00",
        updated_at="2026-07-24T00:00:00+00:00",
        inventory_scope=inventory_scope,
        auth_params=dict(auth_params or {}),
    )


def test_connection_org_fanout_enabled_from_column_and_auth_params() -> None:
    assert connection_org_fanout_enabled(_aws_record(inventory_scope="account")) is False
    assert connection_org_fanout_enabled(_aws_record(inventory_scope="organization")) is True
    assert (
        connection_org_fanout_enabled(
            _aws_record(inventory_scope="account", auth_params={"inventory_scope": "organization"})
        )
        is True
    )


def test_aws_org_connection_scan_calls_discover_all_with_session(monkeypatch: pytest.MonkeyPatch) -> None:
    record = _aws_record(inventory_scope="organization", auth_params={"member_role_name": "agent-bom-readonly"})
    brokered = MagicMock(name="brokered-session")
    fanout_payloads = [
        {"provider": "aws", "status": "ok", "account_id": "111111111111", "warnings": []},
        {"provider": "aws", "status": "ok", "account_id": "222222222222", "warnings": []},
    ]
    seen: dict[str, Any] = {}

    monkeypatch.setattr(routes, "_persist_connection_report", lambda *a, **k: "scan-org-1")
    monkeypatch.setattr(
        "agent_bom.cloud.connection_broker.broker_session",
        lambda rec, **kw: brokered,
    )

    def _fake_discover_all(**kwargs: Any) -> list[dict[str, Any]]:
        seen["kwargs"] = kwargs
        return fanout_payloads

    monkeypatch.setattr(aws_inventory, "discover_all_account_inventories", _fake_discover_all)
    monkeypatch.setattr(
        aws_inventory,
        "discover_inventory",
        lambda **kw: (_ for _ in ()).throw(AssertionError("single-account discover_inventory must not run")),
    )
    monkeypatch.setattr(
        "agent_bom.cloud.aws_cis_benchmark.run_benchmark",
        lambda **kw: MagicMock(to_dict=lambda: {"checks": [], "warnings": []}),
    )
    monkeypatch.setattr(
        "agent_bom.cloud.aws_cis_benchmark.run_all_account_benchmarks",
        lambda **kw: MagicMock(to_dict=lambda: {"checks": [], "warnings": []}),
    )
    monkeypatch.setattr(
        aws_organizations,
        "discover_organization",
        lambda **kw: {"status": "ok", "org_id": "o-test", "accounts": []},
    )
    monkeypatch.setattr(
        aws_organizations,
        "summarize_account_scan",
        lambda payloads: {"accounts_scanned": ["111111111111", "222222222222"], "total": 2},
    )

    result = routes._run_aws_connection_scan(record, "tenant-alpha")

    assert "kwargs" in seen
    assert seen["kwargs"].get("session") is brokered
    assert seen["kwargs"].get("force") is True
    assert seen["kwargs"].get("external_id") == "ext-id-for-tests"
    assert seen["kwargs"].get("role_name") == "agent-bom-readonly"
    assert result["scan_id"] == "scan-org-1"
    assert result["provider"] == "aws"


def test_aws_account_connection_scan_skips_org_fanout(monkeypatch: pytest.MonkeyPatch) -> None:
    record = _aws_record(inventory_scope="account")
    brokered = MagicMock(name="brokered-session")
    called_fanout = {"n": 0}

    monkeypatch.setattr(routes, "_persist_connection_report", lambda *a, **k: "scan-acct-1")
    monkeypatch.setattr(
        "agent_bom.cloud.connection_broker.broker_session",
        lambda rec, **kw: brokered,
    )

    def _fanout(**_kw: Any) -> list[dict[str, Any]]:
        called_fanout["n"] += 1
        return []

    monkeypatch.setattr(aws_inventory, "discover_all_account_inventories", _fanout)
    monkeypatch.setattr(
        aws_inventory,
        "discover_inventory",
        lambda **kw: {"provider": "aws", "status": "ok", "account_id": "111111111111", "warnings": []},
    )
    monkeypatch.setattr(
        "agent_bom.cloud.aws_cis_benchmark.run_benchmark",
        lambda **kw: MagicMock(to_dict=lambda: {"checks": [], "warnings": []}),
    )

    routes._run_aws_connection_scan(record, "tenant-alpha")
    assert called_fanout["n"] == 0


def test_create_api_accepts_inventory_scope() -> None:
    from agent_bom.api.server import app

    client = TestClient(app)
    headers = {
        "X-Agent-Bom-Role": "admin",
        "X-Agent-Bom-Tenant-ID": "tenant-alpha",
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }
    resp = client.post(
        "/v1/cloud/connections",
        headers=headers,
        json={
            "provider": "aws",
            "display_name": "Org mgmt",
            "role_ref": "arn:aws:iam::111111111111:role/agent-bom-readonly",
            "external_id": "ext-create-scope",
            "regions": ["us-east-1"],
            "inventory_scope": "organization",
            "auth_params": {},
        },
    )
    assert resp.status_code in (200, 201), resp.text
    body = resp.json()
    assert body["inventory_scope"] == "organization"


def test_discover_organization_accepts_session() -> None:
    org_client = MagicMock()
    org_client.describe_organization.return_value = {
        "Organization": {"Id": "o-abc", "MasterAccountId": "111111111111", "FeatureSet": "ALL"}
    }
    org_client.list_roots.return_value = {"Roots": [{"Id": "r-root", "Name": "Root"}]}

    class _EmptyPaginator:
        def paginate(self, **_kwargs: Any) -> list[dict[str, Any]]:
            return []

    org_client.get_paginator.return_value = _EmptyPaginator()

    session = MagicMock()
    session.client.return_value = org_client

    result = aws_organizations.discover_organization(session=session, force=True)
    session.client.assert_called_with("organizations")
    assert result["org_id"] == "o-abc"
    assert result["status"] == "ok"
