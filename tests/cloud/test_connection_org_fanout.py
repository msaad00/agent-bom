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


def test_connection_org_fanout_enabled_reads_the_column() -> None:
    assert connection_org_fanout_enabled(_aws_record(inventory_scope="account")) is False
    assert connection_org_fanout_enabled(_aws_record(inventory_scope="organization")) is True


def test_legacy_auth_params_scope_is_promoted_into_the_column_once() -> None:
    """A pre-column row keeps its org intent, but as column state — not a shadow."""
    record = _aws_record(inventory_scope="account", auth_params={"inventory_scope": "organization"})

    assert record.inventory_scope == "organization"
    assert "inventory_scope" not in record.auth_params
    assert connection_org_fanout_enabled(record) is True

    # Once promoted the column is the only switch: turning it off turns fan-out off.
    record.inventory_scope = "account"
    assert connection_org_fanout_enabled(record) is False


def test_patch_to_account_scope_turns_org_fanout_off_end_to_end() -> None:
    """Create carrying a legacy ``auth_params`` scope, then PATCH it back to account.

    Regression for the blast-radius disagreement: the API body, the stored
    column, ``connection_org_fanout_enabled`` (what the scan actually does), and
    the UI chip must all report the same scope after the update.
    """
    from agent_bom.api.connection_store import get_connection_store
    from agent_bom.api.server import app

    client = TestClient(app)
    headers = {
        "X-Agent-Bom-Role": "admin",
        "X-Agent-Bom-Tenant-ID": "tenant-alpha",
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }
    created = client.post(
        "/v1/cloud/connections",
        headers=headers,
        json={
            "provider": "aws",
            "display_name": "Legacy org mgmt",
            "role_ref": "arn:aws:iam::111111111111:role/agent-bom-readonly",
            "external_id": "ext-legacy-scope",
            "regions": ["us-east-1"],
            "auth_params": {"inventory_scope": "organization"},
            "auto_scan_on_create": False,
        },
    )
    assert created.status_code in (200, 201), created.text
    body = created.json()
    connection_id = body["id"]
    # The response must not claim "account" while the scan fans the whole org.
    assert body["inventory_scope"] == "organization"
    assert "inventory_scope" not in body["auth_params"]

    store = get_connection_store()
    stored = store.get("tenant-alpha", connection_id)
    assert stored is not None
    assert stored.inventory_scope == "organization"
    assert connection_org_fanout_enabled(stored) is True

    patched = client.patch(
        f"/v1/cloud/connections/{connection_id}",
        headers=headers,
        json={"inventory_scope": "account"},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["inventory_scope"] == "account"

    after = store.get("tenant-alpha", connection_id)
    assert after is not None
    assert after.inventory_scope == "account"
    assert after.auth_params.get("inventory_scope") is None
    assert connection_org_fanout_enabled(after) is False


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
    cis_report = MagicMock(to_dict=lambda: {"checks": [], "warnings": []})
    monkeypatch.setattr(
        "agent_bom.cloud.aws_cis_benchmark.run_all_account_benchmarks",
        lambda **kw: cis_report,
    )
    monkeypatch.setattr(
        "agent_bom.cloud.aws_cis_benchmark.run_benchmark",
        lambda **kw: (_ for _ in ()).throw(AssertionError("single-account run_benchmark must not run")),
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


def test_create_body_scope_wins_over_a_legacy_auth_params_scope() -> None:
    """An explicit ``account`` request is never widened by the legacy blob."""
    from agent_bom.api.server import app

    client = TestClient(app)
    headers = {
        "X-Agent-Bom-Role": "admin",
        "X-Agent-Bom-Tenant-ID": "tenant-alpha",
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }

    def _create(payload: dict[str, Any]) -> dict[str, Any]:
        resp = client.post("/v1/cloud/connections", headers=headers, json=payload)
        assert resp.status_code in (200, 201), resp.text
        body: dict[str, Any] = resp.json()
        return body

    base = {
        "provider": "aws",
        "display_name": "Explicit account scope",
        "role_ref": "arn:aws:iam::111111111111:role/agent-bom-readonly",
        "external_id": "ext-explicit-scope",
        "regions": ["us-east-1"],
        "auto_scan_on_create": False,
    }
    explicit = _create({**base, "inventory_scope": "account", "auth_params": {"inventory_scope": "organization"}})
    assert explicit["inventory_scope"] == "account"
    assert "inventory_scope" not in explicit["auth_params"]

    # An unparseable legacy scope narrows to the default instead of widening.
    unknown = _create({**base, "auth_params": {"inventory_scope": "whole-org"}})
    assert unknown["inventory_scope"] == "account"
    assert "inventory_scope" not in unknown["auth_params"]


def _member_payload(account_id: str) -> dict[str, Any]:
    return {
        "provider": "aws",
        "status": "ok",
        "account_id": account_id,
        "buckets": [{"name": f"bucket-{account_id}"}],
        "roles": [{"name": f"role-{account_id}"}],
        "warnings": [],
    }


def test_annotate_inventory_counts_covers_single_account_and_org_fanout() -> None:
    """Org fan-out persists a list of per-account payloads, not one dict.

    The scan-result panel sums ``resource_count`` / ``identity_count`` per
    account, so an unannotated list collapses every count to zero.
    """
    single = _member_payload("111111111111")
    routes._annotate_inventory_counts(single)
    assert single["resource_count"] == 1
    assert single["identity_count"] == 1

    fanout = [_member_payload("111111111111"), _member_payload("222222222222")]
    routes._annotate_inventory_counts(fanout)
    assert [item["resource_count"] for item in fanout] == [1, 1]
    assert [item["identity_count"] for item in fanout] == [1, 1]
    assert all(isinstance(item["node_summary"], dict) for item in fanout)

    # Non-payload shapes stay untouched rather than raising.
    mixed: list[Any] = ["not-a-payload", None]
    routes._annotate_inventory_counts(mixed)
    assert mixed == ["not-a-payload", None]


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
