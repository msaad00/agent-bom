"""Workload brokers must bind server identity configuration to one tenant/scope."""

from __future__ import annotations

import json
import sys
import types
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from agent_bom.api.connection_store import CloudConnectionRecord
from agent_bom.cloud.connection_broker import ConnectionBrokerError, broker_session


def record(provider: str = "azure", mode: str = "workload_identity") -> CloudConnectionRecord:
    return CloudConnectionRecord(
        id="connection",
        tenant_id="tenant-a",
        provider=provider,
        display_name="Production",
        role_ref="client-id",
        external_id_encrypted="",
        auth_params={
            "auth_mode": mode,
            "credential_binding": "binding-a",
            **({"tenant_id": "directory-a", "subscription_id": "scope-a"} if provider == "azure" else {"project_id": "scope-a"}),
        },
    )


@pytest.fixture
def binding(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    data = {
        "tenant_id": "tenant-a",
        "provider": "azure",
        "auth_mode": "workload_identity",
        "role_ref": "client-id",
        "scope_id": "scope-a",
        "directory_tenant_id": "directory-a",
        "token_file_path": str(tmp_path / "token"),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    }
    path = tmp_path / "bindings.json"

    def write() -> None:
        path.write_text(json.dumps({"bindings": {"binding-a": data}}))

    write()
    monkeypatch.setenv("AGENT_BOM_CONNECTION_WORKLOAD_BINDINGS_FILE", str(path))
    data["_write"] = lambda: path.write_text(json.dumps({"bindings": {"binding-a": {k: v for k, v in data.items() if k != "_write"}}}))
    return data


def test_azure_workload_uses_exact_server_binding(binding: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    sentinel = object()

    def build(**kwargs: Any) -> object:
        captured.update(kwargs)
        return sentinel

    monkeypatch.setitem(sys.modules, "azure.identity", types.SimpleNamespace(WorkloadIdentityCredential=build))
    assert broker_session(record()) is sentinel
    assert captured == {"tenant_id": "directory-a", "client_id": "client-id", "token_file_path": binding["token_file_path"]}


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "tenant-b"),
        ("scope_id", "other"),
        ("role_ref", "other"),
        ("directory_tenant_id", "other"),
        ("enabled", False),
        ("expires_at", "2000-01-01T00:00:00+00:00"),
    ],
)
def test_binding_mismatch_or_revocation_fails_closed(binding: dict[str, Any], field: str, value: Any) -> None:
    binding[field] = value
    binding["_write"]()
    with pytest.raises(ConnectionBrokerError):
        broker_session(record())


def test_azure_managed_identity_is_explicit(binding: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    binding["auth_mode"] = "managed_identity"
    binding["_write"]()
    calls: list[dict[str, Any]] = []
    monkeypatch.setitem(sys.modules, "azure.identity", types.SimpleNamespace(ManagedIdentityCredential=lambda **kw: calls.append(kw)))
    broker_session(record(mode="managed_identity"))
    assert calls == [{"client_id": "client-id"}]


def test_google_wif_has_fixed_endpoints_scope_and_principal(binding: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    binding.update(
        provider="gcp",
        directory_tenant_id="",
        role_ref="scanner@project.iam.gserviceaccount.com",
        audience="//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
    )
    binding["_write"]()
    source_calls: list[dict[str, Any]] = []
    target_calls: list[dict[str, Any]] = []
    source = object()

    def make_source(**kwargs: Any) -> object:
        source_calls.append(kwargs)
        return source

    monkeypatch.setitem(
        sys.modules,
        "google.auth",
        types.SimpleNamespace(
            identity_pool=types.SimpleNamespace(Credentials=make_source),
            impersonated_credentials=types.SimpleNamespace(Credentials=lambda **kw: target_calls.append(kw)),
        ),
    )
    candidate = record("gcp")
    candidate.role_ref = binding["role_ref"]
    broker_session(candidate)
    assert source_calls == [
        {
            "audience": binding["audience"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": "https://sts.googleapis.com/v1/token",
            "credential_source": {"file": binding["token_file_path"]},
            "scopes": ["https://www.googleapis.com/auth/iam"],
        }
    ]
    assert target_calls == [
        {
            "source_credentials": source,
            "target_principal": binding["role_ref"],
            "target_scopes": ["https://www.googleapis.com/auth/cloud-platform.read-only"],
            "lifetime": 3600,
        }
    ]


@pytest.mark.parametrize("mutation", ["bad_audience", "bad_provider", "no_mode", "unknown_mode", "secret", "unknown_field"])
def test_workload_never_falls_back_or_accepts_injected_configuration(binding: dict[str, Any], mutation: str) -> None:
    candidate = record()
    if mutation == "bad_audience":
        binding["audience"] = "https://attacker.example/token"
    elif mutation == "bad_provider":
        binding["provider"] = "gcp"
    elif mutation == "no_mode":
        candidate.auth_params.pop("auth_mode")
    elif mutation == "unknown_mode":
        candidate.auth_params["auth_mode"] = "automatic"
    elif mutation == "secret":
        candidate.external_id_encrypted = "ciphertext"
    else:
        binding["token_url"] = "https://attacker.example/token"
    binding["_write"]()
    with pytest.raises(ConnectionBrokerError):
        broker_session(candidate)


def test_expired_operator_binding_is_rechecked_on_next_use(binding: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "azure.identity", types.SimpleNamespace(WorkloadIdentityCredential=lambda **kw: object()))
    broker_session(record())
    binding["expires_at"] = "2000-01-01T00:00:00Z"
    binding["_write"]()
    with pytest.raises(ConnectionBrokerError):
        broker_session(record())


def test_account_binding_cannot_enable_organization_fanout(binding: dict[str, Any]) -> None:
    candidate = record()
    candidate.inventory_scope = "organization"
    with pytest.raises(ConnectionBrokerError):
        broker_session(candidate)


def test_operator_binding_failures_never_expose_paths_or_payload(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "private-canary.json"
    monkeypatch.setenv("AGENT_BOM_CONNECTION_WORKLOAD_BINDINGS_FILE", str(path))
    for payload in (None, "private-canary-value", '{"bindings":{}}'):
        if payload is not None:
            path.write_text(payload)
        with pytest.raises(ConnectionBrokerError) as error:
            broker_session(record())
        assert "private-canary" not in str(error.value)


def test_sdk_construction_failure_never_exposes_provider_error(binding: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(**kwargs: Any) -> object:
        raise RuntimeError("private-canary-token")

    monkeypatch.setitem(sys.modules, "azure.identity", types.SimpleNamespace(WorkloadIdentityCredential=broken))
    with pytest.raises(ConnectionBrokerError) as error:
        broker_session(record())
    assert "private-canary-token" not in str(error.value)


@pytest.fixture
def snowflake_binding(binding: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> CloudConnectionRecord:
    binding.update(provider="snowflake", role_ref="account-a", scope_id="account-a", directory_tenant_id="", token_file_path="")
    binding["_write"]()
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_NATIVE_APP", "true")
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "account-a")
    monkeypatch.setenv("SNOWFLAKE_HOST", "account-a.snowflakecomputing.com")
    candidate = record("snowflake")
    candidate.role_ref = "account-a"
    candidate.auth_params.pop("project_id")
    candidate.auth_params["account"] = "account-a"
    return candidate


def test_snowflake_workload_uses_rotating_injected_identity(
    snowflake_binding: CloudConnectionRecord, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    connector = types.ModuleType("snowflake.connector")
    connector.connect = lambda **kw: calls.append(kw)  # type: ignore[attr-defined]
    package = types.ModuleType("snowflake")
    package.connector = connector  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "snowflake", package)
    monkeypatch.setitem(sys.modules, "snowflake.connector", connector)
    monkeypatch.delenv("SNOWFLAKE_TOKEN_FILE_PATH", raising=False)
    broker_session(snowflake_binding)
    assert calls == [
        {
            "account": "account-a",
            "host": "account-a.snowflakecomputing.com",
            "authenticator": "oauth",
            "token_file_path": "/snowflake/session/token",
        }
    ]


@pytest.mark.parametrize("mutation", ["tenant", "account", "outside", "revoked", "expired", "role", "token_file", "organization", "host"])
def test_snowflake_workload_fails_closed(
    snowflake_binding: CloudConnectionRecord, binding: dict[str, Any], monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    if mutation == "tenant":
        snowflake_binding.tenant_id = "other"
    elif mutation == "account":
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "other")
    elif mutation == "outside":
        monkeypatch.delenv("AGENT_BOM_SNOWFLAKE_NATIVE_APP")
    elif mutation == "revoked":
        binding["enabled"] = False
    elif mutation == "expired":
        binding["expires_at"] = "2000-01-01T00:00:00Z"
    elif mutation == "role":
        snowflake_binding.auth_params["role"] = "ACCOUNTADMIN"
    elif mutation == "token_file":
        binding["token_file_path"] = "/another/token"
    elif mutation == "organization":
        snowflake_binding.inventory_scope = "organization"
        binding["inventory_scope"] = "organization"
    else:
        monkeypatch.delenv("SNOWFLAKE_HOST")
    binding["_write"]()
    with pytest.raises(ConnectionBrokerError):
        broker_session(snowflake_binding)
