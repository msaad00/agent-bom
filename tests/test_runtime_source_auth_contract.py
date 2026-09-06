"""Runtime producers authenticate outside evidence bodies and MCP arguments."""

import asyncio
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from starlette.testclient import TestClient

from agent_bom.cloud.runtime_source_auth import SourceAuthenticationError
from tests.runtime_auth_helpers import runtime_headers, runtime_principal


def test_runtime_ingest_api_does_not_accept_credentials():
    from agent_bom.api.models import RuntimeEvidenceIngestRequest

    properties = RuntimeEvidenceIngestRequest.model_json_schema()["properties"]
    assert not {"secret", "token", "api_key", "password"} & properties.keys()


def test_runtime_ingest_mcp_does_not_accept_credentials():
    from agent_bom.mcp_server import create_mcp_server

    tool = next(t for t in asyncio.run(create_mcp_server(profile="full").list_tools()) if t.name == "runtime_evidence_ingest")
    assert not {"secret", "token", "api_key", "password"} & tool.inputSchema["properties"].keys()


def test_runtime_ingest_cli_does_not_accept_source_secrets():
    from agent_bom.cli._cloud_group import cloud_group

    result = CliRunner().invoke(cloud_group, ["runtime-evidence-ingest", "--help"])
    assert result.exit_code == 0
    assert "--secret" not in result.output
    assert "API" in result.output


def test_runtime_source_registration_needs_no_secret():
    from agent_bom.cloud.runtime_workload_evidence import RuntimeEvidenceSource

    source = RuntimeEvidenceSource(source_id="edr-1", tenant_id="a", provider="aws", account_id="123", kind="edr")
    assert "secret" not in repr(source)


@pytest.fixture
def ingest_client(monkeypatch):
    from agent_bom.api.server import app, configure_api
    from agent_bom.cloud.runtime_workload_evidence import RuntimeEvidenceSource, RuntimeSourceRegistry, set_runtime_source_registry
    from agent_bom.cloud.runtime_workload_evidence_store import InMemoryRuntimeWorkloadEvidenceStore, set_runtime_workload_evidence_store

    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH", raising=False)
    configure_api(api_key=None)
    registry = RuntimeSourceRegistry()
    registry.add(RuntimeEvidenceSource("edr-1", "tenant-alpha", "aws", "123", "edr"))
    set_runtime_source_registry(registry)
    store = InMemoryRuntimeWorkloadEvidenceStore()
    set_runtime_workload_evidence_store(store)
    with TestClient(app) as client:
        yield client, store
    set_runtime_source_registry(None)
    set_runtime_workload_evidence_store(None)
    configure_api(api_key=None)


def _payload(**overrides):
    value = dict(
        source_id="edr-1",
        signals=[
            dict(workload_ref="i-1", signal_type="ioc_detection", observed_at=datetime.now(timezone.utc).isoformat(), dedup_key="e-1")
        ],
    )
    value.update(overrides)
    return value


@pytest.mark.parametrize("scopes", [[], ["*"], ["runtime:*"], ["runtime:ingest:other"]])
def test_api_rejects_unbound_source_scope_before_storage(ingest_client, scopes):
    client, store = ingest_client
    with patch.object(store, "put_batch", wraps=store.put_batch) as persist:
        response = client.post("/v1/cloud/runtime-evidence/ingest", headers=runtime_headers(scopes=scopes), json=_payload())
    assert response.status_code in (401, 403)
    persist.assert_not_called()


@pytest.mark.parametrize(
    "overrides",
    [
        {"expires_at": None},
        {"expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()},
        {"expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()},
        {"revoked_at": datetime.now(timezone.utc).isoformat()},
        {"created_at": (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()},
    ],
)
def test_api_rejects_unbounded_expired_revoked_or_future_key(ingest_client, overrides):
    client, store = ingest_client
    with patch.object(store, "put_batch", wraps=store.put_batch) as persist:
        response = client.post("/v1/cloud/runtime-evidence/ingest", headers=runtime_headers(**overrides), json=_payload())
    assert response.status_code == 401
    persist.assert_not_called()


def test_api_rejects_delegated_tenant_mismatch_before_storage(ingest_client):
    client, store = ingest_client
    headers = {**runtime_headers(), "X-Agent-Bom-Tenant-ID": "other"}
    with patch.object(store, "put_batch", wraps=store.put_batch) as persist:
        response = client.post("/v1/cloud/runtime-evidence/ingest", headers=headers, json=_payload())
    assert response.status_code in (401, 403)
    persist.assert_not_called()


def test_api_short_lived_key_persists_and_audits_and_validation_does_not_write(ingest_client):
    client, store = ingest_client
    headers = runtime_headers()
    with patch.object(store, "put_batch", wraps=store.put_batch) as persist:
        validated = client.post("/v1/cloud/runtime-evidence/ingest", headers=headers, json=_payload(validate_only=True))
        assert validated.status_code == 200, validated.text
        assert validated.json()["persisted"] == 0
        persist.assert_not_called()
        response = client.post("/v1/cloud/runtime-evidence/ingest", headers=headers, json=_payload())
    assert response.status_code == 200, response.text
    assert response.json()["persisted"] == 1
    assert response.json()["audit_status"] == "recorded"


def test_api_reports_postwrite_audit_failure_as_partial(ingest_client):
    client, _store = ingest_client
    with patch("agent_bom.api.audit_log.log_action", side_effect=RuntimeError("secret details")):
        response = client.post("/v1/cloud/runtime-evidence/ingest", headers=runtime_headers(), json=_payload())
    assert response.status_code == 200
    assert response.json()["persisted"] == 1
    assert response.json()["audit_status"] == "unavailable"
    assert response.json()["status"] == "partial"
    assert "secret details" not in response.text


def test_legacy_body_secret_rejected_without_echo(ingest_client):
    client, _store = ingest_client
    response = client.post(
        "/v1/cloud/runtime-evidence/ingest", headers=runtime_headers(), json=_payload(secret="private-source-credential")
    )
    assert response.status_code == 422
    assert "private-source-credential" not in response.text


@pytest.mark.parametrize(
    "overrides",
    [
        dict(issued_at=True),
        dict(expires_at=float("inf")),
        dict(expires_at=float("nan")),
        dict(expires_at=time.time() - 1),
        dict(issued_at="future"),
        dict(tenant_id="other"),
        dict(scopes=("*",)),
    ],
)
def test_internal_principal_cannot_grant_invalid_authority(overrides):
    if overrides.get("issued_at") == "future":
        overrides = {"issued_at": time.time() + 60}
    with pytest.raises(SourceAuthenticationError):
        runtime_principal(**overrides).authorize("edr-1", "tenant-a")


def test_api_exact_source_scope_is_sufficient(ingest_client):
    client, _ = ingest_client
    response = client.post("/v1/cloud/runtime-evidence/ingest", headers=runtime_headers(scopes=["runtime:ingest:edr-1"]), json=_payload())
    assert response.status_code == 200, response.text


@pytest.mark.parametrize(
    "change,expected",
    [
        ({}, 200),
        ({"scope": "*"}, 401),
        ({"scope": "runtime:ingest:other"}, 401),
        ({"iat": None}, 401),
        ({"exp": None}, 401),
        ({"tenant_id": "other"}, 401),
        ({"iat": True}, 401),
    ],
)
def test_verified_oidc_source_binding(ingest_client, monkeypatch, change, expected):
    from agent_bom.api.middleware import APIKeyMiddleware
    from agent_bom.api.oidc import OIDCConfig

    client, store = ingest_client
    now = time.time()
    claims = {
        "iss": "https://issuer.example",
        "sub": "producer",
        "tenant_id": "tenant-alpha",
        "agent_bom_role": "admin",
        "iat": now - 1,
        "exp": now + 1799,
        "scope": "runtime:ingest:edr-1",
        **change,
    }
    cfg = OIDCConfig(issuer="https://issuer.example", audience="agent-bom")
    monkeypatch.setattr(cfg, "verify", lambda token: (claims, "admin"))
    # The route sees only middleware-verified claims. Configure the existing
    # middleware instance because the global app is reused across tests.
    current = client.app.middleware_stack
    while current is not None:
        if isinstance(current, APIKeyMiddleware):
            monkeypatch.setattr(current, "_oidc_config", cfg)
            monkeypatch.setattr(current, "_oidc_checked", True)
            break
        current = getattr(current, "app", None)
    with patch.object(store, "put_batch", wraps=store.put_batch) as persist:
        response = client.post("/v1/cloud/runtime-evidence/ingest", headers={"Authorization": "Bearer verified-test-jwt"}, json=_payload())
    assert response.status_code == expected, response.text
    if expected != 200:
        persist.assert_not_called()


@pytest.mark.parametrize("credential", ["api_key", "bearer_token"])
def test_client_transmits_credentials_only_in_auth_headers(credential):
    import json

    import httpx

    from agent_bom.client import AgentBomClient

    def handle(request):
        assert str(request.url) == "https://control.example/v1/cloud/runtime-evidence/ingest"
        assert request.headers["X-Agent-Bom-Tenant-ID"] == "tenant-alpha"
        assert request.headers["X-API-Key" if credential == "api_key" else "Authorization"].endswith("private-credential")
        body = json.loads(request.content)
        assert body == {"source_id": "edr-1", "signals": [], "reason": "Validate producer integration", "validate_only": True}
        assert "private-credential" not in request.content.decode()
        return httpx.Response(200, json={"source_id": "edr-1", "tenant_id": "tenant-alpha"})

    with AgentBomClient(
        base_url="https://control.example",
        tenant_id="tenant-alpha",
        transport=httpx.MockTransport(handle),
        **{credential: "private-credential"},
    ) as client:
        client.ingest_runtime_evidence(source_id="edr-1", signals=[], reason="Validate producer integration", validate_only=True)


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "ftp://control.example",
        "http://control.example",
        "https://control.example/nested",
        "https://control.example:invalid",
        "https://user:pass@control.example",
        "https://control.example?upstream=evil",
        "https://control.example#evil",
    ],
)
def test_producer_rejects_invalid_origin_before_network(monkeypatch, origin):
    from agent_bom.cloud.runtime_evidence_client import push_runtime_evidence

    monkeypatch.setenv("AGENT_BOM_API_URL", origin)
    monkeypatch.setenv("AGENT_BOM_API_KEY", "private-credential")
    monkeypatch.delenv("AGENT_BOM_API_TOKEN", raising=False)
    with patch("agent_bom.cloud.runtime_evidence_client.AgentBomClient") as client:
        with pytest.raises(SourceAuthenticationError):
            push_runtime_evidence(source_id="edr-1", payload=[], reason="Validate integration")
    client.assert_not_called()
