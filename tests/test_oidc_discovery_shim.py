"""Contract tests for the OIDC discovery shim (#3609)."""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from agent_bom.api.oidc_discovery_shim import (
    OIDCDiscoveryShimConfig,
    OIDCDiscoveryShimError,
    build_oidc_discovery_shim_router,
    build_openid_configuration,
    validate_oidc_discovery_document,
)
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


def _sample_config() -> OIDCDiscoveryShimConfig:
    return OIDCDiscoveryShimConfig(
        issuer="https://mcp-auth.example.com",
        authorization_endpoint="https://idp.example.com/oauth2/v1/authorize",
        token_endpoint="https://idp.example.com/oauth2/v1/token",
        jwks_uri="https://idp.example.com/oauth2/v1/keys",
        userinfo_endpoint="https://idp.example.com/oauth2/v1/userinfo",
        scopes_supported=("openid", "profile", "email"),
    )


def test_build_openid_configuration_includes_mcp_client_contract_fields() -> None:
    doc = build_openid_configuration(_sample_config())
    validate_oidc_discovery_document(doc)
    assert doc["issuer"] == "https://mcp-auth.example.com"
    assert doc["authorization_endpoint"].endswith("/authorize")
    assert doc["token_endpoint"].endswith("/token")
    assert doc["jwks_uri"].endswith("/keys")
    assert doc["response_types_supported"] == ["code"]
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert doc["scopes_supported"] == ["openid", "profile", "email"]


def test_validate_oidc_discovery_document_rejects_incomplete_docs() -> None:
    with pytest.raises(OIDCDiscoveryShimError, match="missing required keys"):
        validate_oidc_discovery_document({"issuer": "https://example.com"})


def test_from_mapping_and_env_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "issuer": "https://shim.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/jwks",
    }
    config = OIDCDiscoveryShimConfig.from_mapping(payload)
    monkeypatch.setenv("AGENT_BOM_OIDC_DISCOVERY_SHIM_JSON", json.dumps(payload))
    assert OIDCDiscoveryShimConfig.from_env() == config


def test_shim_router_serves_well_known_openid_configuration() -> None:
    from fastapi import FastAPI

    config = _sample_config()
    app = FastAPI()
    app.include_router(build_oidc_discovery_shim_router(config))
    client = TestClient(app)
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "public, max-age=300"
    body = resp.json()
    validate_oidc_discovery_document(body)
    assert body["issuer"] == config.issuer


def test_gateway_mounts_oidc_discovery_shim_when_configured() -> None:
    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
        policy={},
        oidc_discovery_shim=_sample_config(),
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    validate_oidc_discovery_document(resp.json())
