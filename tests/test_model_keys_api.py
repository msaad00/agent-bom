"""API tests for the model-provider key broker plane (#3907).

Covers RBAC (auth required, viewer read-only), the register -> mint -> authorize
-> revoke lifecycle over HTTP, tenant scoping, and the two hard security
guarantees: the real provider key never appears in ANY response (register, list,
get, mint, or authorize), and revocation blocks further authorization.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from agent_bom.api import connection_crypto
from agent_bom.api.model_key_broker import InMemoryModelKeyBrokerStore, set_model_key_broker_store

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
_TEST_FERNET = Fernet.generate_key().decode("ascii")
_REAL_KEY = "sk-real-provider-secret-DO-NOT-LEAK-xyz"


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
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = _TEST_FERNET
    os.environ.pop(f"{connection_crypto.CONNECTIONS_KEY_ENV}_FILE", None)
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV, None)
    connection_crypto.reset_key_cache()
    set_model_key_broker_store(InMemoryModelKeyBrokerStore())
    try:
        yield
    finally:
        for name, value in prior.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        connection_crypto.reset_key_cache()
        set_model_key_broker_store(None)


def _app() -> Any:
    from agent_bom.api.server import app

    return app


def _register(client: TestClient, tenant: str = "tenant-alpha") -> dict[str, Any]:
    resp = client.post(
        "/v1/model-keys/providers",
        json={"provider": "openai", "display_name": "prod-openai", "api_key": _REAL_KEY},
        headers=_headers(tenant=tenant),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _mint(client: TestClient, provider_key_id: str, tenant: str = "tenant-alpha", **body: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"holder_id": "agent-1", "allowed_models": ["gpt-4o"]}
    payload.update(body)
    resp = client.post(
        f"/v1/model-keys/providers/{provider_key_id}/virtual-keys",
        json=payload,
        headers=_headers(tenant=tenant),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ── auth / RBAC ──────────────────────────────────────────────────────────────


def test_requires_authentication() -> None:
    client = TestClient(_app())
    assert client.get("/v1/model-keys/providers").status_code == 401
    assert (
        client.post(
            "/v1/model-keys/providers",
            json={"provider": "openai", "display_name": "x", "api_key": _REAL_KEY},
        ).status_code
        == 401
    )


def test_viewer_can_list_but_not_register() -> None:
    client = TestClient(_app())
    pk = _register(client)
    assert client.get("/v1/model-keys/providers", headers=_headers(role="viewer")).status_code == 200
    resp = client.post(
        "/v1/model-keys/providers",
        json={"provider": "openai", "display_name": "x", "api_key": _REAL_KEY},
        headers=_headers(role="viewer"),
    )
    assert resp.status_code == 403
    # Viewer cannot mint either.
    assert (
        client.post(
            f"/v1/model-keys/providers/{pk['provider_key_id']}/virtual-keys",
            json={"holder_id": "a"},
            headers=_headers(role="viewer"),
        ).status_code
        == 403
    )


# ── no-secret guarantees ─────────────────────────────────────────────────────


def test_register_response_never_contains_real_key() -> None:
    client = TestClient(_app())
    body = _register(client)
    assert _REAL_KEY not in str(body)
    assert "secret_encrypted" not in body
    assert "api_key" not in body
    assert body["has_secret"] is True
    assert body["provider"] == "openai"


def test_list_and_get_never_contain_real_key() -> None:
    client = TestClient(_app())
    pk = _register(client)
    listed = client.get("/v1/model-keys/providers", headers=_headers()).json()
    got = client.get(f"/v1/model-keys/providers/{pk['provider_key_id']}", headers=_headers()).json()
    for body in (listed, got):
        assert _REAL_KEY not in str(body)
        assert "secret_encrypted" not in str(body)


def test_mint_returns_virtual_token_not_real_key() -> None:
    client = TestClient(_app())
    pk = _register(client)
    minted = _mint(client, pk["provider_key_id"])
    assert minted["virtual_key"].startswith("abvk_")
    assert _REAL_KEY not in str(minted)
    assert "token_hash" not in str(minted["virtual_key_record"])
    assert minted["virtual_key_record"]["provider"] == "openai"


def test_authorize_returns_decision_without_real_key() -> None:
    client = TestClient(_app())
    pk = _register(client)
    raw = _mint(client, pk["provider_key_id"])["virtual_key"]
    resp = client.post(
        "/v1/model-keys/authorize",
        json={"virtual_key": raw, "provider": "openai", "model": "gpt-4o"},
        headers=_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["authorized"] is True
    assert body["provider"] == "openai"
    assert _REAL_KEY not in str(body)
    assert "api_key" not in str(body)
    assert "secret" not in str(body).lower()


# ── scope + revocation over HTTP ─────────────────────────────────────────────


def test_authorize_rejects_out_of_scope_model() -> None:
    client = TestClient(_app())
    pk = _register(client)
    raw = _mint(client, pk["provider_key_id"], allowed_models=["gpt-4o"])["virtual_key"]
    resp = client.post(
        "/v1/model-keys/authorize",
        json={"virtual_key": raw, "provider": "openai", "model": "gpt-3.5-turbo"},
        headers=_headers(),
    )
    assert resp.status_code == 403


def test_revoke_blocks_further_authorization() -> None:
    client = TestClient(_app())
    pk = _register(client)
    minted = _mint(client, pk["provider_key_id"])
    raw = minted["virtual_key"]
    vk_id = minted["virtual_key_record"]["virtual_key_id"]

    ok = client.post(
        "/v1/model-keys/authorize",
        json={"virtual_key": raw, "provider": "openai", "model": "gpt-4o"},
        headers=_headers(),
    )
    assert ok.status_code == 200

    revoked = client.post(f"/v1/model-keys/virtual-keys/{vk_id}/revoke", json={"reason": "rotate"}, headers=_headers())
    assert revoked.status_code == 200
    assert revoked.json()["virtual_key_record"]["status"] == "revoked"

    denied = client.post(
        "/v1/model-keys/authorize",
        json={"virtual_key": raw, "provider": "openai", "model": "gpt-4o"},
        headers=_headers(),
    )
    assert denied.status_code == 403


# ── tenant isolation over HTTP ───────────────────────────────────────────────


def test_tenant_b_cannot_see_or_authorize_tenant_a_keys() -> None:
    client = TestClient(_app())
    pk = _register(client, tenant="tenant-alpha")
    raw = _mint(client, pk["provider_key_id"], tenant="tenant-alpha")["virtual_key"]

    # Tenant B lists nothing and 404s on tenant A's provider key.
    b_list = client.get("/v1/model-keys/providers", headers=_headers(tenant="tenant-beta")).json()
    assert b_list["count"] == 0
    assert client.get(f"/v1/model-keys/providers/{pk['provider_key_id']}", headers=_headers(tenant="tenant-beta")).status_code == 404
    # Tenant B cannot authorize tenant A's virtual key even with the raw token.
    denied = client.post(
        "/v1/model-keys/authorize",
        json={"virtual_key": raw, "provider": "openai", "model": "gpt-4o"},
        headers=_headers(tenant="tenant-beta"),
    )
    assert denied.status_code == 404


def test_register_unsupported_provider_rejected() -> None:
    client = TestClient(_app())
    resp = client.post(
        "/v1/model-keys/providers",
        json={"provider": "definitely-not-real", "display_name": "x", "api_key": _REAL_KEY},
        headers=_headers(),
    )
    assert resp.status_code == 400


def test_register_fails_closed_without_sealing_key() -> None:
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_ENV, None)
    connection_crypto.reset_key_cache()
    client = TestClient(_app())
    resp = client.post(
        "/v1/model-keys/providers",
        json={"provider": "openai", "display_name": "x", "api_key": _REAL_KEY},
        headers=_headers(),
    )
    assert resp.status_code == 503
