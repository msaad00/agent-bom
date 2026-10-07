"""Unauthenticated RelayState issuance only exists when SAML can be used.

The route is public, so issuing a nonce while SAML is unconfigured lets anyone
grow the shared nonce table for a login flow that can never complete.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

from agent_bom.api.server import app
from agent_bom.api.shared_auth_state import InMemoryAuthState, reset_auth_state_for_tests, set_auth_state_for_tests

_SAML_ENV = {
    "AGENT_BOM_SAML_IDP_ENTITY_ID": "https://idp.example.test/metadata",
    "AGENT_BOM_SAML_IDP_SSO_URL": "https://idp.example.test/sso",
    "AGENT_BOM_SAML_IDP_X509_CERT": "MIIC-test-cert",
    "AGENT_BOM_SAML_SP_ENTITY_ID": "https://agent-bom.example.test/sp",
    "AGENT_BOM_SAML_SP_ACS_URL": "https://agent-bom.example.test/v1/auth/saml/login",
}


class _RecordingAuthState(InMemoryAuthState):
    def __init__(self) -> None:
        super().__init__()
        self.registered: list[str] = []

    def register_one_time_nonce(self, nonce, expires_at, now=None):  # type: ignore[no-untyped-def]
        self.registered.append(nonce)
        return super().register_one_time_nonce(nonce, expires_at, now=now)


@pytest.fixture()
def auth_state(monkeypatch: pytest.MonkeyPatch):
    for name in _SAML_ENV:
        monkeypatch.delenv(name, raising=False)
    backend = _RecordingAuthState()
    set_auth_state_for_tests(backend)
    yield backend
    reset_auth_state_for_tests()


def test_relay_state_is_503_and_writes_nothing_when_saml_unconfigured(auth_state, monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.api.saml.saml_runtime_available", lambda: True)
    client = TestClient(app)

    responses = [client.post("/v1/auth/saml/relay-state") for _ in range(5)]

    assert {response.status_code for response in responses} == {503}
    assert "SAML is not configured" in responses[0].json()["detail"]
    assert auth_state.registered == []


def test_relay_state_is_503_when_saml_extra_missing(auth_state, monkeypatch) -> None:
    for key, value in _SAML_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("agent_bom.api.saml.saml_runtime_available", lambda: False)

    response = TestClient(app).post("/v1/auth/saml/relay-state")

    assert response.status_code == 503
    assert "[saml] extra" in response.json()["detail"]
    assert auth_state.registered == []


def test_relay_state_is_issued_when_saml_configured(auth_state, monkeypatch) -> None:
    for key, value in _SAML_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("agent_bom.api.saml.saml_runtime_available", lambda: True)

    response = TestClient(app).post("/v1/auth/saml/relay-state")

    assert response.status_code == 200, response.text
    assert response.json()["relay_state"]
    assert len(auth_state.registered) == 1
