from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from agent_bom.api.auth import KeyStore, get_key_store, set_key_store
from agent_bom.api.models import SAMLLoginRequest
from agent_bom.api.routes import enterprise
from agent_bom.api.saml import SAMLConfig, SAMLError, saml_attributes_to_role, saml_attributes_to_tenant


class _FakeAuth:
    def __init__(
        self,
        *,
        authenticated: bool = True,
        attributes: dict | None = None,
        errors: list[str] | None = None,
        subject: str = "alice@example.com",
        session_index: str = "session-1",
    ) -> None:
        self._authenticated = authenticated
        self._attributes = attributes or {}
        self._errors = errors or []
        self._subject = subject
        self._session_index = session_index

    def process_response(self) -> None:
        return None

    def get_errors(self) -> list[str]:
        return list(self._errors)

    def get_last_error_reason(self) -> str:
        return "invalid assertion" if self._errors else ""

    def is_authenticated(self) -> bool:
        return self._authenticated

    def get_attributes(self) -> dict:
        return dict(self._attributes)

    def get_nameid(self) -> str:
        return self._subject

    def get_nameid_format(self) -> str:
        return "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    def get_session_index(self) -> str:
        return self._session_index


@pytest.fixture
def isolated_key_store():
    original = get_key_store()
    store = KeyStore()
    set_key_store(store)
    try:
        yield store
    finally:
        set_key_store(original)


def test_saml_config_disabled_when_env_missing():
    with patch.dict(os.environ, {}, clear=True):
        cfg = SAMLConfig.from_env()
        assert cfg.enabled is False


def test_saml_attribute_mapping_uses_existing_role_and_tenant_contract():
    assert saml_attributes_to_role({"groups": ["security-analyst"]}) == "analyst"
    assert saml_attributes_to_tenant({"tenant_id": ["tenant-alpha"]}) == "tenant-alpha"


def test_saml_verify_requires_role_attribute_when_enabled():
    cfg = SAMLConfig(
        idp_entity_id="https://idp.example.com/metadata",
        idp_sso_url="https://idp.example.com/sso",
        idp_x509_cert="cert",
        sp_entity_id="https://agent-bom.example.com/saml/metadata",
        sp_acs_url="https://agent-bom.example.com/v1/auth/saml/login",
        require_role_attribute=True,
    )

    with patch("agent_bom.api.saml._build_saml_auth", return_value=_FakeAuth(attributes={"tenant_id": ["tenant-alpha"]})):
        with pytest.raises(SAMLError, match="required role attribute"):
            cfg.verify_response("encoded-response")


def test_saml_verify_requires_tenant_attribute_when_enabled():
    cfg = SAMLConfig(
        idp_entity_id="https://idp.example.com/metadata",
        idp_sso_url="https://idp.example.com/sso",
        idp_x509_cert="cert",
        sp_entity_id="https://agent-bom.example.com/saml/metadata",
        sp_acs_url="https://agent-bom.example.com/v1/auth/saml/login",
        require_tenant_attribute=True,
    )

    with patch(
        "agent_bom.api.saml._build_saml_auth",
        return_value=_FakeAuth(attributes={"agent_bom_role": ["admin"]}),
    ):
        with pytest.raises(SAMLError, match="required tenant attribute"):
            cfg.verify_response("encoded-response")


@pytest.mark.asyncio
async def test_saml_metadata_route_returns_xml(monkeypatch):
    monkeypatch.setattr("agent_bom.api.saml.SAMLConfig.metadata_xml", lambda self: "<EntityDescriptor />")

    response = await enterprise.saml_metadata()

    assert response.media_type == "application/samlmetadata+xml"
    assert response.body.decode() == "<EntityDescriptor />"


@pytest.mark.asyncio
async def test_saml_login_mints_short_lived_api_key(isolated_key_store, monkeypatch):
    monkeypatch.setattr(
        "agent_bom.api.saml.SAMLConfig.verify_response",
        lambda self, saml_response, relay_state=None: type(
            "Assertion",
            (),
            {
                "subject": "alice@example.com",
                "attributes": {"agent_bom_role": "admin", "tenant_id": "tenant-alpha"},
                "role": "admin",
                "tenant_id": "tenant-alpha",
                "session_index": "session-1",
            },
        )(),
    )

    response = await enterprise.saml_login(SAMLLoginRequest(saml_response="assertion"))

    assert response["role"] == "admin"
    assert response["tenant_id"] == "tenant-alpha"
    assert response["subject"] == "alice@example.com"
    assert response["raw_key"].startswith("abom_")
    assert isolated_key_store.verify(response["raw_key"]) is not None


@pytest.mark.asyncio
async def test_saml_login_rejects_invalid_assertion(monkeypatch):
    def _raise_bad_saml(self, saml_response, relay_state=None):
        raise SAMLError("bad saml")

    monkeypatch.setattr("agent_bom.api.saml.SAMLConfig.verify_response", _raise_bad_saml)

    with pytest.raises(HTTPException) as error:
        await enterprise.saml_login(SAMLLoginRequest(saml_response="assertion"))

    assert error.value.status_code == 401
    assert error.value.detail == "bad saml"
