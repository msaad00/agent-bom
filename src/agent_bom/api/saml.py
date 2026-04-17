"""SAML SSO assertion verification for enterprise self-hosted control planes.

This module implements a narrow SAML contract that fits the existing
agent-bom control-plane auth model:

- the IdP posts a SAMLResponse to the control plane
- agent-bom verifies the assertion against operator-supplied SAML metadata
- the verified subject is mapped to the same role/tenant model used by OIDC
- the control plane returns a short-lived API key that the UI/API already knows
  how to enforce, audit, expire, and scope by tenant

Configuration via environment variables::

    AGENT_BOM_SAML_IDP_ENTITY_ID="https://idp.example.com/metadata"
    AGENT_BOM_SAML_IDP_SSO_URL="https://idp.example.com/sso"
    AGENT_BOM_SAML_IDP_X509_CERT="-----BEGIN CERTIFICATE-----..."
    AGENT_BOM_SAML_SP_ENTITY_ID="https://agent-bom.example.com/saml/metadata"
    AGENT_BOM_SAML_SP_ACS_URL="https://agent-bom.example.com/v1/auth/saml/login"
    AGENT_BOM_SAML_ROLE_ATTRIBUTE="agent_bom_role"
    AGENT_BOM_SAML_TENANT_ATTRIBUTE="tenant_id"
    AGENT_BOM_SAML_REQUIRE_ROLE_ATTRIBUTE="1"
    AGENT_BOM_SAML_REQUIRE_TENANT_ATTRIBUTE="1"
    AGENT_BOM_SAML_SESSION_TTL_SECONDS="3600"
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from agent_bom.api.oidc import claims_have_role_signal, claims_to_role, claims_to_tenant


class SAMLError(Exception):
    """Raised when SAML configuration or assertion verification fails."""


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes"}


def _check_saml_support() -> None:
    try:
        import onelogin.saml2.auth  # noqa: F401
        import onelogin.saml2.settings  # noqa: F401
    except ImportError as exc:
        raise SAMLError("SAML support requires python3-saml: pip install 'agent-bom[saml]'") from exc


def _normalize_saml_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in attributes.items():
        if isinstance(value, list):
            cleaned = [str(v) for v in value if str(v).strip()]
            if not cleaned:
                continue
            if key in {"roles", "groups", "permissions"}:
                normalized[key] = cleaned
            else:
                normalized[key] = cleaned[0] if len(cleaned) == 1 else cleaned
        elif value not in (None, ""):
            normalized[key] = str(value)
    return normalized


def saml_attributes_have_role_signal(attributes: dict[str, Any], role_attribute: str = "agent_bom_role") -> bool:
    claims = _normalize_saml_attributes(attributes)
    return claims_have_role_signal(claims, role_attribute)


def saml_attributes_to_role(attributes: dict[str, Any], role_attribute: str = "agent_bom_role") -> str:
    claims = _normalize_saml_attributes(attributes)
    return claims_to_role(claims, role_attribute)


def saml_attributes_to_tenant(attributes: dict[str, Any], tenant_attribute: str = "tenant_id") -> str | None:
    claims = _normalize_saml_attributes(attributes)
    return claims_to_tenant(claims, tenant_attribute)


@dataclass
class SAMLAssertion:
    """Verified SAML assertion mapped to the agent-bom auth model."""

    subject: str
    attributes: dict[str, Any]
    role: str
    tenant_id: str
    session_index: str | None = None


def _build_request_context(acs_url: str, saml_response: str, relay_state: str | None = None) -> dict[str, Any]:
    parsed = urlparse(acs_url)
    if not parsed.scheme or not parsed.netloc:
        raise SAMLError("AGENT_BOM_SAML_SP_ACS_URL must be a fully-qualified URL")
    is_https = parsed.scheme.lower() == "https"
    port = parsed.port or (443 if is_https else 80)
    post_data = {"SAMLResponse": saml_response}
    if relay_state:
        post_data["RelayState"] = relay_state
    return {
        "https": "on" if is_https else "off",
        "http_host": parsed.hostname or "",
        "server_port": str(port),
        "script_name": parsed.path or "/v1/auth/saml/login",
        "get_data": {},
        "post_data": post_data,
    }


def _build_saml_auth(request_context: dict[str, Any], settings: dict[str, Any]):
    _check_saml_support()
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    return OneLogin_Saml2_Auth(request_context, old_settings=settings)


@dataclass
class SAMLConfig:
    """SAML configuration loaded from environment variables."""

    idp_entity_id: str = ""
    idp_sso_url: str = ""
    idp_x509_cert: str = ""
    sp_entity_id: str = ""
    sp_acs_url: str = ""
    role_attribute: str = "agent_bom_role"
    tenant_attribute: str = "tenant_id"
    require_role_attribute: bool = False
    require_tenant_attribute: bool = False
    session_ttl_seconds: int = 3600

    def __post_init__(self) -> None:
        if not self.idp_entity_id:
            self.idp_entity_id = os.environ.get("AGENT_BOM_SAML_IDP_ENTITY_ID", "")
        if not self.idp_sso_url:
            self.idp_sso_url = os.environ.get("AGENT_BOM_SAML_IDP_SSO_URL", "")
        if not self.idp_x509_cert:
            self.idp_x509_cert = os.environ.get("AGENT_BOM_SAML_IDP_X509_CERT", "")
        if not self.sp_entity_id:
            self.sp_entity_id = os.environ.get("AGENT_BOM_SAML_SP_ENTITY_ID", "")
        if not self.sp_acs_url:
            self.sp_acs_url = os.environ.get("AGENT_BOM_SAML_SP_ACS_URL", "")
        self.role_attribute = self.role_attribute or os.environ.get("AGENT_BOM_SAML_ROLE_ATTRIBUTE", "agent_bom_role")
        self.tenant_attribute = self.tenant_attribute or os.environ.get("AGENT_BOM_SAML_TENANT_ATTRIBUTE", "tenant_id")
        if not self.require_role_attribute:
            self.require_role_attribute = _env_flag("AGENT_BOM_SAML_REQUIRE_ROLE_ATTRIBUTE")
        if not self.require_tenant_attribute:
            self.require_tenant_attribute = _env_flag("AGENT_BOM_SAML_REQUIRE_TENANT_ATTRIBUTE")
        if self.session_ttl_seconds == 3600:
            self.session_ttl_seconds = int(os.environ.get("AGENT_BOM_SAML_SESSION_TTL_SECONDS", "3600"))

    @property
    def enabled(self) -> bool:
        return bool(self.idp_entity_id and self.idp_sso_url and self.idp_x509_cert and self.sp_entity_id and self.sp_acs_url)

    def settings_dict(self) -> dict[str, Any]:
        if not self.enabled:
            raise SAMLError(
                "SAML is not configured (set AGENT_BOM_SAML_IDP_ENTITY_ID, "
                "AGENT_BOM_SAML_IDP_SSO_URL, AGENT_BOM_SAML_IDP_X509_CERT, "
                "AGENT_BOM_SAML_SP_ENTITY_ID, and AGENT_BOM_SAML_SP_ACS_URL)"
            )
        return {
            "strict": True,
            "debug": False,
            "sp": {
                "entityId": self.sp_entity_id,
                "assertionConsumerService": {
                    "url": self.sp_acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "x509cert": "",
                "privateKey": "",
            },
            "idp": {
                "entityId": self.idp_entity_id,
                "singleSignOnService": {
                    "url": self.idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": self.idp_x509_cert,
            },
            "security": {
                "authnRequestsSigned": False,
                "logoutRequestSigned": False,
                "logoutResponseSigned": False,
                "signMetadata": False,
                "wantMessagesSigned": True,
                "wantAssertionsSigned": True,
                "wantAssertionsEncrypted": False,
                "requestedAuthnContext": False,
            },
        }

    def metadata_xml(self) -> str:
        _check_saml_support()
        from onelogin.saml2.settings import OneLogin_Saml2_Settings

        settings = OneLogin_Saml2_Settings(self.settings_dict(), custom_base_path=None)
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)
        if errors:
            raise SAMLError(f"Invalid generated SAML metadata: {', '.join(errors)}")
        return metadata

    def verify_response(self, saml_response: str, relay_state: str | None = None) -> SAMLAssertion:
        if not saml_response.strip():
            raise SAMLError("SAMLResponse is required")
        request_context = _build_request_context(self.sp_acs_url, saml_response, relay_state)
        auth = _build_saml_auth(request_context, self.settings_dict())
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            reason = getattr(auth, "get_last_error_reason", lambda: "")() or ", ".join(errors)
            raise SAMLError(f"SAML assertion validation failed: {reason}")
        if not auth.is_authenticated():
            raise SAMLError("SAML assertion did not authenticate a subject")

        attributes = auth.get_attributes() or {}
        if self.require_role_attribute and not saml_attributes_have_role_signal(attributes, self.role_attribute):
            raise SAMLError(f"SAML assertion missing required role attribute '{self.role_attribute}'")
        role = saml_attributes_to_role(attributes, self.role_attribute)
        tenant_id = saml_attributes_to_tenant(attributes, self.tenant_attribute)
        if tenant_id is None:
            if self.require_tenant_attribute:
                raise SAMLError(f"SAML assertion missing required tenant attribute '{self.tenant_attribute}'")
            tenant_id = "default"
        subject = auth.get_nameid() or auth.get_nameid_format() or "saml-user"
        return SAMLAssertion(
            subject=str(subject),
            attributes=_normalize_saml_attributes(attributes),
            role=role,
            tenant_id=str(tenant_id),
            session_index=auth.get_session_index() or None,
        )

    @classmethod
    def from_env(cls) -> "SAMLConfig":
        return cls()
