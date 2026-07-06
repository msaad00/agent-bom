"""OIDC discovery shim for MCP clients and legacy enterprise IdPs.

Many MCP OAuth clients require ``/.well-known/openid-configuration`` at the
issuer URL. Buyer IdPs often issue valid tokens but do not publish discovery
metadata in the shape those clients expect. This module serves a **static**
OpenID Provider Metadata document that points at manually configured upstream
endpoints — a read-only interop shim, not a replacement IdP or OAuth broker.

Configure via ``AGENT_BOM_OIDC_DISCOVERY_SHIM_JSON``::

    {
      "issuer": "https://mcp-auth.example.com",
      "authorization_endpoint": "https://idp.example.com/oauth2/v1/authorize",
      "token_endpoint": "https://idp.example.com/oauth2/v1/token",
      "jwks_uri": "https://idp.example.com/oauth2/v1/keys"
    }

Optional fields: ``userinfo_endpoint``, ``scopes_supported``,
``response_types_supported``, ``grant_types_supported``,
``code_challenge_methods_supported``.

Mount on the gateway (or any FastAPI app) with
:func:`build_oidc_discovery_shim_router`. The route is intentionally
unauthenticated — it only publishes public IdP metadata.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

# Minimum keys MCP OAuth / OIDC discovery clients expect.
_REQUIRED_DISCOVERY_KEYS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
)


class OIDCDiscoveryShimError(ValueError):
    """Invalid shim configuration or discovery document."""


@dataclass(frozen=True)
class OIDCDiscoveryShimConfig:
    """Manual OIDC endpoint wiring for a discovery shim."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    scopes_supported: tuple[str, ...] = ()
    response_types_supported: tuple[str, ...] = ("code",)
    grant_types_supported: tuple[str, ...] = ("authorization_code", "refresh_token")
    code_challenge_methods_supported: tuple[str, ...] = ("S256",)
    subject_types_supported: tuple[str, ...] = ("public",)
    id_token_signing_alg_values_supported: tuple[str, ...] = ("RS256",)

    def __post_init__(self) -> None:
        for label, value in (
            ("issuer", self.issuer),
            ("authorization_endpoint", self.authorization_endpoint),
            ("token_endpoint", self.token_endpoint),
            ("jwks_uri", self.jwks_uri),
        ):
            if not isinstance(value, str) or not value.strip():
                raise OIDCDiscoveryShimError(f"{label} must be a non-empty string")
        if self.userinfo_endpoint is not None and not self.userinfo_endpoint.strip():
            raise OIDCDiscoveryShimError("userinfo_endpoint must be omitted or a non-empty string")

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> OIDCDiscoveryShimConfig:
        if not isinstance(payload, dict):
            raise OIDCDiscoveryShimError("shim config must be a JSON object")

        def _req(key: str) -> str:
            value = payload.get(key)
            if not isinstance(value, str) or not value.strip():
                raise OIDCDiscoveryShimError(f"missing or invalid {key!r}")
            return value.strip()

        def _opt_str(key: str) -> str | None:
            value = payload.get(key)
            if value is None:
                return None
            if not isinstance(value, str) or not value.strip():
                raise OIDCDiscoveryShimError(f"invalid optional field {key!r}")
            return value.strip()

        def _opt_str_tuple(key: str, default: tuple[str, ...]) -> tuple[str, ...]:
            value = payload.get(key)
            if value is None:
                return default
            if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
                raise OIDCDiscoveryShimError(f"{key} must be a list of non-empty strings")
            return tuple(item.strip() for item in value)

        return cls(
            issuer=_req("issuer"),
            authorization_endpoint=_req("authorization_endpoint"),
            token_endpoint=_req("token_endpoint"),
            jwks_uri=_req("jwks_uri"),
            userinfo_endpoint=_opt_str("userinfo_endpoint"),
            scopes_supported=_opt_str_tuple("scopes_supported", ()),
            response_types_supported=_opt_str_tuple("response_types_supported", ("code",)),
            grant_types_supported=_opt_str_tuple("grant_types_supported", ("authorization_code", "refresh_token")),
            code_challenge_methods_supported=_opt_str_tuple("code_challenge_methods_supported", ("S256",)),
            subject_types_supported=_opt_str_tuple("subject_types_supported", ("public",)),
            id_token_signing_alg_values_supported=_opt_str_tuple("id_token_signing_alg_values_supported", ("RS256",)),
        )

    @classmethod
    def from_env(cls, *, env_var: str = "AGENT_BOM_OIDC_DISCOVERY_SHIM_JSON") -> OIDCDiscoveryShimConfig | None:
        raw = os.environ.get(env_var, "").strip()
        if not raw:
            return None
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OIDCDiscoveryShimError(f"{env_var} must be valid JSON") from exc
        return cls.from_mapping(payload)


def build_openid_configuration(config: OIDCDiscoveryShimConfig) -> dict[str, Any]:
    """Build an OpenID Provider Metadata document from manual endpoint wiring."""
    doc: dict[str, Any] = {
        "issuer": config.issuer.rstrip("/"),
        "authorization_endpoint": config.authorization_endpoint,
        "token_endpoint": config.token_endpoint,
        "jwks_uri": config.jwks_uri,
        "response_types_supported": list(config.response_types_supported),
        "subject_types_supported": list(config.subject_types_supported),
        "id_token_signing_alg_values_supported": list(config.id_token_signing_alg_values_supported),
        "grant_types_supported": list(config.grant_types_supported),
        "code_challenge_methods_supported": list(config.code_challenge_methods_supported),
    }
    if config.userinfo_endpoint:
        doc["userinfo_endpoint"] = config.userinfo_endpoint
    if config.scopes_supported:
        doc["scopes_supported"] = list(config.scopes_supported)
    validate_oidc_discovery_document(doc)
    return doc


def validate_oidc_discovery_document(doc: dict[str, Any]) -> None:
    """Validate that ``doc`` satisfies MCP/OIDC discovery client expectations."""
    if not isinstance(doc, dict):
        raise OIDCDiscoveryShimError("discovery document must be a JSON object")
    missing = [key for key in _REQUIRED_DISCOVERY_KEYS if key not in doc]
    if missing:
        raise OIDCDiscoveryShimError(f"discovery document missing required keys: {', '.join(missing)}")
    for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = doc.get(key)
        if not isinstance(value, str) or not value.strip():
            raise OIDCDiscoveryShimError(f"{key} must be a non-empty string")
    for list_key in (
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    ):
        value = doc.get(list_key)
        if not isinstance(value, list) or not value:
            raise OIDCDiscoveryShimError(f"{list_key} must be a non-empty list")


def build_oidc_discovery_shim_router(config: OIDCDiscoveryShimConfig):
    """Expose ``/.well-known/openid-configuration`` for the shim issuer."""
    from fastapi import APIRouter
    from fastapi.responses import JSONResponse

    router = APIRouter()
    document = build_openid_configuration(config)

    @router.get("/.well-known/openid-configuration")
    async def openid_configuration() -> JSONResponse:
        return JSONResponse(
            document,
            headers={"Cache-Control": "public, max-age=300"},
        )

    return router


__all__ = [
    "OIDCDiscoveryShimConfig",
    "OIDCDiscoveryShimError",
    "build_oidc_discovery_shim_router",
    "build_openid_configuration",
    "validate_oidc_discovery_document",
]
