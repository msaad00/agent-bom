"""OAuth 2.1 Authorization Server for the MCP auth spec (broker AS).

Implements the subset of OAuth 2.1 + the MCP authorization spec that lets a
standard MCP client auto-discover and authenticate to agent-bom-brokered MCP
servers fronted by the gateway:

  * RFC 8414 authorization-server metadata
    (``/.well-known/oauth-authorization-server``)
  * RFC 7591 dynamic client registration (``/oauth/register``)
  * PKCE-required authorization-code grant (S256 only; OAuth 2.1 forbids the
    ``plain`` method and the implicit grant) at ``/oauth/authorize``
  * token endpoint (``authorization_code`` + ``client_credentials``) at
    ``/oauth/token``
  * JWKS endpoint for RS256 access-token validation (``/oauth/jwks.json``)

Access tokens are RS256 JWTs signed by a gateway-held key. The ``sub`` claim is
the agent/client identity and ``scope`` carries the granted OAuth scopes that
the per-tool-call scope mapping checks at the relay. The same JWTs validate
through :mod:`agent_bom.agent_identity` (JWKS path), so an issued access token
*is* the agent identity at the relay.

Security posture (fail-closed + bounded):
  * PKCE is mandatory for the code grant; ``code_challenge_method`` must be
    ``S256``. The ``none`` JWT algorithm is never issued.
  * Authorization codes are single-use, short-TTL, and bound to the client +
    redirect_uri + PKCE challenge.
  * Public clients (no secret) may only use the PKCE code grant; the
    ``client_credentials`` grant requires a registered confidential client and
    a verified secret.
  * Every store is bounded (LRU eviction) so a registration/code flood cannot
    exhaust memory.

This module mints and validates tokens entirely in-process; it performs no
outbound network calls. It is a deliberate, scoped auth-broker capability for
the gateway only — the wider product remains read-only by default.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Bounded store sizes — a registration / code flood evicts oldest entries
# rather than growing without limit.
_MAX_CLIENTS = 2048
_MAX_CODES = 4096

# Default lifetimes (seconds). Codes are short-lived (single-use); access
# tokens default to one hour. Both are clamped to sane bounds.
_DEFAULT_CODE_TTL = 60
_DEFAULT_TOKEN_TTL = 3600
_MAX_TOKEN_TTL = 24 * 3600

# RS256 only — OAuth 2.1 access tokens are signed with an asymmetric key so the
# resource server (the relay) can validate without the signing secret.
_SIGNING_ALG = "RS256"

# Grant types this AS supports.
_GRANT_AUTHZ_CODE = "authorization_code"
_GRANT_CLIENT_CREDENTIALS = "client_credentials"
_SUPPORTED_GRANTS = (_GRANT_AUTHZ_CODE, _GRANT_CLIENT_CREDENTIALS)


class OAuthError(Exception):
    """An OAuth protocol error with an RFC 6749 ``error`` code.

    ``status`` is the HTTP status the endpoint should return; ``error`` is the
    machine-readable code (e.g. ``invalid_request``, ``invalid_grant``).
    """

    def __init__(self, error: str, description: str = "", *, status: int = 400) -> None:
        super().__init__(description or error)
        self.error = error
        self.description = description
        self.status = status
        # Set for errors that must be reported by redirecting back to the client.
        self.redirect_location: str | None = None

    def to_dict(self) -> dict[str, str]:
        body = {"error": self.error}
        if self.description:
            body["error_description"] = self.description
        return body


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8 or 1
    return _b64url(value.to_bytes(length, "big"))


def _scope_set(scope: Any) -> set[str]:
    if not scope or not isinstance(scope, str):
        return set()
    return {s for s in scope.replace(",", " ").split() if s}


def _scope_str(scopes: set[str]) -> str:
    return " ".join(sorted(scopes))


# ── Signing key ──────────────────────────────────────────────────────────────


class OAuthSigningKey:
    """RSA signing key for access tokens, with a JWKS view for validation.

    Loads a PEM private key from ``AGENT_BOM_OAUTH_AS_PRIVATE_KEY_PEM`` when set
    (so issued tokens survive a restart and are shared across replicas); else
    generates an ephemeral RSA-2048 key and warns that tokens are invalidated on
    restart. The ``kid`` is the RFC 7638 JWK thumbprint so it is stable for a
    given key.
    """

    def __init__(self, private_pem: str | None = None) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        pem = private_pem if private_pem is not None else os.environ.get("AGENT_BOM_OAUTH_AS_PRIVATE_KEY_PEM", "").strip()
        if pem:
            self._private_key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
            self._ephemeral = False
        else:
            self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self._ephemeral = True
            logger.warning(
                "OAuth AS using an EPHEMERAL signing key: issued access tokens are invalidated on "
                "restart and are not shared across replicas. Set AGENT_BOM_OAUTH_AS_PRIVATE_KEY_PEM "
                "to a stable RSA private key for production."
            )
        self._public_key = self._private_key.public_key()
        nums = self._public_key.public_numbers()
        self._n = _b64url_uint(nums.n)
        self._e = _b64url_uint(nums.e)
        # RFC 7638 thumbprint over the canonical (lexicographically ordered) JWK.
        thumb_input = f'{{"e":"{self._e}","kty":"RSA","n":"{self._n}"}}'.encode("ascii")
        self.kid = _b64url(hashlib.sha256(thumb_input).digest())

    @property
    def ephemeral(self) -> bool:
        return self._ephemeral

    def sign(self, claims: dict[str, Any]) -> str:
        import jwt as pyjwt

        return pyjwt.encode(claims, self._private_pem(), algorithm=_SIGNING_ALG, headers={"kid": self.kid})

    def _private_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_jwk(self) -> dict[str, str]:
        return {"kty": "RSA", "use": "sig", "alg": _SIGNING_ALG, "kid": self.kid, "n": self._n, "e": self._e}

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        return {"keys": [self.public_jwk()]}

    def verify(self, token: str, *, issuer: str | None = None) -> dict[str, Any]:
        """Validate a token signed by this key. Raises on any failure."""
        import jwt as pyjwt

        options = {"require": ["exp", "iat"], "verify_aud": False}
        return pyjwt.decode(
            token,
            self._public_key,
            algorithms=[_SIGNING_ALG],
            issuer=issuer,
            options=options,
        )


# ── Registered clients + authorization codes ─────────────────────────────────


@dataclass
class RegisteredClient:
    """A dynamically-registered OAuth client (RFC 7591)."""

    client_id: str
    client_name: str = ""
    # SHA-256 hash of the client secret for confidential clients; empty for
    # public (PKCE-only) clients. The raw secret is returned once at register
    # time and never stored.
    client_secret_hash: str = ""
    redirect_uris: list[str] = field(default_factory=list)
    grant_types: list[str] = field(default_factory=lambda: [_GRANT_AUTHZ_CODE])
    scope: str = ""  # space-delimited allowed scopes ("" = no scope ceiling)
    token_endpoint_auth_method: str = "none"
    created_at: float = 0.0
    # Subject this client authenticates as. Defaults to the client_id so the
    # issued token's ``sub`` (the agent identity at the relay) is stable.
    subject: str = ""

    @property
    def is_confidential(self) -> bool:
        return bool(self.client_secret_hash)

    def allowed_scopes(self) -> set[str]:
        return _scope_set(self.scope)


@dataclass
class AuthorizationCode:
    """A single-use, PKCE-bound authorization code."""

    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    scope: str
    subject: str
    expires_at: float
    used: bool = False


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


# ── Authorization server ──────────────────────────────────────────────────────


class OAuthAuthorizationServer:
    """In-process OAuth 2.1 Authorization Server for the gateway broker.

    Thread-safe and bounded. ``issuer`` is the externally-reachable base URL of
    the gateway; when ``None`` it is derived per-request from the incoming
    request (so the AS works behind any host/proxy) and the first observed value
    is cached for token ``iss`` stability.
    """

    def __init__(
        self,
        *,
        issuer: str | None = None,
        signing_key: OAuthSigningKey | None = None,
        token_ttl_seconds: int = _DEFAULT_TOKEN_TTL,
        code_ttl_seconds: int = _DEFAULT_CODE_TTL,
        supported_scopes: list[str] | None = None,
    ) -> None:
        self._configured_issuer = issuer.rstrip("/") if issuer else None
        self._observed_issuer: str | None = None
        self.signing_key = signing_key or OAuthSigningKey()
        self.token_ttl_seconds = max(60, min(int(token_ttl_seconds), _MAX_TOKEN_TTL))
        self.code_ttl_seconds = max(10, min(int(code_ttl_seconds), 600))
        self.supported_scopes = list(supported_scopes or [])
        self._clients: OrderedDict[str, RegisteredClient] = OrderedDict()
        self._codes: OrderedDict[str, AuthorizationCode] = OrderedDict()
        self._lock = threading.Lock()

    # -- issuer resolution -----------------------------------------------------

    def resolve_issuer(self, request_base_url: str | None = None) -> str:
        if self._configured_issuer:
            return self._configured_issuer
        if self._observed_issuer:
            return self._observed_issuer
        base = (request_base_url or "").rstrip("/")
        if base:
            with self._lock:
                if self._observed_issuer is None:
                    self._observed_issuer = base
            return self._observed_issuer or base
        return "http://localhost"

    # -- RFC 8414 metadata -----------------------------------------------------

    def metadata(self, request_base_url: str | None = None) -> dict[str, Any]:
        issuer = self.resolve_issuer(request_base_url)
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth/authorize",
            "token_endpoint": f"{issuer}/oauth/token",
            "registration_endpoint": f"{issuer}/oauth/register",
            "jwks_uri": f"{issuer}/oauth/jwks.json",
            "scopes_supported": list(self.supported_scopes),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": list(_SUPPORTED_GRANTS),
            "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_signing_alg_values_supported": [_SIGNING_ALG],
        }

    def jwks(self) -> dict[str, Any]:
        return self.signing_key.jwks()

    # -- RFC 7591 dynamic client registration ----------------------------------

    def register_client(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise OAuthError("invalid_client_metadata", "registration body must be a JSON object")

        redirect_uris = payload.get("redirect_uris", [])
        if redirect_uris is None:
            redirect_uris = []
        if not isinstance(redirect_uris, list) or not all(isinstance(u, str) for u in redirect_uris):
            raise OAuthError("invalid_redirect_uri", "redirect_uris must be a list of strings")
        # Reject non-loopback plaintext redirect URIs (OAuth 2.1 §authorization).
        for uri in redirect_uris:
            self._validate_redirect_uri(uri)

        grant_types_raw = payload.get("grant_types") or [_GRANT_AUTHZ_CODE]
        if not isinstance(grant_types_raw, list):
            raise OAuthError("invalid_client_metadata", "grant_types must be a list")
        grant_types = [g for g in grant_types_raw if g in _SUPPORTED_GRANTS]
        if not grant_types:
            raise OAuthError("invalid_client_metadata", f"no supported grant_types (supported: {', '.join(_SUPPORTED_GRANTS)})")
        if _GRANT_AUTHZ_CODE in grant_types and not redirect_uris:
            raise OAuthError("invalid_redirect_uri", "authorization_code clients must register at least one redirect_uri")

        auth_method = str(payload.get("token_endpoint_auth_method", "none"))
        confidential = auth_method != "none" or _GRANT_CLIENT_CREDENTIALS in grant_types

        scope = str(payload.get("scope", "") or "")
        # When the AS advertises a scope ceiling, a client cannot register scopes
        # outside it.
        if self.supported_scopes:
            requested = _scope_set(scope)
            unknown = requested - set(self.supported_scopes)
            if unknown:
                raise OAuthError("invalid_scope", f"unsupported scope(s): {', '.join(sorted(unknown))}")

        client_id = f"abc_{secrets.token_hex(12)}"
        raw_secret = ""
        secret_hash = ""
        if confidential:
            raw_secret = secrets.token_urlsafe(32)
            secret_hash = _hash_secret(raw_secret)

        subject = str(payload.get("subject") or payload.get("software_id") or client_id)
        client = RegisteredClient(
            client_id=client_id,
            client_name=str(payload.get("client_name", "") or "")[:200],
            client_secret_hash=secret_hash,
            redirect_uris=list(redirect_uris),
            grant_types=grant_types,
            scope=scope,
            token_endpoint_auth_method=auth_method if confidential else "none",
            created_at=time.time(),
            subject=subject[:200],
        )
        with self._lock:
            self._clients[client_id] = client
            self._evict(self._clients, _MAX_CLIENTS)

        response: dict[str, Any] = {
            "client_id": client_id,
            "client_id_issued_at": int(client.created_at),
            "redirect_uris": client.redirect_uris,
            "grant_types": client.grant_types,
            "token_endpoint_auth_method": client.token_endpoint_auth_method,
            "scope": client.scope,
            "response_types": ["code"] if _GRANT_AUTHZ_CODE in grant_types else [],
        }
        if client.client_name:
            response["client_name"] = client.client_name
        if raw_secret:
            response["client_secret"] = raw_secret
            response["client_secret_expires_at"] = 0  # non-expiring
        return response

    def get_client(self, client_id: str) -> RegisteredClient | None:
        with self._lock:
            return self._clients.get(client_id)

    # -- authorization endpoint (PKCE-required code grant) ---------------------

    def authorize(self, params: dict[str, Any]) -> str:
        """Validate an authorization request and return a redirect URL with a code.

        This is a machine-to-machine broker: a registered client that presents a
        valid PKCE challenge is granted an authorization code immediately (no
        interactive login UI). The code is bound to the client, redirect_uri and
        PKCE challenge, and is single-use.

        Raises :class:`OAuthError`. Errors that must be redirected back to the
        client carry ``redirect_location`` (open-redirector protection: invalid
        client / unregistered redirect_uri never redirect).
        """
        response_type = str(params.get("response_type", ""))
        client_id = str(params.get("client_id", ""))
        client = self.get_client(client_id)
        if client is None:
            raise OAuthError("invalid_client", "unknown client_id", status=400)

        redirect_uri = str(params.get("redirect_uri", ""))
        if not redirect_uri:
            if len(client.redirect_uris) == 1:
                redirect_uri = client.redirect_uris[0]
            else:
                raise OAuthError("invalid_request", "redirect_uri is required", status=400)
        if redirect_uri not in client.redirect_uris:
            # Never redirect to an unregistered URI.
            raise OAuthError("invalid_request", "redirect_uri does not match a registered value", status=400)

        state = str(params.get("state", "") or "")

        # From here, errors redirect back to the validated redirect_uri.
        if response_type != "code":
            raise self._redirect_error(redirect_uri, "unsupported_response_type", "only response_type=code is supported", state)
        if _GRANT_AUTHZ_CODE not in client.grant_types:
            raise self._redirect_error(redirect_uri, "unauthorized_client", "client may not use the authorization_code grant", state)

        code_challenge = str(params.get("code_challenge", "") or "")
        code_challenge_method = str(params.get("code_challenge_method", "") or "")
        if not code_challenge:
            raise self._redirect_error(redirect_uri, "invalid_request", "PKCE code_challenge is required", state)
        if code_challenge_method != "S256":
            # OAuth 2.1 forbids "plain"; require S256 explicitly.
            raise self._redirect_error(redirect_uri, "invalid_request", "code_challenge_method must be S256", state)

        requested_scopes = _scope_set(params.get("scope"))
        try:
            granted_scopes = self._resolve_grant_scopes(client, requested_scopes)
        except OAuthError as exc:
            raise self._redirect_error(redirect_uri, exc.error, exc.description, state) from exc

        code = f"abco_{secrets.token_urlsafe(24)}"
        record = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=_scope_str(granted_scopes),
            subject=client.subject or client_id,
            expires_at=time.time() + self.code_ttl_seconds,
        )
        with self._lock:
            self._codes[code] = record
            self._evict(self._codes, _MAX_CODES)

        sep = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{sep}code={code}"
        if state:
            from urllib.parse import quote

            location += f"&state={quote(state, safe='')}"
        return location

    # -- token endpoint --------------------------------------------------------

    def token(
        self,
        form: dict[str, Any],
        *,
        basic_auth: tuple[str, str] | None = None,
        request_base_url: str | None = None,
    ) -> dict[str, Any]:
        grant_type = str(form.get("grant_type", ""))
        if grant_type == _GRANT_AUTHZ_CODE:
            return self._token_authorization_code(form, basic_auth=basic_auth, request_base_url=request_base_url)
        if grant_type == _GRANT_CLIENT_CREDENTIALS:
            return self._token_client_credentials(form, basic_auth=basic_auth, request_base_url=request_base_url)
        raise OAuthError("unsupported_grant_type", f"grant_type must be one of {', '.join(_SUPPORTED_GRANTS)}")

    def _token_authorization_code(
        self, form: dict[str, Any], *, basic_auth: tuple[str, str] | None, request_base_url: str | None
    ) -> dict[str, Any]:
        code = str(form.get("code", ""))
        client_id, _client = self._authenticate_client(form, basic_auth, require_secret=False)

        with self._lock:
            record = self._codes.get(code)
            already_used = bool(record and record.used)
            # Single-use: mark used + drop on first valid presentation so a
            # replay cannot mint a second token.
            if record is not None:
                record.used = True
                self._codes.pop(code, None)

        if record is None or already_used:
            raise OAuthError("invalid_grant", "authorization code is invalid")
        if record.client_id != client_id:
            raise OAuthError("invalid_grant", "authorization code was issued to a different client")
        if time.time() > record.expires_at:
            raise OAuthError("invalid_grant", "authorization code expired")
        redirect_uri = str(form.get("redirect_uri", ""))
        if redirect_uri and redirect_uri != record.redirect_uri:
            raise OAuthError("invalid_grant", "redirect_uri mismatch")

        # PKCE verification (S256): SHA-256(verifier) b64url == stored challenge.
        verifier = str(form.get("code_verifier", ""))
        if not verifier:
            raise OAuthError("invalid_request", "code_verifier is required (PKCE)")
        computed = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        if not secrets.compare_digest(computed, record.code_challenge):
            raise OAuthError("invalid_grant", "PKCE verification failed")

        return self._issue_access_token(
            subject=record.subject,
            client_id=client_id,
            scopes=_scope_set(record.scope),
            request_base_url=request_base_url,
        )

    def _token_client_credentials(
        self, form: dict[str, Any], *, basic_auth: tuple[str, str] | None, request_base_url: str | None
    ) -> dict[str, Any]:
        client_id, client = self._authenticate_client(form, basic_auth, require_secret=True)
        if _GRANT_CLIENT_CREDENTIALS not in client.grant_types:
            raise OAuthError("unauthorized_client", "client may not use the client_credentials grant")
        requested = _scope_set(form.get("scope"))
        granted = self._resolve_grant_scopes(client, requested)
        return self._issue_access_token(
            subject=client.subject or client_id,
            client_id=client_id,
            scopes=granted,
            request_base_url=request_base_url,
        )

    def _issue_access_token(
        self, *, subject: str, client_id: str, scopes: set[str], request_base_url: str | None
    ) -> dict[str, Any]:
        now = int(time.time())
        issuer = self.resolve_issuer(request_base_url)
        claims = {
            "iss": issuer,
            "sub": subject,
            "aud": "agent-bom-gateway",
            "client_id": client_id,
            "iat": now,
            "exp": now + self.token_ttl_seconds,
            "jti": secrets.token_hex(16),
            "scope": _scope_str(scopes),
        }
        access_token = self.signing_key.sign(claims)
        response: dict[str, Any] = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.token_ttl_seconds,
        }
        if scopes:
            response["scope"] = _scope_str(scopes)
        return response

    # -- token validation (used by the relay, in-process) ----------------------

    def validate_token(self, token: str) -> dict[str, Any] | None:
        """Return verified claims for an AS-issued token, or None if invalid.

        Verifies the RS256 signature against this server's key and enforces
        ``exp``. Never raises — an invalid/expired/foreign token returns None so
        the caller fails closed without leaking the reason to the client.
        """
        if not token or token.count(".") != 2:
            return None
        try:
            return self.signing_key.verify(token)
        except Exception:  # noqa: BLE001 — any verification failure → not our token
            return None

    # -- helpers ---------------------------------------------------------------

    def _authenticate_client(
        self, form: dict[str, Any], basic_auth: tuple[str, str] | None, *, require_secret: bool
    ) -> tuple[str, RegisteredClient]:
        client_id = ""
        client_secret = ""
        if basic_auth is not None:
            client_id, client_secret = basic_auth
        if not client_id:
            client_id = str(form.get("client_id", ""))
        if not client_secret:
            client_secret = str(form.get("client_secret", ""))

        client = self.get_client(client_id)
        if client is None:
            raise OAuthError("invalid_client", "unknown client_id", status=401)

        if client.is_confidential:
            if not client_secret or not secrets.compare_digest(_hash_secret(client_secret), client.client_secret_hash):
                raise OAuthError("invalid_client", "client authentication failed", status=401)
        elif require_secret:
            raise OAuthError("invalid_client", "client_credentials requires a confidential client", status=401)
        return client_id, client

    def _resolve_grant_scopes(self, client: RegisteredClient, requested: set[str]) -> set[str]:
        ceiling = client.allowed_scopes()
        if requested:
            if ceiling:
                unknown = requested - ceiling
                if unknown:
                    raise OAuthError("invalid_scope", f"requested scope(s) outside client grant: {', '.join(sorted(unknown))}")
                return requested
            return requested
        return set(ceiling)

    def _validate_redirect_uri(self, uri: str) -> None:
        from urllib.parse import urlparse

        parsed = urlparse(uri)
        if parsed.scheme == "https":
            return
        if parsed.scheme == "http":
            host = (parsed.hostname or "").lower()
            if host in ("localhost", "127.0.0.1", "::1"):
                return
            raise OAuthError("invalid_redirect_uri", "http redirect_uri is only allowed for loopback hosts")
        # Custom/native schemes (e.g. an app callback) are permitted but must be
        # absolute with a scheme.
        if parsed.scheme and (parsed.netloc or parsed.path):
            return
        raise OAuthError("invalid_redirect_uri", f"invalid redirect_uri: {uri!r}")

    @staticmethod
    def _redirect_error(redirect_uri: str, error: str, description: str, state: str) -> OAuthError:
        from urllib.parse import quote

        sep = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{sep}error={quote(error, safe='')}&error_description={quote(description, safe='')}"
        if state:
            location += f"&state={quote(state, safe='')}"
        exc = OAuthError(error, description, status=302)
        exc.redirect_location = location
        return exc

    @staticmethod
    def _evict(store: OrderedDict, max_size: int) -> None:
        while len(store) > max_size:
            store.popitem(last=False)


def _basic_auth_from_header(authorization: str | None) -> tuple[str, str] | None:
    """Parse an HTTP Basic ``Authorization`` header into (client_id, secret)."""
    if not authorization or not authorization.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(authorization[6:].strip()).decode("utf-8")
    except Exception:  # noqa: BLE001
        return None
    if ":" not in decoded:
        return None
    client_id, secret = decoded.split(":", 1)
    return client_id, secret


def build_oauth_as_router(server: OAuthAuthorizationServer):
    """Build a FastAPI router exposing the OAuth 2.1 AS endpoints.

    Mounted on the gateway app so a standard MCP client can discover the AS via
    ``/.well-known/oauth-authorization-server`` and complete the PKCE flow.
    """
    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse, RedirectResponse

    # The module uses ``from __future__ import annotations`` so route-handler
    # type hints are strings; FastAPI resolves them against the module globals.
    # Expose the FastAPI symbols there so ``request: Request`` resolves to the
    # real type (otherwise FastAPI treats it as a query parameter).
    globals().update({"Request": Request, "JSONResponse": JSONResponse, "RedirectResponse": RedirectResponse})

    router = APIRouter()

    def _request_base_url(request: Request) -> str:
        # Honor a trusted reverse proxy's forwarded host/proto when present.
        proto = (request.headers.get("x-forwarded-proto", "") or request.url.scheme).split(",")[0].strip()
        host = (request.headers.get("x-forwarded-host", "") or request.headers.get("host", "")).split(",")[0].strip()
        if host:
            return f"{proto}://{host}"
        return str(request.base_url).rstrip("/")

    @router.get("/.well-known/oauth-authorization-server")
    async def authorization_server_metadata(request: Request) -> JSONResponse:
        return JSONResponse(server.metadata(_request_base_url(request)))

    @router.get("/oauth/jwks.json")
    async def jwks(_request: Request) -> JSONResponse:
        return JSONResponse(server.jwks())

    @router.post("/oauth/register")
    async def register(request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"error": "invalid_client_metadata", "error_description": "body must be JSON"}, status_code=400)
        try:
            registered = server.register_client(payload if isinstance(payload, dict) else {})
        except OAuthError as exc:
            return JSONResponse(exc.to_dict(), status_code=exc.status)
        return JSONResponse(registered, status_code=201)

    @router.get("/oauth/authorize")
    async def authorize(request: Request):
        params = dict(request.query_params)
        try:
            location = server.authorize(params)
        except OAuthError as exc:
            if exc.redirect_location:
                return RedirectResponse(exc.redirect_location, status_code=302)
            return JSONResponse(exc.to_dict(), status_code=exc.status)
        return RedirectResponse(location, status_code=302)

    @router.post("/oauth/token")
    async def token(request: Request) -> JSONResponse:
        form = dict(await request.form())
        basic_auth = _basic_auth_from_header(request.headers.get("authorization"))
        try:
            issued = server.token(form, basic_auth=basic_auth, request_base_url=_request_base_url(request))
        except OAuthError as exc:
            headers = {"WWW-Authenticate": "Basic"} if exc.status == 401 else None
            return JSONResponse(exc.to_dict(), status_code=exc.status, headers=headers)
        # Tokens must never be cached (OAuth 2.1 §token-response).
        return JSONResponse(issued, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    return router


__all__ = [
    "AuthorizationCode",
    "OAuthAuthorizationServer",
    "OAuthError",
    "OAuthSigningKey",
    "RegisteredClient",
    "build_oauth_as_router",
]
