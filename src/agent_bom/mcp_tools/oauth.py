"""Read-only MCP resource-server authentication with an operator-owned issuer.

The issuer owns login, consent and renewable credentials. This module never
registers clients or issues tokens. Approved subjects share the process-bound
MCP tenant; it is not a multi-tenant token router.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlsplit

_ENV_NAMES = {
    "ISSUER": "AGENT_BOM_MCP_OAUTH_ISSUER",
    "AUDIENCE": "AGENT_BOM_MCP_OAUTH_AUDIENCE",
    "JWKS_URI": "AGENT_BOM_MCP_OAUTH_JWKS_URI",
    "SUBJECTS": "AGENT_BOM_MCP_OAUTH_SUBJECTS",
}


def oauth_configured() -> bool:
    return any(os.environ.get(name, "").strip() for name in _ENV_NAMES.values())


def _https_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("MCP OAuth URLs must be absolute HTTPS URLs without credentials, queries or fragments")
    return value


@dataclass(frozen=True)
class OAuthConfig:
    issuer: str
    audience: str
    jwks_uri: str
    subjects: frozenset[str]

    @classmethod
    def from_env(cls) -> OAuthConfig:
        values = {key: os.environ.get(name, "").strip() for key, name in _ENV_NAMES.items()}
        if not all(values.values()):
            raise ValueError("MCP OAuth requires ISSUER, AUDIENCE, JWKS_URI and SUBJECTS settings")
        subjects = frozenset(s.strip() for s in values["SUBJECTS"].split(",") if s.strip())
        if not subjects or "*" in subjects:
            raise ValueError("MCP OAuth requires explicit approved subjects; wildcards are not supported")
        issuer, jwks = _https_url(values["ISSUER"]), _https_url(values["JWKS_URI"])
        if urlsplit(issuer).netloc != urlsplit(jwks).netloc:
            raise ValueError("MCP OAuth JWKS must use the configured issuer origin")
        return cls(issuer, _https_url(values["AUDIENCE"]), jwks, subjects)


class OAuthTokenVerifier:
    """Verify signatures with cached, rotating public keys and bounded lifetimes."""

    def __init__(self, config: OAuthConfig):
        try:
            import jwt
        except ImportError as exc:
            raise ValueError("MCP OAuth requires agent-bom[oidc]") from exc
        self.config = config

        class TrustedKeys(jwt.PyJWKClient):
            _last_fetch = 0.0

            def fetch_data(self):
                import time

                import httpx

                # Unknown key IDs must not turn every rejected token into an
                # issuer request. A rotated key can be retried after this bound.
                now = time.monotonic()
                if now - self._last_fetch < 10:
                    raise ValueError("MCP OAuth key refresh is rate limited")
                self._last_fetch = now

                from agent_bom.security import validate_url

                validate_url(self.uri)
                # Never forward requests to redirects or token-selected URLs.
                with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
                    with client.stream("GET", self.uri) as response:
                        response.raise_for_status()
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            body.extend(chunk)
                            if len(body) > 262144:
                                raise ValueError("MCP OAuth JWKS exceeds size limit")
                import json

                data = json.loads(body)
                if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
                    raise ValueError("Invalid MCP OAuth JWKS")
                if self.jwk_set_cache is not None:
                    self.jwk_set_cache.put(cast(Any, data))
                return data

        self.keys = TrustedKeys(config.jwks_uri, cache_jwk_set=True, lifespan=300)
        # Serialize key refresh to keep one consistent cache across callers.
        self._lock = asyncio.Lock()

    def _verify(self, token: str):
        import time

        import jwt
        from mcp.server.auth.provider import AccessToken

        try:
            key = self.keys.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256", "ES256"],
                issuer=self.config.issuer,
                audience=self.config.audience,
                options={"require": ["iss", "aud", "sub", "iat", "exp"]},
            )
            issued, expires = claims["iat"], claims["exp"]
            if type(issued) is not int or type(expires) is not int or not 0 < expires - issued <= 3600:
                return None
            if expires <= time.time() or issued > time.time():
                return None
            if claims["sub"] not in self.config.subjects:
                return None
            scope = claims.get("scope")
            if not isinstance(scope, str) or "read" not in scope.split():
                return None
            # Identity and administrative claims cannot grant write authority.
            return AccessToken(
                token=token,
                client_id="oauth:" + claims["sub"],
                scopes=["read"],
                expires_at=expires,
                resource=self.config.audience,
            )
        except Exception:  # noqa: BLE001 — auth failures fail closed; never log token or remote exception
            return None

    async def verify_token(self, token: str):
        if not token or len(token) > 16384:
            return None
        async with self._lock:
            return await asyncio.to_thread(self._verify, token)
