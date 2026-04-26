"""Signed browser session cookies for the dashboard.

The cookie deliberately stores an HMAC-signed session envelope, not the raw API
key that was used for the one-time exchange.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

SESSION_COOKIE_NAME = "agent_bom_session"
CSRF_COOKIE_NAME = "agent_bom_csrf"
CSRF_HEADER_NAME = "x-agent-bom-csrf"

_logger = logging.getLogger(__name__)
_EPHEMERAL_SIGNING_KEY = secrets.token_bytes(32)
_REVOKED_SESSION_NONCES: dict[str, int] = {}
_REVOKED_LOCK = threading.Lock()


class BrowserSessionError(Exception):
    """Raised when a browser session token is absent, invalid, or expired."""


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _configured_api_replicas() -> int:
    raw = os.environ.get("AGENT_BOM_CONTROL_PLANE_REPLICAS", "").strip()
    if not raw:
        return 1
    try:
        return max(1, int(raw))
    except ValueError:
        _logger.warning("Invalid AGENT_BOM_CONTROL_PLANE_REPLICAS=%r; defaulting to 1", raw)
        return 1


def persistent_browser_session_signing_required() -> bool:
    """Clustered control planes need a stable key shared by every replica."""
    return _configured_api_replicas() > 1 or _env_flag("AGENT_BOM_REQUIRE_BROWSER_SESSION_SIGNING_KEY")


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _signing_key() -> bytes:
    configured = (os.environ.get("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY") or "").strip()
    if configured:
        return hashlib.pbkdf2_hmac(
            "sha256",
            configured.encode("utf-8"),
            b"agent-bom-browser-session-signing-key:v1",
            600_000,
            dklen=32,
        )
    if persistent_browser_session_signing_required():
        raise BrowserSessionError("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY is required for clustered browser-session auth")
    _logger.warning(
        "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY is not set; browser sessions use an ephemeral signing key "
        "and will be invalid after process restart"
    )
    return _EPHEMERAL_SIGNING_KEY


def create_browser_session_token(
    *,
    subject: str,
    role: str,
    tenant_id: str,
    auth_method: str,
    key_id: str | None = None,
    scopes: list[str] | None = None,
    max_age_seconds: int,
) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    csrf = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    payload: dict[str, Any] = {
        "v": 1,
        "sub": subject[:256],
        "role": role,
        "tenant_id": tenant_id,
        "auth_method": auth_method,
        "key_id": key_id,
        "scopes": scopes or [],
        "csrf_sha256": hashlib.sha256(f"{nonce}:{csrf}".encode("utf-8")).hexdigest(),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=max_age_seconds)).timestamp()),
        "nonce": nonce,
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encoded_payload = _b64encode(payload_bytes)
    signature = hmac.new(_signing_key(), encoded_payload.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded_payload}.{_b64encode(signature)}", csrf


def verify_browser_session_token(token: str) -> dict[str, Any]:
    if not token or "." not in token:
        raise BrowserSessionError("browser session cookie is missing or malformed")
    encoded_payload, encoded_signature = token.split(".", 1)
    expected = hmac.new(_signing_key(), encoded_payload.encode("ascii"), hashlib.sha256).digest()
    try:
        supplied = _b64decode(encoded_signature)
    except Exception as exc:  # noqa: BLE001
        raise BrowserSessionError("browser session signature is malformed") from exc
    if not hmac.compare_digest(supplied, expected):
        raise BrowserSessionError("browser session signature is invalid")
    try:
        payload = json.loads(_b64decode(encoded_payload).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise BrowserSessionError("browser session payload is invalid") from exc
    exp = int(payload.get("exp") or 0)
    if exp <= int(datetime.now(timezone.utc).timestamp()):
        raise BrowserSessionError("browser session is expired")
    nonce = str(payload.get("nonce") or "")
    with _REVOKED_LOCK:
        expires_at = _REVOKED_SESSION_NONCES.get(nonce)
        if expires_at is not None:
            if expires_at > int(datetime.now(timezone.utc).timestamp()):
                raise BrowserSessionError("browser session has been revoked")
            _REVOKED_SESSION_NONCES.pop(nonce, None)
    return payload


def verify_csrf(payload: dict[str, Any], csrf_cookie: str, csrf_header: str) -> bool:
    if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
        return False
    expected = str(payload.get("csrf_sha256") or "")
    nonce = str(payload.get("nonce") or "")
    actual = hashlib.sha256(f"{nonce}:{csrf_cookie}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(actual, expected)


def revoke_browser_session_token(token: str) -> bool:
    """Revoke a signed browser session nonce until its natural expiry."""
    try:
        payload = verify_browser_session_token(token)
    except BrowserSessionError:
        return False
    nonce = str(payload.get("nonce") or "")
    exp = int(payload.get("exp") or 0)
    if not nonce or exp <= int(datetime.now(timezone.utc).timestamp()):
        return False
    with _REVOKED_LOCK:
        now = int(datetime.now(timezone.utc).timestamp())
        expired = [key for key, expires_at in _REVOKED_SESSION_NONCES.items() if expires_at <= now]
        for key in expired:
            _REVOKED_SESSION_NONCES.pop(key, None)
        _REVOKED_SESSION_NONCES[nonce] = exp
    return True
