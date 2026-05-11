"""Shared audit-chain integrity helpers."""

from __future__ import annotations

import json
import logging
import os
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

_logger = logging.getLogger(__name__)
_AUDIT_CHAIN_EPHEMERAL_KEY: bytes | None = None


def _env_truthy(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def audit_chain_key() -> bytes:
    """Return the operator audit-chain key.

    Development runs may use a per-process ephemeral key, but production can
    opt into fail-closed startup with AGENT_BOM_REQUIRE_AUDIT_HMAC=1.
    """
    global _AUDIT_CHAIN_EPHEMERAL_KEY

    configured = (os.environ.get("AGENT_BOM_AUDIT_HMAC_KEY") or "").strip()
    if configured:
        return configured.encode("utf-8")
    if _env_truthy("AGENT_BOM_REQUIRE_AUDIT_HMAC"):
        raise RuntimeError("AGENT_BOM_REQUIRE_AUDIT_HMAC is enabled but AGENT_BOM_AUDIT_HMAC_KEY is not set")
    if _AUDIT_CHAIN_EPHEMERAL_KEY is None:
        _AUDIT_CHAIN_EPHEMERAL_KEY = secrets.token_bytes(32)
        _logger.warning(
            "AGENT_BOM_AUDIT_HMAC_KEY not set — audit-chain CMAC uses an ephemeral key "
            "(signatures will not survive process restart; set env var for production)"
        )
    return _AUDIT_CHAIN_EPHEMERAL_KEY


def _audit_chain_cmac_key() -> bytes:
    raw = audit_chain_key()
    if len(raw) in {16, 24, 32}:
        return raw
    if len(raw) < 16:
        return raw.ljust(16, b"\0")
    if len(raw) < 24:
        return raw.ljust(24, b"\0")
    if len(raw) < 32:
        return raw.ljust(32, b"\0")
    return raw[:32]


def canonical_audit_payload(payload: dict[str, Any]) -> str:
    """Serialize an audit payload deterministically for integrity checks."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_audit_record_mac(payload: dict[str, Any], prev_hash: str) -> str:
    """Return the chain MAC for a redacted audit payload."""
    canonical = canonical_audit_payload(payload)
    message = f"{prev_hash}|{canonical}".encode("utf-8")
    mac = CMAC(algorithms.AES(_audit_chain_cmac_key()))
    mac.update(message)
    return mac.finalize().hex()
