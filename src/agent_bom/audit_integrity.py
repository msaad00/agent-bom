"""Shared audit-chain integrity helpers."""

from __future__ import annotations

import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

_AUDIT_CHAIN_FALLBACK_KEY = b"agent-bom-audit-chain-v1"


def audit_chain_key() -> bytes:
    """Return the operator HMAC key, or a deterministic local fallback."""
    configured = (os.environ.get("AGENT_BOM_AUDIT_HMAC_KEY") or "").strip()
    return configured.encode("utf-8") if configured else _AUDIT_CHAIN_FALLBACK_KEY


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
