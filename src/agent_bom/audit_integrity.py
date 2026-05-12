"""Shared audit-chain integrity helpers."""

from __future__ import annotations

import json
import logging
import os
import secrets
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

_logger = logging.getLogger(__name__)
_AUDIT_CHAIN_EPHEMERAL_KEY: bytes | None = None

CHAIN_KEY_SIDECAR_SUFFIX = ".chain-key"


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


def _normalize_cmac_key(raw: bytes) -> bytes:
    if len(raw) in {16, 24, 32}:
        return raw
    if len(raw) < 16:
        return raw.ljust(16, b"\0")
    if len(raw) < 24:
        return raw.ljust(24, b"\0")
    if len(raw) < 32:
        return raw.ljust(32, b"\0")
    return raw[:32]


def _audit_chain_cmac_key() -> bytes:
    return _normalize_cmac_key(audit_chain_key())


def canonical_audit_payload(payload: dict[str, Any]) -> str:
    """Serialize an audit payload deterministically for integrity checks."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_audit_record_mac(payload: dict[str, Any], prev_hash: str) -> str:
    """Return the chain MAC for a redacted audit payload."""
    return compute_audit_record_mac_with_key(payload, prev_hash, _audit_chain_cmac_key())


def compute_audit_record_mac_with_key(payload: dict[str, Any], prev_hash: str, key: bytes) -> str:
    """Return the chain MAC for an audit payload using an explicit key.

    Used by the verifier to validate logs written under a sidecar-persisted
    ephemeral key without mutating process-global state.
    """
    canonical = canonical_audit_payload(payload)
    message = f"{prev_hash}|{canonical}".encode("utf-8")
    mac = CMAC(algorithms.AES(_normalize_cmac_key(key)))
    mac.update(message)
    return mac.finalize().hex()


def _sidecar_path_for(log_path: str | os.PathLike[str]) -> Path:
    """Return the sidecar key path next to a JSONL audit log."""
    return Path(str(log_path) + CHAIN_KEY_SIDECAR_SUFFIX)


def persist_ephemeral_chain_key(log_path: str | os.PathLike[str], key: bytes) -> Path:
    """Persist the ephemeral chain key alongside ``log_path``.

    The sidecar is written with 0600 permissions so cross-process verifiers
    (``agent-bom audit --verify-chain``) can validate logs even when no
    ``AGENT_BOM_AUDIT_HMAC_KEY`` is configured. The sidecar carries no
    additional secrecy benefit beyond the log itself — an attacker with
    write access to the log can replace both — but it removes the false
    "tampered" reading that otherwise plagues default-config CI.
    """
    sidecar = _sidecar_path_for(log_path)
    if sidecar.exists():
        return sidecar
    fd = os.open(str(sidecar), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return sidecar


def load_sidecar_chain_key(log_path: str | os.PathLike[str]) -> bytes | None:
    """Return the sidecar chain key for ``log_path`` if one exists."""
    sidecar = _sidecar_path_for(log_path)
    try:
        return sidecar.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:  # pragma: no cover — permission denied surfaces clearly
        _logger.warning("Failed to read audit chain sidecar %s: %s", sidecar, exc)
        return None


def resolve_verifier_chain_key(log_path: str | os.PathLike[str]) -> bytes:
    """Return the chain key to use when verifying ``log_path``.

    Order of precedence:
    1. ``AGENT_BOM_AUDIT_HMAC_KEY`` env var (operator-configured key)
    2. Sidecar ``<log>.chain-key`` written by the proxy at log creation
    3. The current process's ephemeral fallback (only useful in-process)
    """
    configured = (os.environ.get("AGENT_BOM_AUDIT_HMAC_KEY") or "").strip()
    if configured:
        return _normalize_cmac_key(configured.encode("utf-8"))
    sidecar_key = load_sidecar_chain_key(log_path)
    if sidecar_key is not None:
        return _normalize_cmac_key(sidecar_key)
    return _audit_chain_cmac_key()
