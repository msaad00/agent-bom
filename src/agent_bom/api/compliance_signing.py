"""Compliance evidence bundle signing.

Two signing modes:

- **HMAC-SHA256 (default)** — tamper-evident. Verifier needs the shared
  secret. Good for internal review; not suitable for handing to an external
  auditor because the secret must also be shared.
- **Ed25519 (opt-in)** — asymmetric. Verifier needs only the public key,
  which is safe to distribute. Meets the SOC 2 / ISO / PCI expectation that
  evidence can be independently verified by a third party without receiving
  key material that could forge new bundles.

Activation:
- Set ``AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM`` to a PEM-encoded
  Ed25519 private key (32-byte seed or OpenSSH/PKCS#8 PEM). When present,
  the evidence bundle is signed with Ed25519 and the response exposes the
  algorithm, a stable ``key_id`` (SHA-256 of the DER public key, first 16
  hex chars), and the public key is also retrievable at
  ``GET /v1/compliance/verification-key`` for offline verification.
- When unset, falls back to HMAC-SHA256 using ``AGENT_BOM_AUDIT_HMAC_KEY``
  (existing behavior). No change for existing deployments.

Key rotation is explicit: rotate by swapping the env var and redeploying.
Old bundles remain verifiable against the old public key (which auditors
should retain). The ``key_id`` in the bundle tells verifiers which key to
use.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Final

logger = logging.getLogger(__name__)

_ED25519_ENV_VAR: Final[str] = "AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM"


@dataclass(frozen=True)
class SignatureResult:
    """Signing output passed back to the route handler."""

    algorithm: str  # "HMAC-SHA256" or "Ed25519"
    signature_hex: str  # hex string; for Ed25519 this is the hex of the raw 64-byte sig
    key_id: str | None  # sha256 prefix of public key (Ed25519 only)
    public_key_pem: str | None  # only set for Ed25519


class _Ed25519Signer:
    """Lazy-loaded Ed25519 signer. Raises if the env var is malformed."""

    def __init__(self, pem: str) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        loaded = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM is not an Ed25519 key")
        self._private_key = loaded
        public_bytes: bytes = loaded.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._key_id: str = hashlib.sha256(public_bytes).hexdigest()[:16]
        pem_bytes: bytes = loaded.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._public_pem: str = pem_bytes.decode()

    def sign(self, payload: bytes) -> SignatureResult:
        return SignatureResult(
            algorithm="Ed25519",
            signature_hex=self._private_key.sign(payload).hex(),
            key_id=self._key_id,
            public_key_pem=self._public_pem,
        )

    @property
    def public_key_pem(self) -> str:
        return self._public_pem

    @property
    def key_id(self) -> str:
        return self._key_id


_signer_cache: _Ed25519Signer | None = None
_signer_init_error: str | None = None


def _load_ed25519_signer() -> _Ed25519Signer | None:
    """Return the process-wide Ed25519 signer, or None when asymmetric signing is off."""
    global _signer_cache, _signer_init_error
    if _signer_cache is not None:
        return _signer_cache
    pem = os.environ.get(_ED25519_ENV_VAR)
    if not pem:
        return None
    if _signer_init_error is not None:
        return None
    try:
        _signer_cache = _Ed25519Signer(pem)
        logger.info("compliance evidence signing: Ed25519 enabled (key_id=%s)", _signer_cache.key_id)
        return _signer_cache
    except Exception as exc:  # pragma: no cover — exercised via tests with bad PEM
        _signer_init_error = str(exc)
        logger.error(
            "AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM is set but could not be parsed: %s — falling back to HMAC",
            exc,
        )
        return None


def reset_signer_cache_for_tests() -> None:
    """Drop the process-wide Ed25519 signer — used by tests that rotate keys."""
    global _signer_cache, _signer_init_error
    _signer_cache = None
    _signer_init_error = None


def describe_current_signer() -> tuple[str, str | None, str | None]:
    """Return ``(algorithm, key_id, public_key_pem)`` for the active signer.

    Called BEFORE signing so the algorithm and key fields can be embedded in
    the canonical body that gets signed — verifiers then see the same body
    that was signed.
    """
    signer = _load_ed25519_signer()
    if signer is not None:
        return "Ed25519", signer.key_id, signer.public_key_pem
    return "HMAC-SHA256", None, None


def sign_compliance_bundle(payload: bytes) -> SignatureResult:
    """Sign a canonical-JSON compliance bundle payload.

    Prefers Ed25519 when ``AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM`` is
    set; otherwise returns an HMAC-SHA256 signature using the audit log's
    shared secret.
    """
    signer = _load_ed25519_signer()
    if signer is not None:
        return signer.sign(payload)

    from agent_bom.api.audit_log import sign_export_payload

    return SignatureResult(
        algorithm="HMAC-SHA256",
        signature_hex=sign_export_payload(payload),
        key_id=None,
        public_key_pem=None,
    )


def current_public_key_pem() -> str | None:
    """Return the Ed25519 public key PEM for /v1/compliance/verification-key, or None."""
    signer = _load_ed25519_signer()
    return signer.public_key_pem if signer is not None else None


def current_key_id() -> str | None:
    """Return the Ed25519 key_id, or None when only HMAC is configured."""
    signer = _load_ed25519_signer()
    return signer.key_id if signer is not None else None
