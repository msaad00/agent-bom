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
import hmac
import json
import logging
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    @property
    def public_key_pem(self) -> str:
        return self._public_pem

    @property
    def key_id(self) -> str:
        return self._key_id


_signer_cache: _Ed25519Signer | None = None
_signer_init_error: str | None = None


def _env_int(name: str) -> int | None:
    value = (os.environ.get(name) or "").strip()
    if not value:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _describe_rotation_posture() -> dict[str, object]:
    rotation_days = _env_int("AGENT_BOM_COMPLIANCE_SIGNING_ROTATION_DAYS")
    max_age_days = _env_int("AGENT_BOM_COMPLIANCE_SIGNING_MAX_AGE_DAYS")
    raw_last_rotated = (os.environ.get("AGENT_BOM_COMPLIANCE_SIGNING_LAST_ROTATED") or "").strip()

    if not raw_last_rotated:
        return {
            "rotation_tracking_supported": True,
            "rotation_tracking_status": "supported",
            "rotation_status": "unknown_age",
            "rotation_method": "env_swap_and_restart",
            "rotation_days": rotation_days,
            "max_age_days": max_age_days,
            "last_rotated": None,
            "age_days": None,
            "rotation_message": (
                "Compliance signing is configured but AGENT_BOM_COMPLIANCE_SIGNING_LAST_ROTATED is unset. "
                "Record an ISO-8601 rotation timestamp to expose key age in operator surfaces."
            ),
        }

    try:
        rotated = datetime.fromisoformat(raw_last_rotated)
    except ValueError:
        return {
            "rotation_tracking_supported": True,
            "rotation_tracking_status": "supported",
            "rotation_status": "unknown_age",
            "rotation_method": "env_swap_and_restart",
            "rotation_days": rotation_days,
            "max_age_days": max_age_days,
            "last_rotated": raw_last_rotated,
            "age_days": None,
            "rotation_message": (
                "AGENT_BOM_COMPLIANCE_SIGNING_LAST_ROTATED is set but is not a valid ISO-8601 timestamp. "
                "Use a value like '2026-04-17T00:00:00+00:00'."
            ),
        }

    if rotated.tzinfo is None:
        rotated = rotated.replace(tzinfo=timezone.utc)
    age_days = max(0, int((datetime.now(timezone.utc) - rotated).total_seconds() // 86400))

    if max_age_days is not None and age_days >= max_age_days:
        status = "max_age_exceeded"
        message = (
            f"Compliance signing key is {age_days} days old, exceeding the configured maximum ({max_age_days} days). "
            "Rotate the signing key, redeploy, and update the recorded rotation timestamp."
        )
    elif rotation_days is not None and age_days >= rotation_days:
        status = "rotation_due"
        message = f"Compliance signing key is {age_days} days old, past the configured rotation interval ({rotation_days} days)."
    else:
        status = "ok"
        if rotation_days is not None:
            message = f"Compliance signing key is {age_days} days old; configured rotation interval is {rotation_days} days."
        else:
            message = f"Compliance signing key is {age_days} days old. No explicit rotation interval is configured."

    return {
        "rotation_tracking_supported": True,
        "rotation_tracking_status": "supported",
        "rotation_status": status,
        "rotation_method": "env_swap_and_restart",
        "rotation_days": rotation_days,
        "max_age_days": max_age_days,
        "last_rotated": rotated.isoformat(),
        "age_days": age_days,
        "rotation_message": message,
    }


def _load_ed25519_signer() -> _Ed25519Signer | None:
    """Return the process-wide Ed25519 signer, or None when asymmetric signing is off."""
    global _signer_cache, _signer_init_error
    if _signer_cache is not None:
        return _signer_cache
    from agent_bom.api.secret_source import resolve_secret

    pem = resolve_secret(_ED25519_ENV_VAR)
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

    Reports the signer's identity only. Surfaces that publish signer facts to
    an auditor want :func:`describe_signer_disclosure` instead — this cannot
    tell a configured HMAC key from a per-process one, so on its own it made
    an unverifiable deployment look identical to a verifiable one.
    """
    signer = _load_ed25519_signer()
    if signer is not None:
        return "Ed25519", signer.key_id, signer.public_key_pem
    return "HMAC-SHA256", None, None


VERIFIABLE_PUBLIC_KEY: Final[str] = "verifiable_public_key"
VERIFIABLE_SHARED_SECRET: Final[str] = "verifiable_shared_secret"
UNVERIFIABLE_EPHEMERAL_KEY: Final[str] = "unverifiable_ephemeral_key"

_ED25519_GUIDANCE: Final[str] = (
    "Retrieve this key over TLS once, pin the key_id, and use it to verify "
    "every compliance bundle signed with Ed25519. Rotate by updating "
    "AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM and re-fetching."
)
_SHARED_SECRET_GUIDANCE: Final[str] = (
    "Bundles are signed with the shared secret in AGENT_BOM_AUDIT_HMAC_KEY, which the operator must hand to each "
    "verifier over a trusted channel. Anyone holding that secret can also forge a bundle, so it is not safe to give "
    "an external auditor — set AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM for asymmetric, auditor-distributable signing."
)
_EPHEMERAL_GUIDANCE: Final[str] = (
    "This deployment signs with a per-process HMAC key generated at startup that never leaves the process. There is "
    "no key to distribute, and bundles it signs cannot be verified by anyone — including this deployment after a restart."
)
_EPHEMERAL_REMEDIATION: Final[str] = (
    "Set AGENT_BOM_AUDIT_HMAC_KEY (or AGENT_BOM_AUDIT_HMAC_KEY_FILE) to a persistent secret so signatures survive a "
    "restart, or — for evidence an external auditor can verify without holding forgeable key material — set "
    "AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM to an Ed25519 private key. Re-export any bundle already issued: "
    "the key that signed it is gone."
)


@dataclass(frozen=True)
class SignerDisclosure:
    """Whether the active signer produces bundles anyone can actually verify.

    ``describe_current_signer`` only sees the algorithm name, so an ephemeral
    per-process HMAC key was indistinguishable from a configured one — both
    stamped ``HMAC-SHA256``. This carries the persistence fact alongside the
    algorithm so the bundle and the verification-key endpoint can say which
    deployment produced it.
    """

    algorithm: str
    key_id: str | None
    public_key_pem: str | None
    signature_verifiable: bool
    persists_across_restart: bool
    verification_status: str
    verification_guidance: str
    remediation: str | None

    def as_bundle_field(self) -> dict[str, object]:
        """The disclosure as it is embedded in the signed bundle body."""
        return {
            "signature_verifiable": self.signature_verifiable,
            "persists_across_restart": self.persists_across_restart,
            "verification_status": self.verification_status,
            "verification_guidance": self.verification_guidance,
            "remediation": self.remediation,
        }


def describe_signer_disclosure() -> SignerDisclosure:
    """Return the verifiability disclosure for the active signer.

    Built from :func:`describe_signing_posture`, which is the only function
    here that can see whether the HMAC secret survives a restart.
    """
    posture = describe_signing_posture()
    algorithm = str(posture["algorithm"])
    key_id = posture["key_id"]
    persists = bool(posture["persists_across_restart"])

    if algorithm == "Ed25519":
        return SignerDisclosure(
            algorithm=algorithm,
            key_id=str(key_id) if key_id is not None else None,
            public_key_pem=current_public_key_pem(),
            signature_verifiable=True,
            persists_across_restart=True,
            verification_status=VERIFIABLE_PUBLIC_KEY,
            verification_guidance=_ED25519_GUIDANCE,
            remediation=None,
        )
    if persists:
        return SignerDisclosure(
            algorithm=algorithm,
            key_id=None,
            public_key_pem=None,
            signature_verifiable=True,
            persists_across_restart=True,
            verification_status=VERIFIABLE_SHARED_SECRET,
            verification_guidance=_SHARED_SECRET_GUIDANCE,
            remediation=None,
        )
    return SignerDisclosure(
        algorithm=algorithm,
        key_id=None,
        public_key_pem=None,
        signature_verifiable=False,
        persists_across_restart=False,
        verification_status=UNVERIFIABLE_EPHEMERAL_KEY,
        verification_guidance=_EPHEMERAL_GUIDANCE,
        remediation=_EPHEMERAL_REMEDIATION,
    )


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


SIGNATURE_FIELD: Final[str] = "signature"


def canonical_bundle_payload(body: Mapping[str, object]) -> bytes:
    """Return the exact bytes a compliance bundle's signature covers.

    The bundle EMBEDS its signature in ``body["signature"]`` so a saved file is
    verifiable on its own — the header alone is lost the moment an operator runs
    ``curl -o bundle.json``. The signature obviously cannot cover itself, so the
    canonical form is the body with that one field removed, serialized as
    ``json.dumps(..., sort_keys=True)``. This is the canonical form for BOTH the
    ``json`` and ``jsonl`` renderings, so either saved artifact verifies the same
    way.
    """
    unsigned = {key: value for key, value in body.items() if key != SIGNATURE_FIELD}
    return json.dumps(unsigned, sort_keys=True).encode()


def verify_compliance_signature(payload: bytes, signature_hex: str) -> bool:
    """Verify ``signature_hex`` over ``payload`` with the active signer.

    Returns False for a malformed signature rather than raising, so callers can
    treat "unverifiable" and "tampered" alike. HMAC comparison is constant-time.
    """
    if not signature_hex:
        return False
    signer = _load_ed25519_signer()
    if signer is not None:
        from cryptography.exceptions import InvalidSignature

        try:
            raw = bytes.fromhex(signature_hex)
        except ValueError:
            return False
        try:
            signer.public_key.verify(raw, payload)
        except InvalidSignature:
            return False
        return True

    from agent_bom.api.audit_log import sign_export_payload

    return hmac.compare_digest(sign_export_payload(payload), signature_hex)


def _verify_ed25519_pem(pem: str, payload: bytes, signature_hex: str) -> bool:
    """Verify ``signature_hex`` over ``payload`` against one PEM public key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as _Ed25519PublicKey

    try:
        raw = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    try:
        key = serialization.load_pem_public_key(pem.encode())
    except (ValueError, TypeError):
        return False
    if not isinstance(key, _Ed25519PublicKey):
        return False
    try:
        key.verify(raw, payload)
    except InvalidSignature:
        return False
    return True


def _verify_hmac_with_secret(secret: str, payload: bytes, signature_hex: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex)


def verify_compliance_bundle(
    body: Mapping[str, object],
    *,
    trusted_public_key_pems: Sequence[str] = (),
    shared_secret: str | None = None,
) -> bool:
    """Verify a bundle against the signature it carries in its own body.

    ``trusted_public_key_pems`` / ``shared_secret`` let an off-line verifier
    (``agent-bom attest compliance-verify``) supply key material it obtained
    itself. Key material EMBEDDED in the bundle (``signature_public_key_pem``)
    is never consulted — it is self-attesting and proves only that the file is
    internally consistent. With neither argument the active in-process signer
    is used, which is what the issuing server has.

    Dispatch follows the bundle's own ``signature_algorithm``: an HMAC bundle
    is never checked with a locally configured Ed25519 key, and vice versa.
    """
    signature = body.get(SIGNATURE_FIELD)
    if not isinstance(signature, str) or not signature:
        return False
    payload = canonical_bundle_payload(body)
    declared = body.get("signature_algorithm")

    if trusted_public_key_pems:
        return any(_verify_ed25519_pem(pem, payload, signature) for pem in trusted_public_key_pems)
    if shared_secret is not None:
        return _verify_hmac_with_secret(shared_secret, payload, signature)

    if declared == "HMAC-SHA256":
        from agent_bom.api.audit_log import sign_export_payload

        return hmac.compare_digest(sign_export_payload(payload), signature)
    if declared == "Ed25519":
        signer = _load_ed25519_signer()
        if signer is None:
            return False
        return _verify_ed25519_pem(signer.public_key_pem, payload, signature)
    return verify_compliance_signature(payload, signature)


def current_public_key_pem() -> str | None:
    """Return the Ed25519 public key PEM for /v1/compliance/verification-key, or None."""
    signer = _load_ed25519_signer()
    return signer.public_key_pem if signer is not None else None


def current_key_id() -> str | None:
    """Return the Ed25519 key_id, or None when only HMAC is configured."""
    signer = _load_ed25519_signer()
    return signer.key_id if signer is not None else None


def describe_signing_posture() -> dict[str, object]:
    """Return operator-facing compliance bundle signing posture."""
    signer = _load_ed25519_signer()
    if signer is not None:
        return {
            "algorithm": "Ed25519",
            "mode": "asymmetric_public_key",
            "configured": True,
            "key_id": signer.key_id,
            "public_key_endpoint": "/v1/compliance/verification-key",
            "auditor_distributable": True,
            "uses_audit_hmac_secret": False,
            "persists_across_restart": True,
            "message": (
                "Compliance evidence bundles are signed with Ed25519. "
                "External verifiers only need the public key, not shared secret material."
            ),
            **_describe_rotation_posture(),
        }

    from agent_bom.api.audit_log import describe_audit_hmac_status

    audit_hmac = describe_audit_hmac_status()
    return {
        "algorithm": "HMAC-SHA256",
        "mode": "shared_secret",
        "configured": bool(audit_hmac["configured"]),
        "key_id": None,
        "public_key_endpoint": None,
        "auditor_distributable": False,
        "uses_audit_hmac_secret": True,
        "persists_across_restart": bool(audit_hmac["persists_across_restart"]),
        "message": (
            "Compliance evidence bundles are signed with the same shared secret family as the audit export path. "
            "For auditor-distributable verification, switch to Ed25519."
        ),
        "rotation_tracking_supported": bool(audit_hmac["rotation_tracking_supported"]),
        "rotation_tracking_status": audit_hmac.get("rotation_tracking_status", "supported"),
        "rotation_status": audit_hmac["rotation_status"],
        "rotation_method": audit_hmac["rotation_method"],
        "rotation_days": audit_hmac["rotation_days"],
        "max_age_days": audit_hmac["max_age_days"],
        "last_rotated": audit_hmac["last_rotated"],
        "age_days": audit_hmac["age_days"],
        "rotation_message": (
            "Compliance evidence currently inherits audit HMAC rotation posture because HMAC signing reuses the audit secret family."
        ),
    }
