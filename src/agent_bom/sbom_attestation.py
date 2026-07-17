"""Sign and verify generated SBOMs at an explicit DSSE trust boundary.

New attestations use DSSE pre-authentication encoding (PAE) and Ed25519 only.
Verification trusts only caller-supplied public keys; envelope metadata and
embedded legacy keys are evidence, never trust anchors. Older self-consistent
envelopes remain readable but are always reported as legacy and untrusted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_bom import __version__

_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
_DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_DSSE_SCHEMA_VERSION = "agent-bom-sbom-dsse-v2"
_BUILDER_ID = "https://github.com/msaad00/agent-bom"
_DETACHED_TYPE = "https://agent-bom.dev/sbom-detached-signature/v2"
_PRIVATE_KEY_ENV = "AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM"

_SIG_SUFFIX = ".sig"
_ATTESTATION_SUFFIX = ".intoto.json"
_MAX_ENVELOPE_BYTES = 16 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 12 * 1024 * 1024
_MAX_SIGNATURE_FILE_BYTES = 64 * 1024
_MAX_TRUSTED_KEYS = 32
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class AttestationSigningError(RuntimeError):
    """Controlled signing configuration failure with no secret-bearing detail."""


class AttestationTrustError(ValueError):
    """Controlled caller trust-policy configuration failure."""


class _DuplicateJsonKeyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _TrustedEd25519Key:
    key_id: str
    public_key: Ed25519PublicKey


@dataclass(frozen=True, slots=True)
class AttestationTrustPolicy:
    """Bounded immutable set of verifier-configured Ed25519 trust anchors."""

    keys: tuple[_TrustedEd25519Key, ...]

    def __post_init__(self) -> None:
        if not self.keys:
            raise AttestationTrustError("trusted_public_key_required")
        if len(self.keys) > _MAX_TRUSTED_KEYS:
            raise AttestationTrustError("too_many_trusted_public_keys")
        key_ids = [key.key_id for key in self.keys]
        if len(key_ids) != len(set(key_ids)):
            raise AttestationTrustError("ambiguous_trusted_key_id")

    @classmethod
    def from_public_key_pems(cls, public_key_pems: Iterable[str]) -> AttestationTrustPolicy:
        by_id: dict[str, _TrustedEd25519Key] = {}
        for pem in public_key_pems:
            try:
                loaded = serialization.load_pem_public_key(str(pem).encode("utf-8"))
            except (TypeError, ValueError):
                raise AttestationTrustError("trusted_public_key_invalid") from None
            if not isinstance(loaded, Ed25519PublicKey):
                raise AttestationTrustError("trusted_public_key_not_ed25519")
            key_id = _public_key_id(loaded)
            existing = by_id.get(key_id)
            if existing is not None and _public_der(existing.public_key) != _public_der(loaded):
                raise AttestationTrustError("ambiguous_trusted_key_id")
            by_id[key_id] = _TrustedEd25519Key(key_id=key_id, public_key=loaded)
            if len(by_id) > _MAX_TRUSTED_KEYS:
                raise AttestationTrustError("too_many_trusted_public_keys")
        return cls(keys=tuple(by_id[key_id] for key_id in sorted(by_id)))

    def resolve(self, key_id: str) -> Ed25519PublicKey | None:
        matches = [key.public_key for key in self.keys if key.key_id == key_id]
        return matches[0] if len(matches) == 1 else None


@dataclass(frozen=True)
class AttestationResult:
    """Artifacts produced when signing a generated SBOM file."""

    sbom_path: str
    sha256: str
    algorithm: str
    cryptographic: bool
    key_id: str | None
    signature_path: str
    attestation_path: str
    public_key_pem: str | None = None


@dataclass
class VerificationResult:
    """Outcome of verifying one SBOM attestation against caller trust."""

    sbom_path: str
    verified: bool = False
    algorithm: str = ""
    cryptographic: bool = False
    key_id: str | None = None
    digest_matches: bool = False
    signature_valid: bool = False
    reason: str = ""
    expected_sha256: str = ""
    actual_sha256: str = ""
    checks: list[str] = field(default_factory=list)
    format_version: str = ""
    legacy: bool = False
    trust_status: str = "untrusted"


def _canonical_bytes(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_sbom_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Return DSSE v1 pre-authentication encoding for type and payload."""

    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(type_bytes)).encode("ascii") + b" " + type_bytes + b" " + str(len(payload)).encode("ascii") + b" " + payload


def _infer_format(name: str) -> str:
    lowered = name.lower()
    if lowered.endswith(".cdx.json") or "cyclonedx" in lowered:
        return "CycloneDX"
    if lowered.endswith(".spdx.json") or "spdx" in lowered:
        return "SPDX"
    return "unknown"


def build_intoto_statement(
    sbom_path: str | Path,
    sbom_bytes: bytes,
    *,
    sbom_format: str | None = None,
) -> dict[str, Any]:
    name = Path(sbom_path).name
    digest = compute_sbom_digest(sbom_bytes)
    now = datetime.now(timezone.utc).isoformat()
    return {
        "_type": _STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": digest}}],
        "predicateType": _PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://agent-bom.dev/sbom-generation/v1",
                "externalParameters": {"sbomFormat": sbom_format or _infer_format(name)},
            },
            "runDetails": {
                "builder": {"id": _BUILDER_ID, "version": {"agent-bom": __version__}},
                "metadata": {"startedOn": now, "finishedOn": now},
            },
        },
    }


def _public_der(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _public_key_id(public_key: Ed25519PublicKey) -> str:
    return hashlib.sha256(_public_der(public_key)).hexdigest()


def _load_private_signer() -> Ed25519PrivateKey:
    from agent_bom.api.secret_source import resolve_secret

    try:
        pem = resolve_secret(_PRIVATE_KEY_ENV)
    except (OSError, ValueError):
        raise AttestationSigningError("ed25519_signing_key_invalid") from None
    if not pem:
        raise AttestationSigningError("ed25519_signing_key_required")
    try:
        loaded = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except (TypeError, ValueError):
        raise AttestationSigningError("ed25519_signing_key_invalid") from None
    if not isinstance(loaded, Ed25519PrivateKey):
        raise AttestationSigningError("ed25519_signing_key_not_ed25519")
    return loaded


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def sign_sbom_file(
    sbom_path: str | Path,
    *,
    signature_path: str | Path | None = None,
    attestation_path: str | Path | None = None,
    sbom_format: str | None = None,
) -> AttestationResult:
    """Write an Ed25519 detached signature and DSSE-PAE attestation."""

    src = Path(sbom_path)
    try:
        sbom_bytes = src.read_bytes()
    except OSError:
        raise AttestationSigningError("sbom_file_unreadable") from None
    signer = _load_private_signer()
    public_key = signer.public_key()
    key_id = _public_key_id(public_key)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    digest = compute_sbom_digest(sbom_bytes)
    sig_out = Path(signature_path) if signature_path else Path(str(src) + _SIG_SUFFIX)
    att_out = Path(attestation_path) if attestation_path else Path(str(src) + _ATTESTATION_SUFFIX)
    if sig_out.resolve() == att_out.resolve():
        raise AttestationSigningError("signature_and_attestation_paths_must_differ")

    statement = build_intoto_statement(src, sbom_bytes, sbom_format=sbom_format)
    payload = _canonical_bytes(statement)
    if len(payload) > _MAX_PAYLOAD_BYTES:
        raise AttestationSigningError("attestation_payload_too_large")
    envelope = {
        "payloadType": _DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "keyid": key_id,
                "sig": base64.b64encode(signer.sign(dsse_pae(_DSSE_PAYLOAD_TYPE, payload))).decode("ascii"),
            }
        ],
        "_agentBom": {"schemaVersion": _DSSE_SCHEMA_VERSION},
    }
    detached = {
        "_type": _DETACHED_TYPE,
        "subject": src.name,
        "sha256": digest,
        "algorithm": "Ed25519",
        "keyId": key_id,
        "signature": base64.b64encode(signer.sign(sbom_bytes)).decode("ascii"),
    }
    try:
        _atomic_write_json(sig_out, detached)
        _atomic_write_json(att_out, envelope)
    except OSError:
        try:
            sig_out.unlink()
        except OSError:
            pass
        raise AttestationSigningError("attestation_artifact_write_failed") from None

    return AttestationResult(
        sbom_path=str(src),
        sha256=digest,
        algorithm="Ed25519",
        cryptographic=True,
        key_id=key_id,
        signature_path=str(sig_out),
        attestation_path=str(att_out),
        public_key_pem=public_pem,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError
        result[key] = value
    return result


def _load_json_object(raw: bytes) -> dict[str, Any]:
    decoded = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(decoded, dict):
        raise ValueError
    return decoded


def _decode_payload(envelope: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    encoded = envelope.get("payload")
    if not isinstance(encoded, str):
        raise ValueError
    payload = base64.b64decode(encoded, validate=True)
    if len(payload) > _MAX_PAYLOAD_BYTES:
        raise OverflowError
    return payload, _load_json_object(payload)


def _statement_digest(statement: Mapping[str, Any], expected_name: str) -> str:
    if statement.get("_type") != _STATEMENT_TYPE or statement.get("predicateType") != _PREDICATE_TYPE:
        return ""
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], Mapping):
        return ""
    subject = subjects[0]
    if subject.get("name") != expected_name or not isinstance(subject.get("digest"), Mapping):
        return ""
    digest = subject["digest"].get("sha256")
    return str(digest) if isinstance(digest, str) and _SHA256_RE.fullmatch(digest) else ""


def _verify_ed25519(public_key: Ed25519PublicKey, signature_b64: Any, signed: bytes) -> bool:
    if not isinstance(signature_b64, str):
        return False
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        if len(signature) != 64:
            return False
        public_key.verify(signature, signed)
        return True
    except (binascii.Error, InvalidSignature, ValueError):
        return False


def _legacy_result(
    result: VerificationResult,
    envelope: Mapping[str, Any],
    *,
    actual_digest: str,
    sbom_name: str,
) -> VerificationResult:
    """Read only the legacy digest binding; never trust embedded signer data."""

    result.legacy = True
    result.format_version = "legacy"
    result.algorithm = "legacy-untrusted"
    result.trust_status = "legacy_untrusted"
    try:
        _payload, statement = _decode_payload(envelope)
        result.expected_sha256 = _statement_digest(statement, sbom_name)
        result.digest_matches = bool(result.expected_sha256) and result.expected_sha256 == actual_digest
        result.checks.append("legacy_digest_match=" + ("ok" if result.digest_matches else "FAIL"))
        result.checks.append("legacy_signature_trust=untrusted")
        result.reason = "legacy_attestation_untrusted"
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError, ValueError, OverflowError, _DuplicateJsonKeyError):
        result.reason = "malformed_attestation"
    return result


def _verify_detached(
    path: Path,
    *,
    sbom_bytes: bytes,
    actual_digest: str,
    key_id: str,
    public_key: Ed25519PublicKey,
) -> tuple[bool, str]:
    try:
        if path.stat().st_size > _MAX_SIGNATURE_FILE_BYTES:
            return False, "detached_signature_too_large"
        detached = _load_json_object(path.read_bytes())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError, _DuplicateJsonKeyError):
        return False, "detached_signature_invalid"
    if detached.get("_type") != _DETACHED_TYPE or detached.get("algorithm") != "Ed25519":
        return False, "detached_signature_invalid"
    if detached.get("keyId") != key_id:
        return False, "detached_key_id_mismatch"
    if detached.get("sha256") != actual_digest:
        return False, "detached_digest_mismatch"
    if not _verify_ed25519(public_key, detached.get("signature"), sbom_bytes):
        return False, "detached_signature_invalid"
    return True, ""


def verify_sbom_attestation(
    sbom_path: str | Path,
    *,
    attestation_path: str | Path | None = None,
    signature_path: str | Path | None = None,
    trust_policy: AttestationTrustPolicy | None = None,
) -> VerificationResult:
    """Verify a versioned DSSE envelope only against external caller trust."""

    src = Path(sbom_path)
    result = VerificationResult(sbom_path=str(src))
    if not src.is_file():
        result.reason = "sbom_file_not_found"
        return result
    try:
        sbom_bytes = src.read_bytes()
    except OSError:
        result.reason = "sbom_file_unreadable"
        return result
    actual_digest = compute_sbom_digest(sbom_bytes)
    result.actual_sha256 = actual_digest
    att_path = Path(attestation_path) if attestation_path else Path(str(src) + _ATTESTATION_SUFFIX)
    if not att_path.is_file():
        result.reason = "attestation_not_found"
        return result
    try:
        if att_path.stat().st_size > _MAX_ENVELOPE_BYTES:
            result.reason = "attestation_too_large"
            return result
        envelope = _load_json_object(att_path.read_bytes())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError, _DuplicateJsonKeyError):
        result.reason = "malformed_attestation"
        return result

    metadata = envelope.get("_agentBom")
    metadata_map: Mapping[str, Any] = metadata if isinstance(metadata, Mapping) else {}
    version = metadata_map.get("schemaVersion")
    if version is None:
        return _legacy_result(result, envelope, actual_digest=actual_digest, sbom_name=src.name)
    if version != _DSSE_SCHEMA_VERSION:
        result.reason = "unsupported_attestation_version"
        return result
    if "algorithm" in metadata_map:
        result.reason = "algorithm_metadata_invalid"
        return result
    result.format_version = _DSSE_SCHEMA_VERSION
    result.algorithm = "Ed25519"
    result.cryptographic = True
    if envelope.get("payloadType") != _DSSE_PAYLOAD_TYPE:
        result.reason = "payload_type_invalid"
        return result
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1 or not isinstance(signatures[0], Mapping):
        result.reason = "ambiguous_signatures"
        return result
    signature = signatures[0]
    if set(signature) != {"keyid", "sig"}:
        result.reason = "signature_metadata_invalid"
        return result
    key_id = signature.get("keyid")
    if not isinstance(key_id, str) or not _SHA256_RE.fullmatch(key_id):
        result.reason = "key_id_missing" if not key_id else "key_id_invalid"
        return result
    try:
        payload, statement = _decode_payload(envelope)
    except OverflowError:
        result.reason = "attestation_payload_too_large"
        return result
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError, ValueError, _DuplicateJsonKeyError):
        result.reason = "malformed_attestation"
        return result
    expected_digest = _statement_digest(statement, src.name)
    if not expected_digest:
        result.reason = "statement_subject_invalid"
        return result
    result.expected_sha256 = expected_digest
    result.digest_matches = expected_digest == actual_digest
    result.checks.append("digest_match=" + ("ok" if result.digest_matches else "FAIL"))

    if trust_policy is None:
        result.reason = "trusted_public_key_required"
        result.checks.append("signer_trust=missing")
        return result
    public_key = trust_policy.resolve(key_id)
    if public_key is None:
        result.reason = "untrusted_signer"
        result.checks.append("signer_trust=untrusted")
        return result
    result.key_id = key_id
    result.trust_status = "trusted"
    result.signature_valid = _verify_ed25519(public_key, signature.get("sig"), dsse_pae(_DSSE_PAYLOAD_TYPE, payload))
    result.checks.append("dsse_signature=" + ("ok" if result.signature_valid else "FAIL"))

    detached_ok = True
    detached_reason = ""
    sig_path = Path(signature_path) if signature_path else Path(str(src) + _SIG_SUFFIX)
    if sig_path.is_file():
        detached_ok, detached_reason = _verify_detached(
            sig_path,
            sbom_bytes=sbom_bytes,
            actual_digest=actual_digest,
            key_id=key_id,
            public_key=public_key,
        )
        result.checks.append("detached_signature=" + ("ok" if detached_ok else "FAIL"))

    if not result.digest_matches:
        result.reason = "digest_mismatch"
    elif not result.signature_valid:
        result.reason = "signature_invalid"
    elif not detached_ok:
        result.reason = detached_reason
    else:
        result.verified = True
        result.reason = "verified"
    return result
