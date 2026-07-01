"""Sign and attest generated SBOM output.

This closes the supply-chain-integrity loop for SBOMs that *agent-bom itself
emits* (CycloneDX / SPDX / JSON). Release artifacts are already signed via the
Sigstore/cosign release workflow; this module signs the **content** of a
generated SBOM file so a downstream consumer can prove the document was not
altered after generation.

What it produces for an SBOM file ``foo.cdx.json``:

- ``foo.cdx.json.sig`` — a self-describing *detached signature* over the raw
  SBOM bytes.
- ``foo.cdx.json.intoto.json`` — a DSSE-style envelope wrapping an
  `in-toto Statement v1 <https://in-toto.io/Statement/v1>`_ with a SLSA-style
  provenance predicate. The statement binds the SBOM's SHA-256 digest to the
  builder identity and signs that binding.

Honesty about cryptography
--------------------------
The signing primitive is reused from :mod:`agent_bom.api.compliance_signing`:

- When ``AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM`` is set, signatures are
  **real asymmetric Ed25519** signatures. The public key is embedded in the
  artifacts, so a third party can verify them offline with only the public key
  — this is genuine cryptographic provenance.
- Otherwise it falls back to **HMAC-SHA256** using the audit shared secret.
  HMAC is *tamper-evident*, not non-repudiable: a verifier needs the same
  shared secret, and anyone holding that secret could forge a signature. The
  emitted artifacts label themselves ``"cryptographic": false`` in that mode so
  no one mistakes them for asymmetric signatures.

Either way the SHA-256 digest binding is real: the attestation always lets a
consumer detect that the SBOM bytes changed.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from agent_bom import __version__

# in-toto / SLSA constants
_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
_DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_BUILDER_ID = "https://github.com/msaad00/agent-bom"

_SIG_SUFFIX = ".sig"
_ATTESTATION_SUFFIX = ".intoto.json"


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
    """Outcome of verifying an SBOM attestation/signature."""

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


def _canonical_bytes(obj: dict) -> bytes:
    """Deterministic JSON encoding used as the signed payload."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_sbom_digest(data: bytes) -> str:
    """Return the hex SHA-256 digest of raw SBOM bytes."""
    return hashlib.sha256(data).hexdigest()


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
) -> dict:
    """Build an in-toto Statement v1 binding the SBOM digest to a SLSA predicate."""
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
                "externalParameters": {
                    "sbomFormat": sbom_format or _infer_format(name),
                },
            },
            "runDetails": {
                "builder": {"id": _BUILDER_ID, "version": {"agent-bom": __version__}},
                "metadata": {"startedOn": now, "finishedOn": now},
            },
        },
    }


def _sign(payload: bytes):
    """Return (SignatureResult, cryptographic_bool) using the shared signer."""
    from agent_bom.api.compliance_signing import sign_compliance_bundle

    result = sign_compliance_bundle(payload)
    return result, result.algorithm == "Ed25519"


def sign_sbom_file(
    sbom_path: str | Path,
    *,
    signature_path: str | Path | None = None,
    attestation_path: str | Path | None = None,
    sbom_format: str | None = None,
) -> AttestationResult:
    """Sign a generated SBOM file: write a detached signature + in-toto attestation.

    Reuses the Ed25519 (preferred) / HMAC-SHA256 signer from
    :mod:`agent_bom.api.compliance_signing`. See the module docstring for the
    honest distinction between the two modes.
    """
    src = Path(sbom_path)
    sbom_bytes = src.read_bytes()
    digest = compute_sbom_digest(sbom_bytes)

    # 1. Detached signature over the raw SBOM bytes.
    blob_sig, cryptographic = _sign(sbom_bytes)
    sig_obj = {
        "_type": "https://agent-bom.dev/sbom-detached-signature/v1",
        "subject": src.name,
        "sha256": digest,
        "algorithm": blob_sig.algorithm,
        "cryptographic": cryptographic,
        "keyId": blob_sig.key_id,
        "publicKeyPem": blob_sig.public_key_pem,
        "signature": blob_sig.signature_hex,
    }
    sig_out = Path(signature_path) if signature_path else Path(str(src) + _SIG_SUFFIX)
    sig_out.write_text(json.dumps(sig_obj, indent=2), encoding="utf-8")

    # 2. in-toto Statement + DSSE-style envelope (the attestation).
    statement = build_intoto_statement(src, sbom_bytes, sbom_format=sbom_format)
    payload = _canonical_bytes(statement)
    stmt_sig, _ = _sign(payload)
    envelope = {
        "payloadType": _DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": stmt_sig.key_id or "", "sig": stmt_sig.signature_hex}],
        "_agentBom": {
            "algorithm": stmt_sig.algorithm,
            "cryptographic": cryptographic,
            "publicKeyPem": stmt_sig.public_key_pem,
            "note": (
                "Ed25519: asymmetric, third-party verifiable with the public key. "
                "HMAC-SHA256: tamper-evident only; verification requires the shared secret."
            ),
        },
    }
    att_out = Path(attestation_path) if attestation_path else Path(str(src) + _ATTESTATION_SUFFIX)
    att_out.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

    return AttestationResult(
        sbom_path=str(src),
        sha256=digest,
        algorithm=blob_sig.algorithm,
        cryptographic=cryptographic,
        key_id=blob_sig.key_id,
        signature_path=str(sig_out),
        attestation_path=str(att_out),
        public_key_pem=blob_sig.public_key_pem,
    )


def _verify_signature(payload: bytes, signature_hex: str, algorithm: str, public_key_pem: str | None) -> bool:
    """Verify a signature against the signed payload for the given algorithm."""
    if algorithm == "Ed25519":
        if not public_key_pem:
            return False
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            loaded = serialization.load_pem_public_key(public_key_pem.encode())
            if not isinstance(loaded, Ed25519PublicKey):
                return False
            loaded.verify(bytes.fromhex(signature_hex), payload)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
    if algorithm == "HMAC-SHA256":
        from agent_bom.api.audit_log import verify_export_payload

        return verify_export_payload(payload, signature_hex)
    return False


def verify_sbom_attestation(
    sbom_path: str | Path,
    *,
    attestation_path: str | Path | None = None,
    signature_path: str | Path | None = None,
) -> VerificationResult:
    """Verify a generated SBOM against its in-toto attestation (and detached sig).

    Recomputes the SBOM SHA-256, confirms it matches the digest bound in the
    signed in-toto subject, and validates the signature. For Ed25519 this is a
    full asymmetric check using the embedded public key; for HMAC-SHA256 it
    recomputes the MAC with the shared secret.
    """
    src = Path(sbom_path)
    result = VerificationResult(sbom_path=str(src))

    if not src.is_file():
        result.reason = "sbom_file_not_found"
        return result

    sbom_bytes = src.read_bytes()
    actual_digest = compute_sbom_digest(sbom_bytes)
    result.actual_sha256 = actual_digest

    att_path = Path(attestation_path) if attestation_path else Path(str(src) + _ATTESTATION_SUFFIX)
    if not att_path.is_file():
        result.reason = "attestation_not_found"
        return result

    try:
        envelope = json.loads(att_path.read_text(encoding="utf-8"))
        payload = base64.b64decode(envelope["payload"])
        statement = json.loads(payload)
        meta = envelope.get("_agentBom", {})
        sig_entry = envelope["signatures"][0]
    except (OSError, ValueError, KeyError, IndexError) as exc:
        result.reason = f"malformed_attestation: {type(exc).__name__}"
        return result

    result.algorithm = str(meta.get("algorithm", ""))
    result.cryptographic = bool(meta.get("cryptographic", False))
    result.key_id = sig_entry.get("keyid") or None

    # Digest binding: recomputed SBOM hash must equal the signed subject digest.
    expected_digest = ""
    for subject in statement.get("subject", []):
        expected_digest = subject.get("digest", {}).get("sha256", "")
        if expected_digest:
            break
    result.expected_sha256 = expected_digest
    result.digest_matches = bool(expected_digest) and expected_digest == actual_digest
    result.checks.append("digest_match=" + ("ok" if result.digest_matches else "FAIL"))

    # Signature over the in-toto statement payload.
    result.signature_valid = _verify_signature(
        payload,
        sig_entry.get("sig", ""),
        result.algorithm,
        meta.get("publicKeyPem"),
    )
    result.checks.append("statement_signature=" + ("ok" if result.signature_valid else "FAIL"))

    # Optional: detached signature over the raw SBOM bytes.
    sig_path = Path(signature_path) if signature_path else Path(str(src) + _SIG_SUFFIX)
    if sig_path.is_file():
        try:
            sig_obj = json.loads(sig_path.read_text(encoding="utf-8"))
            blob_ok = sig_obj.get("sha256") == actual_digest and _verify_signature(
                sbom_bytes,
                sig_obj.get("signature", ""),
                str(sig_obj.get("algorithm", "")),
                sig_obj.get("publicKeyPem"),
            )
        except (OSError, ValueError):
            blob_ok = False
        result.checks.append("detached_signature=" + ("ok" if blob_ok else "FAIL"))
        signature_ok = result.signature_valid and blob_ok
    else:
        signature_ok = result.signature_valid

    if not result.digest_matches:
        result.reason = "digest_mismatch"
    elif not signature_ok:
        result.reason = "signature_invalid"
    else:
        result.verified = True
        result.reason = "verified"

    return result
