"""Signed, portable per-instance MCP server scan attestations (#4151 PR-1).

Each scanned MCP server instance is bound into a DSSE-signed evidence object:
the immutable instance identity/digest, scanner version, observation time,
verdict, SBOM digest, capability fingerprint, and a normalized evidence digest.
An independent verifier validates it only against an operator-configured trust
policy (pinned Ed25519 signers, expected tenant, freshness). Trust is never
derived from key material embedded in the artifact being verified.

This module deliberately reuses the hardened DSSE primitives introduced for SBOM
attestations (#4155/#4163) — pre-authentication encoding, external-only signer
trust, bounded envelopes, JSON hardening, and the replay-store contract — while
using a *dedicated* MCP signing domain (predicate/media/build/builder types) and
a *dedicated* MCP signing key. It never falls back to the compliance/audit key.

Signature validity is orthogonal to the scan verdict: a valid attestation may
truthfully carry FAIL/BLOCK. State precedence for the catalog surface is
revoked > expired > invalid/untrusted signature > verified > unsigned > unknown.

Pure verification is repeatable and read-only. Persistent replay consumption is
an explicit acceptance operation (:func:`accept_mcp_scan_attestation`).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_bom import __version__
from agent_bom.sbom_attestation import (
    _MAX_PAYLOAD_BYTES,
    _MAX_TENANT_ID_BYTES,
    _MAX_TRUSTED_KEYS,
    _NONCE_RE,
    _SHA256_RE,
    AttestationReplayStore,
    AttestationSigningError,
    AttestationTrustError,
    MemoryAttestationReplayStore,
    _canonical_bytes,
    _DuplicateJsonKeyError,
    _load_json_object,
    _normalize_datetime,
    _parse_signed_datetime,
    _public_der,
    _public_key_id,
    _TrustedEd25519Key,
    _validate_policy_text,
    _verify_ed25519,
    dsse_pae,
)

__all__ = [
    "Ed25519MCPScanSigner",
    "MCPScanEvidence",
    "MCPScanTrustPolicy",
    "MCPScanVerification",
    "MemoryAttestationReplayStore",
    "accept_mcp_scan_attestation",
    "build_mcp_scan_statement",
    "compute_evidence_digest",
    "mcp_catalog_attestation_receipt",
    "mcp_catalog_trust_label",
    "sign_mcp_scan_attestation",
    "verify_mcp_scan_attestation",
]

# --- dedicated MCP signing domain (distinct from the SBOM/compliance domain) --
_MCP_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_MCP_PREDICATE_TYPE = "https://agent-bom.dev/mcp-server-scan/v1"
_MCP_PAYLOAD_TYPE = "application/vnd.agent-bom.mcp-scan-attestation+json"
_MCP_BUILD_TYPE = "https://agent-bom.dev/mcp-scan/v1"
_MCP_BUILDER_ID = "https://github.com/msaad00/agent-bom/mcp-scanner"
_MCP_SCHEMA_VERSION = "agent-bom-mcp-scan-attestation-v1"
_MCP_PRIVATE_KEY_ENV = "AGENT_BOM_MCP_SCAN_ED25519_PRIVATE_KEY_PEM"

_MAX_MCP_MAX_AGE_SECONDS = 30 * 24 * 60 * 60
_MAX_MCP_CLOCK_SKEW_SECONDS = 300
_DEFAULT_TTL_SECONDS = 24 * 60 * 60
_MAX_REFERENCES = 16
_MAX_REFERENCE_BYTES = 512
_MAX_FINDINGS = 100_000
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,255}$")
_ATTESTATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{3,255}$")

_VALID_VERDICTS = frozenset({"PASS", "WARN", "FAIL", "BLOCK", "UNKNOWN"})
_TRUST_STATES = frozenset({"verified", "unsigned", "expired", "revoked", "invalid", "unknown"})

_NON_PROMOTION_NOTICE = (
    "Instance attestation only. Not catalog membership, not a clean-scan claim, "
    "and not operator endorsement. A valid FAIL/BLOCK attestation is verified "
    "evidence of failure. The relying party owns the trust decision."
)

# Stable evidence fields; everything else (timestamps, paths, args, results,
# free-text messages/warnings) is excluded from the evidence digest.
_STABLE_FINDING_FIELDS = ("finding_id", "rule_id", "severity", "category")


def _require_id(value: Any, name: str, pattern: re.Pattern[str] = _ID_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise AttestationSigningError(f"{name}_invalid")
    return value


def _require_sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise AttestationSigningError(f"{name}_invalid")
    return value


def _sanitize_references(references: Mapping[str, Any] | None) -> dict[str, str]:
    if references is None:
        return {}
    if not isinstance(references, Mapping) or len(references) > _MAX_REFERENCES:
        raise AttestationSigningError("references_invalid")
    cleaned: dict[str, str] = {}
    for key, value in references.items():
        if not isinstance(key, str) or not _ID_RE.fullmatch(key):
            raise AttestationSigningError("reference_key_invalid")
        text = str(value)
        if len(text.encode("utf-8")) > _MAX_REFERENCE_BYTES or not all(ch.isprintable() for ch in text):
            raise AttestationSigningError("reference_value_invalid")
        cleaned[key] = text
    return {k: cleaned[k] for k in sorted(cleaned)}


def compute_evidence_digest(findings: Iterable[Mapping[str, Any]]) -> str:
    """Return a stable sha256 over findings' identity fields only.

    Uses stable finding IDs and a canonical order and *excludes* mutable
    timestamps, raw paths, arguments, results, and warning/exception text, so
    two scans of the same instance state produce the same digest.
    """
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, finding in enumerate(findings):
        if index >= _MAX_FINDINGS:
            raise AttestationSigningError("too_many_findings")
        if not isinstance(finding, Mapping):
            raise AttestationSigningError("finding_invalid")
        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            raise AttestationSigningError("finding_id_required")
        if finding_id in seen:
            raise AttestationSigningError("duplicate_finding_id")
        seen.add(finding_id)
        normalized.append({field_name: str(finding.get(field_name, "")) for field_name in _STABLE_FINDING_FIELDS})
    normalized.sort(key=lambda item: item["finding_id"])
    return hashlib.sha256(_canonical_bytes({"findings": normalized})).hexdigest()


@dataclass(frozen=True, slots=True)
class MCPScanEvidence:
    """Validated inputs bound into a signed MCP scan attestation.

    Generation happens only after scan execution completes; "completed" never
    means "clean" — the verdict is supplied by the caller and carried verbatim.
    """

    tenant_id: str
    scan_id: str
    run_id: str
    catalog_id: str
    instance_digest: str
    capability_fingerprint: str
    sbom_digest: str
    evidence_digest: str
    verdict: str
    issued_at: datetime
    observed_at: datetime
    scanner_version: str = __version__
    references: Mapping[str, Any] | None = None
    ttl_seconds: int = _DEFAULT_TTL_SECONDS
    nonce: str = ""
    attestation_id: str = ""

    def __post_init__(self) -> None:
        try:
            _validate_policy_text(self.tenant_id, "tenant_id", _MAX_TENANT_ID_BYTES)
        except AttestationTrustError as exc:
            raise AttestationSigningError(str(exc)) from None
        _require_id(self.scan_id, "scan_id")
        _require_id(self.run_id, "run_id")
        _require_id(self.catalog_id, "catalog_id")
        _require_sha256(self.instance_digest, "instance_digest")
        _require_sha256(self.sbom_digest, "sbom_digest")
        _require_sha256(self.evidence_digest, "evidence_digest")
        _require_id(self.capability_fingerprint, "capability_fingerprint", _FINGERPRINT_RE)
        _require_id(self.scanner_version, "scanner_version", _FINGERPRINT_RE)
        if self.verdict not in _VALID_VERDICTS:
            raise AttestationSigningError("verdict_invalid")
        if not 1 <= self.ttl_seconds <= _MAX_MCP_MAX_AGE_SECONDS:
            raise AttestationSigningError("ttl_seconds_invalid")
        if self.nonce and not _NONCE_RE.fullmatch(self.nonce):
            raise AttestationSigningError("nonce_invalid")
        if self.attestation_id and not _ATTESTATION_ID_RE.fullmatch(self.attestation_id):
            raise AttestationSigningError("attestation_id_invalid")
        _normalize_datetime(self.issued_at)
        _normalize_datetime(self.observed_at)
        object.__setattr__(self, "references", _sanitize_references(self.references))


def build_mcp_scan_statement(evidence: MCPScanEvidence) -> dict[str, Any]:
    """Build the canonical in-toto statement bound by the signature."""
    import secrets
    import uuid

    issued = _normalize_datetime(evidence.issued_at)
    observed = _normalize_datetime(evidence.observed_at)
    expires = issued + timedelta(seconds=evidence.ttl_seconds)
    nonce = evidence.nonce or secrets.token_hex(16)
    attestation_id = evidence.attestation_id or str(uuid.uuid4())
    return {
        "_type": _MCP_STATEMENT_TYPE,
        "subject": [{"name": evidence.catalog_id, "digest": {"sha256": evidence.instance_digest}}],
        "predicateType": _MCP_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {"buildType": _MCP_BUILD_TYPE},
            "runDetails": {
                "builder": {"id": _MCP_BUILDER_ID, "version": {"agent-bom": evidence.scanner_version}},
                "metadata": {"startedOn": observed.isoformat(), "finishedOn": issued.isoformat()},
            },
            "agentBom": {
                "tenantId": evidence.tenant_id,
                "attestationId": attestation_id,
                "nonce": nonce,
                "scanId": evidence.scan_id,
                "runId": evidence.run_id,
                "issuedAt": issued.isoformat(),
                "observedAt": observed.isoformat(),
                "expiresAt": expires.isoformat(),
                "scannerVersion": evidence.scanner_version,
                "catalogId": evidence.catalog_id,
                "instanceDigest": evidence.instance_digest,
                "capabilityFingerprint": evidence.capability_fingerprint,
                "sbomDigest": evidence.sbom_digest,
                "evidenceDigest": evidence.evidence_digest,
                "references": dict(evidence.references or {}),
                "verdict": evidence.verdict,
            },
        },
    }


class Ed25519MCPScanSigner:
    """Ed25519 signer over the dedicated MCP signing key domain.

    Private keys are file/secret-manager references resolved from
    ``AGENT_BOM_MCP_SCAN_ED25519_PRIVATE_KEY_PEM`` (or its ``_FILE`` variant),
    never raw env/API/log/artifact values, and never the compliance key.
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise AttestationSigningError("mcp_signing_key_not_ed25519")
        self._private_key = private_key
        self._key_id = _public_key_id(private_key.public_key())

    @classmethod
    def from_env(cls) -> Ed25519MCPScanSigner:
        from agent_bom.api.secret_source import resolve_secret

        try:
            pem = resolve_secret(_MCP_PRIVATE_KEY_ENV)
        except (OSError, ValueError):
            raise AttestationSigningError("mcp_signing_key_invalid") from None
        if not pem:
            raise AttestationSigningError("mcp_signing_key_required")
        try:
            loaded = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        except (TypeError, ValueError):
            raise AttestationSigningError("mcp_signing_key_invalid") from None
        if not isinstance(loaded, Ed25519PrivateKey):
            raise AttestationSigningError("mcp_signing_key_not_ed25519")
        return cls(loaded)

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)


def sign_mcp_scan_attestation(
    evidence: MCPScanEvidence,
    *,
    signer: Ed25519MCPScanSigner | None = None,
) -> dict[str, Any]:
    """Produce a DSSE envelope for a completed MCP scan.

    Missing signing configuration fails closed (no compliance/audit fallback).
    """
    active_signer = signer or Ed25519MCPScanSigner.from_env()
    statement = build_mcp_scan_statement(evidence)
    payload = _canonical_bytes(statement)
    if len(payload) > _MAX_PAYLOAD_BYTES:
        raise AttestationSigningError("attestation_payload_too_large")
    signature = active_signer.sign(dsse_pae(_MCP_PAYLOAD_TYPE, payload))
    return {
        "payloadType": _MCP_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": active_signer.key_id, "sig": base64.b64encode(signature).decode("ascii")}],
        "_agentBom": {"schemaVersion": _MCP_SCHEMA_VERSION},
    }


@dataclass(frozen=True, slots=True)
class MCPScanTrustPolicy:
    """Operator-controlled verifier policy: which signers/tenant/freshness."""

    keys: tuple[_TrustedEd25519Key, ...]
    expected_tenant_id: str
    expected_builder_id: str = _MCP_BUILDER_ID
    expected_predicate_type: str = _MCP_PREDICATE_TYPE
    max_age_seconds: int = 24 * 60 * 60
    clock_skew_seconds: int = 60
    policy_id: str = "default"
    policy_version: str = "1"

    def __post_init__(self) -> None:
        _validate_policy_text(self.expected_tenant_id, "expected_tenant_id", _MAX_TENANT_ID_BYTES)
        if not self.keys:
            raise AttestationTrustError("trusted_public_key_required")
        if len(self.keys) > _MAX_TRUSTED_KEYS:
            raise AttestationTrustError("too_many_trusted_public_keys")
        key_ids = [key.key_id for key in self.keys]
        if len(key_ids) != len(set(key_ids)):
            raise AttestationTrustError("ambiguous_trusted_key_id")
        if not 1 <= self.max_age_seconds <= _MAX_MCP_MAX_AGE_SECONDS:
            raise AttestationTrustError("max_age_seconds_invalid")
        if not 0 <= self.clock_skew_seconds <= _MAX_MCP_CLOCK_SKEW_SECONDS:
            raise AttestationTrustError("clock_skew_seconds_invalid")

    @classmethod
    def from_public_key_pems(
        cls,
        public_key_pems: Iterable[str],
        *,
        expected_tenant_id: str,
        expected_builder_id: str = _MCP_BUILDER_ID,
        expected_predicate_type: str = _MCP_PREDICATE_TYPE,
        max_age_seconds: int = 24 * 60 * 60,
        clock_skew_seconds: int = 60,
        policy_id: str = "default",
        policy_version: str = "1",
    ) -> MCPScanTrustPolicy:
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
        return cls(
            keys=tuple(by_id[key_id] for key_id in sorted(by_id)),
            expected_tenant_id=expected_tenant_id,
            expected_builder_id=expected_builder_id,
            expected_predicate_type=expected_predicate_type,
            max_age_seconds=max_age_seconds,
            clock_skew_seconds=clock_skew_seconds,
            policy_id=policy_id,
            policy_version=policy_version,
        )

    def resolve(self, key_id: str) -> Ed25519PublicKey | None:
        matches = [key.public_key for key in self.keys if key.key_id == key_id]
        return matches[0] if len(matches) == 1 else None


@dataclass
class MCPScanVerification:
    """Outcome of verifying one MCP scan attestation against operator trust."""

    verified: bool = False
    trust_state: str = "unknown"
    verdict: str = "UNKNOWN"
    signature_valid: bool = False
    reason: str = ""
    key_id: str | None = None
    tenant_id: str = ""
    attestation_id: str = ""
    scan_id: str = ""
    run_id: str = ""
    catalog_id: str = ""
    instance_digest: str = ""
    capability_fingerprint: str = ""
    sbom_digest: str = ""
    evidence_digest: str = ""
    scanner_version: str = ""
    issued_at: str = ""
    observed_at: str = ""
    expires_at: str = ""
    policy_id: str = ""
    policy_version: str = ""
    checks: list[str] = field(default_factory=list)
    references: dict[str, str] = field(default_factory=dict)


def _decode_payload(envelope: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    encoded = envelope.get("payload")
    if not isinstance(encoded, str):
        raise ValueError
    payload = base64.b64decode(encoded, validate=True)
    if len(payload) > _MAX_PAYLOAD_BYTES:
        raise OverflowError
    return payload, _load_json_object(payload)


def _fail(result: MCPScanVerification, *, trust_state: str, reason: str, check: str | None = None) -> MCPScanVerification:
    result.verified = False
    result.trust_state = trust_state
    result.reason = reason
    if check:
        result.checks.append(check)
    return result


def verify_mcp_scan_attestation(
    envelope: Mapping[str, Any],
    *,
    trust_policy: MCPScanTrustPolicy | None,
    now: datetime | None = None,
    revoked_ids: frozenset[str] = frozenset(),
) -> MCPScanVerification:
    """Verify a signed MCP scan attestation against operator trust policy.

    Pure and repeatable (no replay consumption). Trust is established only from
    the policy; embedded key material is never sufficient. Signature validity is
    orthogonal to the carried verdict.
    """
    result = MCPScanVerification()
    if trust_policy is not None:
        result.policy_id = trust_policy.policy_id
        result.policy_version = trust_policy.policy_version

    if not isinstance(envelope, Mapping):
        return _fail(result, trust_state="unknown", reason="malformed_attestation")

    metadata = envelope.get("_agentBom")
    metadata_map: Mapping[str, Any] = metadata if isinstance(metadata, Mapping) else {}
    version = metadata_map.get("schemaVersion")
    if version is None:
        return _fail(result, trust_state="unsigned", reason="unsigned_or_unrecognized")
    if version != _MCP_SCHEMA_VERSION:
        return _fail(result, trust_state="unknown", reason="unsupported_attestation_version")
    if "algorithm" in metadata_map:
        return _fail(result, trust_state="invalid", reason="algorithm_metadata_invalid")

    if envelope.get("payloadType") != _MCP_PAYLOAD_TYPE:
        return _fail(result, trust_state="invalid", reason="payload_type_invalid")

    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1 or not isinstance(signatures[0], Mapping):
        return _fail(result, trust_state="invalid", reason="ambiguous_signatures")
    signature = signatures[0]
    if set(signature) != {"keyid", "sig"}:
        return _fail(result, trust_state="invalid", reason="signature_metadata_invalid")
    key_id = signature.get("keyid")
    if not isinstance(key_id, str) or not _SHA256_RE.fullmatch(key_id):
        return _fail(result, trust_state="invalid", reason="key_id_invalid")

    try:
        payload, statement = _decode_payload(envelope)
    except OverflowError:
        return _fail(result, trust_state="invalid", reason="attestation_payload_too_large")
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError, ValueError, _DuplicateJsonKeyError):
        return _fail(result, trust_state="invalid", reason="malformed_attestation")

    predicate = statement.get("predicate")
    agent_bom = predicate.get("agentBom") if isinstance(predicate, Mapping) else None
    if not isinstance(agent_bom, Mapping):
        return _fail(result, trust_state="invalid", reason="attestation_metadata_invalid")

    # Read the (as-yet unauthenticated) attestation id only for revocation, a
    # fail-closed downgrade that outranks every positive state by precedence.
    attestation_id = agent_bom.get("attestationId")
    if isinstance(attestation_id, str) and attestation_id in revoked_ids:
        result.attestation_id = attestation_id
        return _fail(result, trust_state="revoked", reason="attestation_revoked")

    if trust_policy is None:
        return _fail(result, trust_state="unknown", reason="trust_policy_required", check="signer_trust=missing")

    public_key = trust_policy.resolve(key_id)
    if public_key is None:
        return _fail(result, trust_state="invalid", reason="untrusted_signer", check="signer_trust=untrusted")

    signature_valid = _verify_ed25519(public_key, signature.get("sig"), dsse_pae(_MCP_PAYLOAD_TYPE, payload))
    result.signature_valid = signature_valid
    result.checks.append("dsse_signature=" + ("ok" if signature_valid else "FAIL"))
    if not signature_valid:
        return _fail(result, trust_state="invalid", reason="signature_invalid")
    result.key_id = key_id

    # Signature is authentic; now populate authenticated fields (verdict included
    # verbatim — it is orthogonal to signature trust).
    verdict = agent_bom.get("verdict")
    result.verdict = verdict if isinstance(verdict, str) and verdict in _VALID_VERDICTS else "UNKNOWN"

    semantic_reason = _semantic_check(statement, agent_bom, trust_policy, result, now=now)
    if semantic_reason:
        # Expiry/future are freshness states; everything else is an invalid match.
        trust_state = "expired" if semantic_reason in {"attestation_expired", "attestation_max_age_exceeded"} else "invalid"
        return _fail(result, trust_state=trust_state, reason=semantic_reason, check="semantic_policy=FAIL")

    result.checks.append("semantic_policy=ok")
    result.verified = True
    result.trust_state = "verified"
    result.reason = "verified"
    return result


def _semantic_check(
    statement: Mapping[str, Any],
    agent_bom: Mapping[str, Any],
    policy: MCPScanTrustPolicy,
    result: MCPScanVerification,
    *,
    now: datetime | None,
) -> str:
    if statement.get("predicateType") != policy.expected_predicate_type:
        return "predicate_type_mismatch"
    predicate = statement.get("predicate")
    run_details = predicate.get("runDetails") if isinstance(predicate, Mapping) else None
    builder = run_details.get("builder") if isinstance(run_details, Mapping) else None
    if not isinstance(builder, Mapping) or builder.get("id") != policy.expected_builder_id:
        return "builder_mismatch"

    tenant_id = agent_bom.get("tenantId")
    if tenant_id != policy.expected_tenant_id:
        return "tenant_mismatch"
    nonce = agent_bom.get("nonce")
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        return "attestation_nonce_invalid"
    attestation_id = agent_bom.get("attestationId")
    if not isinstance(attestation_id, str) or not _ATTESTATION_ID_RE.fullmatch(attestation_id):
        return "attestation_id_invalid"

    scan_id = agent_bom.get("scanId")
    run_id = agent_bom.get("runId")
    catalog_id = agent_bom.get("catalogId")
    if not (isinstance(scan_id, str) and _ID_RE.fullmatch(scan_id)):
        return "scan_id_invalid"
    if not (isinstance(run_id, str) and _ID_RE.fullmatch(run_id)):
        return "run_id_invalid"
    if not (isinstance(catalog_id, str) and _ID_RE.fullmatch(catalog_id)):
        return "catalog_id_invalid"

    for name, key in (
        ("instance_digest", "instanceDigest"),
        ("sbom_digest", "sbomDigest"),
        ("evidence_digest", "evidenceDigest"),
    ):
        value = agent_bom.get(key)
        if not (isinstance(value, str) and _SHA256_RE.fullmatch(value)):
            return f"{name}_invalid"

    issued_at = _parse_signed_datetime(agent_bom.get("issuedAt"))
    observed_at = _parse_signed_datetime(agent_bom.get("observedAt"))
    expires_at = _parse_signed_datetime(agent_bom.get("expiresAt"))
    if issued_at is None or observed_at is None or expires_at is None or expires_at <= issued_at:
        return "attestation_time_invalid"
    current = _normalize_datetime(now or datetime.now(timezone.utc))
    skew = timedelta(seconds=policy.clock_skew_seconds)
    if issued_at > current + skew:
        return "issued_in_future"
    if current > expires_at + skew:
        return "attestation_expired"
    if (current - issued_at).total_seconds() > policy.max_age_seconds:
        return "attestation_max_age_exceeded"

    capability = agent_bom.get("capabilityFingerprint")
    if not (isinstance(capability, str) and _FINGERPRINT_RE.fullmatch(capability)):
        return "capability_fingerprint_invalid"
    scanner_version = agent_bom.get("scannerVersion")
    if not (isinstance(scanner_version, str) and _FINGERPRINT_RE.fullmatch(scanner_version)):
        return "scanner_version_invalid"
    references = agent_bom.get("references")
    if references is not None and not isinstance(references, Mapping):
        return "references_invalid"

    result.tenant_id = tenant_id
    result.attestation_id = attestation_id
    result.scan_id = scan_id
    result.run_id = run_id
    result.catalog_id = catalog_id
    result.instance_digest = str(agent_bom.get("instanceDigest"))
    result.sbom_digest = str(agent_bom.get("sbomDigest"))
    result.evidence_digest = str(agent_bom.get("evidenceDigest"))
    result.capability_fingerprint = capability
    result.scanner_version = scanner_version
    result.issued_at = issued_at.isoformat()
    result.observed_at = observed_at.isoformat()
    result.expires_at = expires_at.isoformat()
    result.references = {str(k): str(v) for k, v in (references or {}).items()}
    return ""


def accept_mcp_scan_attestation(
    envelope: Mapping[str, Any],
    *,
    trust_policy: MCPScanTrustPolicy | None,
    replay_store: AttestationReplayStore,
    now: datetime | None = None,
    revoked_ids: frozenset[str] = frozenset(),
) -> MCPScanVerification:
    """Verify, then consume the attestation identity once (explicit acceptance).

    Distinct from pure verification: acceptance mutates the replay store and so
    is not repeatable. Use for import/promotion flows, never for read-only
    verify surfaces.
    """
    result = verify_mcp_scan_attestation(envelope, trust_policy=trust_policy, now=now, revoked_ids=revoked_ids)
    if not result.verified:
        return result
    current = _normalize_datetime(now or datetime.now(timezone.utc))
    expires_at = _parse_signed_datetime(result.expires_at)
    assert expires_at is not None
    _payload, statement = _decode_payload(envelope)
    agent_bom = statement["predicate"]["agentBom"]
    status = replay_store.consume(
        tenant_id=result.tenant_id,
        evidence_id=result.attestation_id,
        nonce=str(agent_bom["nonce"]),
        expires_at=expires_at + timedelta(seconds=(trust_policy.clock_skew_seconds if trust_policy else 0)),
        now=current,
    )
    if status == "accepted":
        result.checks.append("replay_guard=accepted")
        return result
    result.verified = False
    result.reason = {
        "replay": "attestation_replay_detected",
        "full": "replay_store_full",
        "unavailable": "replay_store_unavailable",
    }.get(status, "replay_store_unavailable")
    result.checks.append("replay_guard=rejected")
    return result


def mcp_catalog_trust_label(verification: MCPScanVerification) -> str:
    """Map a verification to the catalog instance-attestation trust label.

    Distinct from generic *catalog membership* ("catalog verified") — this is an
    instance-level signal only.
    """
    state = verification.trust_state if verification.trust_state in _TRUST_STATES else "unknown"
    return f"instance_{state}"


def mcp_catalog_attestation_receipt(verification: MCPScanVerification) -> dict[str, Any]:
    """Return a portable, non-promoting attestation receipt for catalog surfaces.

    A receipt of "this instance produced a verifier-readable attestation under
    policy X at time Y" — never an endorsement of the server, operator, or
    verdict. A relying party attaches it without re-running the scan.
    """
    return {
        "kind": "mcp_scan_attestation_receipt/v1",
        "trust_state": verification.trust_state,
        "trust_label": mcp_catalog_trust_label(verification),
        "verified": verification.verified,
        "verdict": verification.verdict,
        "reason": verification.reason,
        "tenant_id": verification.tenant_id,
        "attestation_id": verification.attestation_id,
        "scan_id": verification.scan_id,
        "run_id": verification.run_id,
        "catalog_id": verification.catalog_id,
        "instance_digest": verification.instance_digest,
        "capability_fingerprint": verification.capability_fingerprint,
        "sbom_digest": verification.sbom_digest,
        "evidence_digest": verification.evidence_digest,
        "scanner_version": verification.scanner_version,
        "signer_key_id": verification.key_id,
        "policy_id": verification.policy_id,
        "policy_version": verification.policy_version,
        "issued_at": verification.issued_at,
        "observed_at": verification.observed_at,
        "expires_at": verification.expires_at,
        "references": dict(verification.references),
        "notice": _NON_PROMOTION_NOTICE,
    }
