"""Sign and verify generated SBOMs at an explicit DSSE trust boundary.

New attestations use DSSE pre-authentication encoding (PAE) and Ed25519 signing.
Verification trusts only caller-supplied Ed25519 keys or an explicitly pinned,
offline Sigstore identity/issuer policy; envelope metadata and embedded legacy
keys are evidence, never trust anchors. Older self-consistent envelopes remain
readable but are always reported as legacy and untrusted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import sqlite3
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol
from urllib.parse import urlparse

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
_MAX_SIGNATURE_BYTES = 16 * 1024
_MAX_TRUSTED_KEYS = 32
_MAX_SIGSTORE_BUNDLE_BYTES = 16 * 1024 * 1024
_MAX_POLICY_TEXT_BYTES = 2048
_MAX_TENANT_ID_BYTES = 256
_MAX_MAX_AGE_SECONDS = 30 * 24 * 60 * 60
_MAX_CLOCK_SKEW_SECONDS = 300
_DEFAULT_ATTESTATION_TTL_SECONDS = 15 * 60
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_EVIDENCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")


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


class AttestationReplayStore(Protocol):
    """Consume a signed evidence identity once until its expiry."""

    def consume(
        self,
        *,
        tenant_id: str,
        evidence_id: str,
        nonce: str,
        expires_at: datetime,
        now: datetime,
    ) -> str: ...


class SigstoreVerificationAdapter(Protocol):
    """Verify exact bytes against an externally supplied Sigstore bundle."""

    def verify(
        self,
        *,
        signed_bytes: bytes,
        signature_b64: str,
        bundle_bytes: bytes,
        trusted_root_bytes: bytes,
        identity_regexp: str,
        issuer: str,
    ) -> bool: ...


class MemoryAttestationReplayStore:
    """Bounded process-local replay guard for library callers and tests."""

    def __init__(self, *, max_entries: int = 10_000) -> None:
        if max_entries < 1 or max_entries > 1_000_000:
            raise AttestationTrustError("replay_store_size_invalid")
        self._max_entries = max_entries
        self._entries: dict[tuple[str, str, str], float] = {}
        self._lock = threading.Lock()

    def consume(
        self,
        *,
        tenant_id: str,
        evidence_id: str,
        nonce: str,
        expires_at: datetime,
        now: datetime,
    ) -> str:
        key = (tenant_id, evidence_id, nonce)
        now_epoch = now.timestamp()
        with self._lock:
            self._entries = {entry: expiry for entry, expiry in self._entries.items() if expiry > now_epoch}
            if key in self._entries:
                return "replay"
            if len(self._entries) >= self._max_entries:
                return "full"
            self._entries[key] = expires_at.timestamp()
        return "accepted"


class SQLiteAttestationReplayStore:
    """SQLite-backed replay guard shared safely across CLI processes."""

    def __init__(self, path: str | Path, *, max_entries: int = 100_000) -> None:
        if max_entries < 1 or max_entries > 1_000_000:
            raise AttestationTrustError("replay_store_size_invalid")
        self._path = Path(path)
        self._max_entries = max_entries

    def consume(
        self,
        *,
        tenant_id: str,
        evidence_id: str,
        nonce: str,
        expires_at: datetime,
        now: datetime,
    ) -> str:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self._path, timeout=5) as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS attestation_replay ("
                    "tenant_id TEXT NOT NULL, evidence_id TEXT NOT NULL, nonce TEXT NOT NULL, "
                    "expires_at REAL NOT NULL, PRIMARY KEY (tenant_id, evidence_id, nonce))"
                )
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("DELETE FROM attestation_replay WHERE expires_at <= ?", (now.timestamp(),))
                existing = connection.execute(
                    "SELECT 1 FROM attestation_replay WHERE tenant_id = ? AND evidence_id = ? AND nonce = ?",
                    (tenant_id, evidence_id, nonce),
                ).fetchone()
                if existing is not None:
                    connection.rollback()
                    return "replay"
                count = int(connection.execute("SELECT COUNT(*) FROM attestation_replay").fetchone()[0])
                if count >= self._max_entries:
                    connection.rollback()
                    return "full"
                connection.execute(
                    "INSERT INTO attestation_replay (tenant_id, evidence_id, nonce, expires_at) VALUES (?, ?, ?, ?)",
                    (tenant_id, evidence_id, nonce, expires_at.timestamp()),
                )
                connection.commit()
            return "accepted"
        except sqlite3.Error:
            return "unavailable"


def _validate_policy_text(value: str, field_name: str, max_bytes: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value.encode("utf-8")) > max_bytes
        or not all(char.isprintable() for char in value)
    ):
        raise AttestationTrustError(f"{field_name}_required" if not value else f"{field_name}_invalid")


@dataclass(frozen=True, slots=True)
class AttestationTrustPolicy:
    """Bounded verifier policy for signer, semantic, freshness, and replay trust."""

    keys: tuple[_TrustedEd25519Key, ...]
    expected_tenant_id: str
    expected_builder_id: str = _BUILDER_ID
    expected_predicate_type: str = _PREDICATE_TYPE
    max_age_seconds: int = 60 * 60
    clock_skew_seconds: int = 60
    replay_store: AttestationReplayStore = field(default_factory=MemoryAttestationReplayStore)
    sigstore_identity_regexp: str | None = None
    sigstore_issuer: str | None = None
    sigstore_trusted_root: bytes | None = None
    sigstore_trusted_root_sha256: str | None = None

    def __post_init__(self) -> None:
        _validate_policy_text(self.expected_tenant_id, "expected_tenant_id", _MAX_TENANT_ID_BYTES)
        _validate_policy_text(self.expected_builder_id, "expected_builder_id", _MAX_POLICY_TEXT_BYTES)
        _validate_policy_text(self.expected_predicate_type, "expected_predicate_type", _MAX_POLICY_TEXT_BYTES)
        if not 1 <= self.max_age_seconds <= _MAX_MAX_AGE_SECONDS:
            raise AttestationTrustError("max_age_seconds_invalid")
        if not 0 <= self.clock_skew_seconds <= _MAX_CLOCK_SKEW_SECONDS:
            raise AttestationTrustError("clock_skew_seconds_invalid")
        if len(self.keys) > _MAX_TRUSTED_KEYS:
            raise AttestationTrustError("too_many_trusted_public_keys")
        key_ids = [key.key_id for key in self.keys]
        if len(key_ids) != len(set(key_ids)):
            raise AttestationTrustError("ambiguous_trusted_key_id")
        sigstore_configured = any(
            value is not None
            for value in (
                self.sigstore_identity_regexp,
                self.sigstore_issuer,
                self.sigstore_trusted_root,
                self.sigstore_trusted_root_sha256,
            )
        )
        if self.keys and sigstore_configured:
            raise AttestationTrustError("ambiguous_signer_policy")
        if not self.keys and not sigstore_configured:
            raise AttestationTrustError("trusted_public_key_required")
        if sigstore_configured:
            identity = self.sigstore_identity_regexp or ""
            issuer = self.sigstore_issuer or ""
            _validate_policy_text(identity, "sigstore_identity", _MAX_POLICY_TEXT_BYTES)
            _validate_policy_text(issuer, "sigstore_issuer", _MAX_POLICY_TEXT_BYTES)
            try:
                re.compile(identity)
            except re.error:
                raise AttestationTrustError("sigstore_identity_invalid") from None
            parsed = urlparse(issuer)
            if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise AttestationTrustError("sigstore_issuer_invalid")
            if self.sigstore_trusted_root is None or not _SHA256_RE.fullmatch(self.sigstore_trusted_root_sha256 or ""):
                raise AttestationTrustError("sigstore_trusted_root_required")

    @classmethod
    def from_public_key_pems(
        cls,
        public_key_pems: Iterable[str],
        *,
        expected_tenant_id: str,
        expected_builder_id: str = _BUILDER_ID,
        expected_predicate_type: str = _PREDICATE_TYPE,
        max_age_seconds: int = 60 * 60,
        clock_skew_seconds: int = 60,
        replay_store: AttestationReplayStore | None = None,
    ) -> AttestationTrustPolicy:
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
            replay_store=replay_store or MemoryAttestationReplayStore(),
        )

    @classmethod
    def from_sigstore(
        cls,
        *,
        expected_identity_regexp: str,
        expected_issuer: str,
        trusted_root_path: str | Path,
        expected_tenant_id: str,
        expected_builder_id: str = _BUILDER_ID,
        expected_predicate_type: str = _PREDICATE_TYPE,
        max_age_seconds: int = 60 * 60,
        clock_skew_seconds: int = 60,
        replay_store: AttestationReplayStore | None = None,
    ) -> AttestationTrustPolicy:
        trusted_root = Path(trusted_root_path)
        try:
            if not trusted_root.is_file() or trusted_root.stat().st_size > _MAX_SIGSTORE_BUNDLE_BYTES:
                raise AttestationTrustError("sigstore_trusted_root_invalid")
            trusted_root_bytes = trusted_root.read_bytes()
            _load_json_object(trusted_root_bytes)
        except AttestationTrustError:
            raise
        except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError, _DuplicateJsonKeyError):
            raise AttestationTrustError("sigstore_trusted_root_invalid") from None
        return cls(
            keys=(),
            expected_tenant_id=expected_tenant_id,
            expected_builder_id=expected_builder_id,
            expected_predicate_type=expected_predicate_type,
            max_age_seconds=max_age_seconds,
            clock_skew_seconds=clock_skew_seconds,
            replay_store=replay_store or MemoryAttestationReplayStore(),
            sigstore_identity_regexp=expected_identity_regexp,
            sigstore_issuer=expected_issuer,
            sigstore_trusted_root=trusted_root_bytes,
            sigstore_trusted_root_sha256=hashlib.sha256(trusted_root_bytes).hexdigest(),
        )

    def resolve(self, key_id: str) -> Ed25519PublicKey | None:
        matches = [key.public_key for key in self.keys if key.key_id == key_id]
        return matches[0] if len(matches) == 1 else None

    @property
    def signer_mode(self) -> str:
        return "sigstore" if self.sigstore_identity_regexp is not None else "ed25519"

    @property
    def sigstore_key_id(self) -> str | None:
        if self.signer_mode != "sigstore":
            return None
        identity = self.sigstore_identity_regexp or ""
        issuer = self.sigstore_issuer or ""
        root_digest = self.sigstore_trusted_root_sha256 or ""
        return hashlib.sha256(f"sigstore\0{identity}\0{issuer}\0{root_digest}".encode()).hexdigest()


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
    tenant_id: str = ""
    evidence_id: str = ""
    issued_at: str = ""
    expires_at: str = ""


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
    tenant_id: str = "local",
    issued_at: datetime | None = None,
    ttl_seconds: int = _DEFAULT_ATTESTATION_TTL_SECONDS,
    nonce: str | None = None,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    _validate_signed_metadata(
        tenant_id=tenant_id,
        ttl_seconds=ttl_seconds,
        nonce=nonce,
        evidence_id=evidence_id,
        issued_at=issued_at,
    )
    name = Path(sbom_path).name
    digest = compute_sbom_digest(sbom_bytes)
    issued = _normalize_datetime(issued_at or datetime.now(timezone.utc))
    expires = issued + timedelta(seconds=ttl_seconds)
    nonce_value = nonce or secrets.token_hex(16)
    evidence_value = evidence_id or str(uuid.uuid4())
    now = issued.isoformat()
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
            "agentBom": {
                "tenantId": tenant_id,
                "issuedAt": now,
                "expiresAt": expires.isoformat(),
                "nonce": nonce_value,
                "evidenceId": evidence_value,
            },
        },
    }


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AttestationSigningError("issued_at_timezone_required")
    return value.astimezone(timezone.utc)


def _validate_signed_metadata(
    *,
    tenant_id: str,
    ttl_seconds: int,
    nonce: str | None,
    evidence_id: str | None,
    issued_at: datetime | None,
) -> None:
    try:
        _validate_policy_text(tenant_id, "tenant_id", _MAX_TENANT_ID_BYTES)
    except AttestationTrustError as exc:
        raise AttestationSigningError(str(exc)) from None
    if not 1 <= ttl_seconds <= _MAX_MAX_AGE_SECONDS:
        raise AttestationSigningError("attestation_ttl_invalid")
    if nonce is not None and not _NONCE_RE.fullmatch(nonce):
        raise AttestationSigningError("attestation_nonce_invalid")
    if evidence_id is not None and not _EVIDENCE_ID_RE.fullmatch(evidence_id):
        raise AttestationSigningError("attestation_evidence_id_invalid")
    if issued_at is not None:
        _normalize_datetime(issued_at)


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
    tenant_id: str = "local",
    issued_at: datetime | None = None,
    ttl_seconds: int = _DEFAULT_ATTESTATION_TTL_SECONDS,
    nonce: str | None = None,
    evidence_id: str | None = None,
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

    statement = build_intoto_statement(
        src,
        sbom_bytes,
        sbom_format=sbom_format,
        tenant_id=tenant_id,
        issued_at=issued_at,
        ttl_seconds=ttl_seconds,
        nonce=nonce,
        evidence_id=evidence_id,
    )
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
    if statement.get("_type") != _STATEMENT_TYPE:
        return ""
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], Mapping):
        return ""
    subject = subjects[0]
    if subject.get("name") != expected_name or not isinstance(subject.get("digest"), Mapping):
        return ""
    digest = subject["digest"].get("sha256")
    return str(digest) if isinstance(digest, str) and _SHA256_RE.fullmatch(digest) else ""


def _parse_signed_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _semantic_policy_result(
    statement: Mapping[str, Any],
    policy: AttestationTrustPolicy,
    *,
    now: datetime,
) -> tuple[str, dict[str, str], datetime | None]:
    if statement.get("predicateType") != policy.expected_predicate_type:
        return "predicate_type_mismatch", {}, None
    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping):
        return "attestation_policy_metadata_invalid", {}, None
    run_details = predicate.get("runDetails")
    builder = run_details.get("builder") if isinstance(run_details, Mapping) else None
    if not isinstance(builder, Mapping) or builder.get("id") != policy.expected_builder_id:
        return "builder_mismatch", {}, None
    agent_bom = predicate.get("agentBom")
    if not isinstance(agent_bom, Mapping):
        return "attestation_policy_metadata_invalid", {}, None
    tenant_id = agent_bom.get("tenantId")
    nonce = agent_bom.get("nonce")
    evidence_id = agent_bom.get("evidenceId")
    if tenant_id != policy.expected_tenant_id:
        return "tenant_mismatch", {}, None
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        return "attestation_nonce_invalid", {}, None
    if not isinstance(evidence_id, str) or not _EVIDENCE_ID_RE.fullmatch(evidence_id):
        return "attestation_evidence_id_invalid", {}, None
    issued_at = _parse_signed_datetime(agent_bom.get("issuedAt"))
    expires_at = _parse_signed_datetime(agent_bom.get("expiresAt"))
    if issued_at is None or expires_at is None or expires_at <= issued_at:
        return "attestation_time_invalid", {}, None
    current = now.astimezone(timezone.utc)
    skew = timedelta(seconds=policy.clock_skew_seconds)
    if issued_at > current + skew:
        return "issued_in_future", {}, None
    if current > expires_at + skew:
        return "attestation_expired", {}, None
    if (current - issued_at).total_seconds() > policy.max_age_seconds:
        return "attestation_max_age_exceeded", {}, None
    return (
        "",
        {
            "tenant_id": tenant_id,
            "nonce": nonce,
            "evidence_id": evidence_id,
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
        },
        expires_at,
    )


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
    sigstore_bundle_path: str | Path | None = None,
    sigstore_verifier: SigstoreVerificationAdapter | None = None,
    now: datetime | None = None,
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
    signed_pae = dsse_pae(_DSSE_PAYLOAD_TYPE, payload)
    public_key: Ed25519PublicKey | None = None
    if trust_policy.signer_mode == "ed25519":
        result.algorithm = "Ed25519"
        public_key = trust_policy.resolve(key_id)
        if public_key is None:
            result.reason = "untrusted_signer"
            result.checks.append("signer_trust=untrusted")
            return result
        result.signature_valid = _verify_ed25519(public_key, signature.get("sig"), signed_pae)
    else:
        result.algorithm = "Sigstore"
        if sigstore_bundle_path is None:
            result.reason = "sigstore_bundle_required"
            return result
        if sigstore_verifier is None:
            result.reason = "sigstore_verifier_required"
            return result
        if key_id != trust_policy.sigstore_key_id:
            result.reason = "untrusted_signer"
            result.checks.append("signer_trust=untrusted")
            return result
        signature_b64 = signature.get("sig")
        try:
            signature_bytes = base64.b64decode(signature_b64, validate=True) if isinstance(signature_b64, str) else b""
        except (binascii.Error, ValueError):
            signature_bytes = b""
        if not signature_bytes or len(signature_bytes) > _MAX_SIGNATURE_BYTES:
            result.reason = "signature_invalid"
            return result
        assert isinstance(signature_b64, str)
        identity = trust_policy.sigstore_identity_regexp or ""
        issuer = trust_policy.sigstore_issuer or ""
        trusted_root_bytes = trust_policy.sigstore_trusted_root
        if trusted_root_bytes is None:
            result.reason = "sigstore_trusted_root_required"
            return result
        bundle_path = Path(sigstore_bundle_path)
        try:
            if not bundle_path.is_file() or bundle_path.stat().st_size > _MAX_SIGSTORE_BUNDLE_BYTES:
                result.reason = "sigstore_bundle_invalid"
                return result
            bundle_bytes = bundle_path.read_bytes()
            bundle = _load_json_object(bundle_bytes)
            message_signature = bundle.get("messageSignature")
            if not isinstance(message_signature, Mapping) or message_signature.get("signature") != signature_b64:
                result.reason = "sigstore_bundle_signature_mismatch"
                return result
        except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError, _DuplicateJsonKeyError):
            result.reason = "sigstore_bundle_invalid"
            return result
        result.signature_valid = sigstore_verifier.verify(
            signed_bytes=signed_pae,
            signature_b64=signature_b64,
            bundle_bytes=bundle_bytes,
            trusted_root_bytes=trusted_root_bytes,
            identity_regexp=identity,
            issuer=issuer,
        )
    result.key_id = key_id
    result.trust_status = "trusted"
    result.checks.append("dsse_signature=" + ("ok" if result.signature_valid else "FAIL"))

    if not result.signature_valid:
        result.reason = "signature_invalid"
        return result

    try:
        current = _normalize_datetime(now or datetime.now(timezone.utc))
    except AttestationSigningError:
        result.reason = "verification_time_invalid"
        return result
    policy_reason, signed_metadata, expires_at = _semantic_policy_result(statement, trust_policy, now=current)
    if policy_reason:
        result.reason = policy_reason
        result.checks.append("semantic_policy=FAIL")
        return result
    result.tenant_id = signed_metadata["tenant_id"]
    result.evidence_id = signed_metadata["evidence_id"]
    result.issued_at = signed_metadata["issued_at"]
    result.expires_at = signed_metadata["expires_at"]
    result.checks.append("semantic_policy=ok")

    detached_ok = True
    detached_reason = ""
    sig_path = Path(signature_path) if signature_path else Path(str(src) + _SIG_SUFFIX)
    if trust_policy.signer_mode == "ed25519" and sig_path.is_file() and public_key is not None:
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
    elif not detached_ok:
        result.reason = detached_reason
    else:
        assert expires_at is not None
        replay_status = trust_policy.replay_store.consume(
            tenant_id=result.tenant_id,
            evidence_id=result.evidence_id,
            nonce=signed_metadata["nonce"],
            expires_at=expires_at + timedelta(seconds=trust_policy.clock_skew_seconds),
            now=current,
        )
        if replay_status == "accepted":
            result.verified = True
            result.reason = "verified"
            result.checks.append("replay_guard=accepted")
        else:
            result.reason = {
                "replay": "attestation_replay_detected",
                "full": "replay_store_full",
                "unavailable": "replay_store_unavailable",
            }.get(replay_status, "replay_store_unavailable")
            result.checks.append("replay_guard=rejected")
    return result
