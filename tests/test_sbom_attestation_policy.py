"""Semantic and offline signer policy for SBOM attestations."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bom.cli._attest_group import attest_group
from agent_bom.sbom_attestation import (
    _ATTESTATION_SUFFIX,
    _DSSE_PAYLOAD_TYPE,
    _SIG_SUFFIX,
    AttestationTrustError,
    AttestationTrustPolicy,
    MemoryAttestationReplayStore,
    SQLiteAttestationReplayStore,
    dsse_pae,
    sign_sbom_file,
    verify_sbom_attestation,
)

_TENANT = "tenant-a"
_ISSUED_AT = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
_NONCE = "ab" * 16
_EVIDENCE_ID = "018f1f5e-7b44-7a86-b5af-010203040506"


def _write_sbom(tmp_path: Path) -> Path:
    path = tmp_path / "report.cdx.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}), encoding="utf-8")
    return path


def _keys(monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", private_pem)
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE", raising=False)
    return private_pem, public_pem


def _sign(path: Path) -> None:
    sign_sbom_file(
        path,
        tenant_id=_TENANT,
        issued_at=_ISSUED_AT,
        ttl_seconds=300,
        nonce=_NONCE,
        evidence_id=_EVIDENCE_ID,
    )


def _policy(public_pem: str, **overrides: object) -> AttestationTrustPolicy:
    values: dict[str, object] = {
        "expected_tenant_id": _TENANT,
        "max_age_seconds": 600,
        "clock_skew_seconds": 30,
        "replay_store": MemoryAttestationReplayStore(max_entries=8),
    }
    values.update(overrides)
    return AttestationTrustPolicy.from_public_key_pems([public_pem], **values)


def _trusted_root(tmp_path: Path) -> Path:
    path = tmp_path / "trusted-root.json"
    path.write_text(json.dumps({"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1"}))
    return path


def test_statement_policy_accepts_expected_builder_predicate_tenant_and_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_sbom(tmp_path)
    _private_pem, public_pem = _keys(monkeypatch)
    _sign(path)

    result = verify_sbom_attestation(path, trust_policy=_policy(public_pem), now=_ISSUED_AT + timedelta(seconds=60))

    assert result.verified is True
    assert result.reason == "verified"
    assert result.tenant_id == _TENANT
    assert result.evidence_id == _EVIDENCE_ID
    assert result.issued_at == _ISSUED_AT.isoformat()
    assert result.expires_at == (_ISSUED_AT + timedelta(seconds=300)).isoformat()
    assert "semantic_policy=ok" in result.checks
    assert "replay_guard=accepted" in result.checks


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"expected_builder_id": "https://builder.example/wrong"}, "builder_mismatch"),
        ({"expected_predicate_type": "https://predicate.example/wrong"}, "predicate_type_mismatch"),
        ({"expected_tenant_id": "tenant-b"}, "tenant_mismatch"),
    ],
)
def test_signed_statement_must_match_semantic_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    reason: str,
) -> None:
    path = _write_sbom(tmp_path)
    _private_pem, public_pem = _keys(monkeypatch)
    _sign(path)

    result = verify_sbom_attestation(
        path,
        trust_policy=_policy(public_pem, **overrides),
        now=_ISSUED_AT + timedelta(seconds=60),
    )

    assert result.verified is False
    assert result.signature_valid is True
    assert result.reason == reason


@pytest.mark.parametrize(
    ("now", "policy_overrides", "reason"),
    [
        (_ISSUED_AT - timedelta(seconds=31), {}, "issued_in_future"),
        (_ISSUED_AT + timedelta(seconds=331), {}, "attestation_expired"),
        (_ISSUED_AT + timedelta(seconds=121), {"max_age_seconds": 120}, "attestation_max_age_exceeded"),
    ],
)
def test_freshness_policy_rejects_future_expired_and_over_age_attestations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    now: datetime,
    policy_overrides: dict[str, object],
    reason: str,
) -> None:
    path = _write_sbom(tmp_path)
    _private_pem, public_pem = _keys(monkeypatch)
    _sign(path)

    result = verify_sbom_attestation(path, trust_policy=_policy(public_pem, **policy_overrides), now=now)

    assert result.verified is False
    assert result.signature_valid is True
    assert result.reason == reason


def test_replay_nonce_and_evidence_id_are_consumed_only_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_sbom(tmp_path)
    _private_pem, public_pem = _keys(monkeypatch)
    _sign(path)
    policy = _policy(public_pem)

    first = verify_sbom_attestation(path, trust_policy=policy, now=_ISSUED_AT + timedelta(seconds=60))
    replay = verify_sbom_attestation(path, trust_policy=policy, now=_ISSUED_AT + timedelta(seconds=61))

    assert first.verified is True
    assert replay.verified is False
    assert replay.signature_valid is True
    assert replay.reason == "attestation_replay_detected"
    assert "replay_guard=rejected" in replay.checks


def test_sqlite_replay_store_rejects_across_verifier_instances(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_sbom(tmp_path)
    _private_pem, public_pem = _keys(monkeypatch)
    _sign(path)
    replay_db = tmp_path / "replay.sqlite3"

    first_policy = _policy(public_pem, replay_store=SQLiteAttestationReplayStore(replay_db, max_entries=8))
    second_policy = _policy(public_pem, replay_store=SQLiteAttestationReplayStore(replay_db, max_entries=8))

    assert verify_sbom_attestation(path, trust_policy=first_policy, now=_ISSUED_AT + timedelta(seconds=60)).verified is True
    replay = verify_sbom_attestation(path, trust_policy=second_policy, now=_ISSUED_AT + timedelta(seconds=61))
    assert replay.reason == "attestation_replay_detected"


def test_cli_sqlite_replay_cache_rejects_a_second_process_style_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_sbom(tmp_path)
    _private_pem, public_pem = _keys(monkeypatch)
    public_key_path = tmp_path / "trusted.pub.pem"
    public_key_path.write_text(public_pem)
    replay_cache = tmp_path / "replay.sqlite3"
    runner = CliRunner()
    assert runner.invoke(attest_group, ["sign", str(path), "--tenant-id", _TENANT]).exit_code == 0
    command = [
        "verify",
        str(path),
        "--tenant-id",
        _TENANT,
        "--public-key",
        str(public_key_path),
        "--replay-cache",
        str(replay_cache),
        "--json",
    ]

    first = runner.invoke(attest_group, command)
    replay = runner.invoke(attest_group, command)

    assert first.exit_code == 0, first.output
    assert replay.exit_code == 1
    assert json.loads(replay.output)["reason"] == "attestation_replay_detected"


def test_cli_requires_an_explicit_tenant_for_sign_and_verify(tmp_path: Path) -> None:
    path = _write_sbom(tmp_path)
    runner = CliRunner()

    assert runner.invoke(attest_group, ["sign", str(path)]).exit_code == 2
    assert runner.invoke(attest_group, ["verify", str(path)]).exit_code == 2


def test_policy_rejects_unbounded_or_ambiguous_configuration() -> None:
    with pytest.raises(AttestationTrustError, match="expected_tenant_id_required"):
        AttestationTrustPolicy.from_public_key_pems([], expected_tenant_id="")
    with pytest.raises(AttestationTrustError, match="max_age_seconds_invalid"):
        AttestationTrustPolicy.from_public_key_pems([], expected_tenant_id=_TENANT, max_age_seconds=0)
    with pytest.raises(AttestationTrustError, match="clock_skew_seconds_invalid"):
        AttestationTrustPolicy.from_public_key_pems([], expected_tenant_id=_TENANT, clock_skew_seconds=301)


class _SyntheticSigstoreVerifier:
    def __init__(self, expected_pae: bytes, expected_signature: str) -> None:
        self.expected_pae = expected_pae
        self.expected_signature = expected_signature
        self.calls = 0

    def verify(
        self,
        *,
        signed_bytes: bytes,
        signature_b64: str,
        bundle_bytes: bytes,
        trusted_root_bytes: bytes,
        identity_regexp: str,
        issuer: str,
    ) -> bool:
        self.calls += 1
        return (
            signed_bytes == self.expected_pae
            and signature_b64 == self.expected_signature
            and json.loads(bundle_bytes)["messageSignature"]["signature"] == signature_b64
            and "trustedroot" in json.loads(trusted_root_bytes)["mediaType"]
            and identity_regexp == r"https://github\.com/acme/repo/.+"
            and issuer == "https://token.actions.githubusercontent.com"
        )


def test_sigstore_policy_verifies_exact_pae_with_explicit_identity_and_issuer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_sbom(tmp_path)
    _private_pem, _public_pem = _keys(monkeypatch)
    _sign(path)
    Path(str(path) + _SIG_SUFFIX).unlink()
    envelope_path = Path(str(path) + _ATTESTATION_SUFFIX)
    envelope = json.loads(envelope_path.read_text())
    payload = base64.b64decode(envelope["payload"], validate=True)
    signature_b64 = base64.b64encode(b"s" * 64).decode()
    policy = AttestationTrustPolicy.from_sigstore(
        expected_identity_regexp=r"https://github\.com/acme/repo/.+",
        expected_issuer="https://token.actions.githubusercontent.com",
        trusted_root_path=_trusted_root(tmp_path),
        expected_tenant_id=_TENANT,
        replay_store=MemoryAttestationReplayStore(max_entries=8),
    )
    envelope["signatures"] = [{"keyid": policy.sigstore_key_id, "sig": signature_b64}]
    envelope_path.write_text(json.dumps(envelope))
    bundle_path = tmp_path / "attestation.sigstore.json"
    bundle_path.write_text(json.dumps({"messageSignature": {"signature": signature_b64}}))
    adapter = _SyntheticSigstoreVerifier(dsse_pae(_DSSE_PAYLOAD_TYPE, payload), signature_b64)

    result = verify_sbom_attestation(
        path,
        trust_policy=policy,
        sigstore_bundle_path=bundle_path,
        sigstore_verifier=adapter,
        now=_ISSUED_AT + timedelta(seconds=60),
    )

    assert result.verified is True
    assert result.algorithm == "Sigstore"
    assert result.trust_status == "trusted"
    assert adapter.calls == 1


def test_sigstore_policy_requires_bundle_and_exact_policy_key_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_sbom(tmp_path)
    _private_pem, _public_pem = _keys(monkeypatch)
    _sign(path)
    policy = AttestationTrustPolicy.from_sigstore(
        expected_identity_regexp=r"https://github\.com/acme/repo/.+",
        expected_issuer="https://token.actions.githubusercontent.com",
        trusted_root_path=_trusted_root(tmp_path),
        expected_tenant_id=_TENANT,
    )

    missing_bundle = verify_sbom_attestation(path, trust_policy=policy, now=_ISSUED_AT + timedelta(seconds=60))
    assert missing_bundle.reason == "sigstore_bundle_required"

    envelope_path = Path(str(path) + _ATTESTATION_SUFFIX)
    envelope = json.loads(envelope_path.read_text())
    signature_b64 = base64.b64encode(b"s" * 64).decode()
    envelope["signatures"] = [{"keyid": policy.sigstore_key_id, "sig": signature_b64}]
    envelope_path.write_text(json.dumps(envelope))
    bundle_path = tmp_path / "attestation.sigstore.json"
    bundle_path.write_text(json.dumps({"messageSignature": {"signature": signature_b64}}))

    missing_adapter = verify_sbom_attestation(
        path,
        trust_policy=policy,
        sigstore_bundle_path=bundle_path,
        now=_ISSUED_AT + timedelta(seconds=60),
    )
    assert missing_adapter.reason == "sigstore_verifier_required"

    envelope["signatures"] = [{"keyid": "f" * 64, "sig": signature_b64}]
    envelope_path.write_text(json.dumps(envelope))
    adapter = _SyntheticSigstoreVerifier(b"unused", signature_b64)

    mismatch = verify_sbom_attestation(
        path,
        trust_policy=policy,
        sigstore_bundle_path=bundle_path,
        sigstore_verifier=adapter,
        now=_ISSUED_AT + timedelta(seconds=60),
    )
    assert mismatch.reason == "untrusted_signer"
    assert adapter.calls == 0
