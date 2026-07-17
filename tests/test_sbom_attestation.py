"""Trusted DSSE verification boundary for generated SBOM attestations."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bom.cli._attest_group import attest_group
from agent_bom.sbom_attestation import (
    _ATTESTATION_SUFFIX,
    _DSSE_PAYLOAD_TYPE,
    _DSSE_SCHEMA_VERSION,
    _SIG_SUFFIX,
    AttestationSigningError,
    AttestationTrustPolicy,
    dsse_pae,
    sign_sbom_file,
    verify_sbom_attestation,
)


def _write_sbom(tmp_path: Path) -> Path:
    sbom = tmp_path / "report.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}), encoding="utf-8")
    return sbom


def _key_material() -> tuple[Ed25519PrivateKey, str, str]:
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return key, private_pem, public_pem


@pytest.fixture
def signing_key(monkeypatch) -> tuple[Ed25519PrivateKey, str, str]:
    from agent_bom.api import compliance_signing

    material = _key_material()
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", material[1])
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE", raising=False)
    compliance_signing.reset_signer_cache_for_tests()
    yield material
    compliance_signing.reset_signer_cache_for_tests()


def _policy(public_pem: str) -> AttestationTrustPolicy:
    return AttestationTrustPolicy.from_public_key_pems([public_pem])


def test_dsse_pae_matches_the_specification_encoding() -> None:
    assert dsse_pae("text/plain", b"hello") == b"DSSEv1 10 text/plain 5 hello"


def test_sign_emits_versioned_dsse_without_embedded_trust_material(tmp_path: Path, signing_key) -> None:
    path = _write_sbom(tmp_path)

    result = sign_sbom_file(path)

    assert result.algorithm == "Ed25519"
    assert result.cryptographic is True
    assert result.signature_path.endswith(_SIG_SUFFIX)
    assert result.attestation_path.endswith(_ATTESTATION_SUFFIX)
    envelope = json.loads(Path(result.attestation_path).read_text())
    assert envelope["payloadType"] == _DSSE_PAYLOAD_TYPE
    assert envelope["_agentBom"] == {"schemaVersion": _DSSE_SCHEMA_VERSION}
    assert "publicKeyPem" not in json.dumps(envelope)
    assert len(envelope["signatures"]) == 1
    assert len(base64.b64decode(envelope["signatures"][0]["sig"], validate=True)) == 64
    statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["subject"] == [{"name": path.name, "digest": {"sha256": result.sha256}}]
    signing_key[0].public_key().verify(
        base64.b64decode(envelope["signatures"][0]["sig"], validate=True),
        dsse_pae(envelope["payloadType"], base64.b64decode(envelope["payload"], validate=True)),
    )


def test_missing_or_malformed_signer_never_falls_back_to_hmac(tmp_path: Path, monkeypatch) -> None:
    from agent_bom.api import compliance_signing

    path = _write_sbom(tmp_path)
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", raising=False)
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE", raising=False)
    compliance_signing.reset_signer_cache_for_tests()

    with pytest.raises(AttestationSigningError, match="ed25519_signing_key_required"):
        sign_sbom_file(path)
    assert not Path(str(path) + _SIG_SUFFIX).exists()
    assert not Path(str(path) + _ATTESTATION_SUFFIX).exists()

    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", "not a private key")
    compliance_signing.reset_signer_cache_for_tests()
    with pytest.raises(AttestationSigningError, match="ed25519_signing_key_invalid"):
        sign_sbom_file(path)
    assert not Path(str(path) + _SIG_SUFFIX).exists()
    assert not Path(str(path) + _ATTESTATION_SUFFIX).exists()


def test_clean_dsse_requires_external_trust_and_then_verifies(tmp_path: Path, signing_key) -> None:
    path = _write_sbom(tmp_path)
    signed = sign_sbom_file(path)

    untrusted = verify_sbom_attestation(path)
    assert untrusted.verified is False
    assert untrusted.digest_matches is True
    assert untrusted.signature_valid is False
    assert untrusted.reason == "trusted_public_key_required"
    assert untrusted.trust_status == "untrusted"

    trusted = verify_sbom_attestation(path, trust_policy=_policy(signing_key[2]))
    assert trusted.verified is True
    assert trusted.digest_matches is True
    assert trusted.signature_valid is True
    assert trusted.reason == "verified"
    assert trusted.trust_status == "trusted"
    assert trusted.key_id == signed.key_id


def test_embedded_attacker_key_is_never_a_trust_anchor(tmp_path: Path, signing_key) -> None:
    path = _write_sbom(tmp_path)
    sign_sbom_file(path)
    envelope_path = Path(str(path) + _ATTESTATION_SUFFIX)
    envelope = json.loads(envelope_path.read_text())
    envelope["_agentBom"]["publicKeyPem"] = signing_key[2]
    envelope_path.write_text(json.dumps(envelope))
    _other_key, _other_private, other_public = _key_material()

    result = verify_sbom_attestation(path, trust_policy=_policy(other_public))

    assert result.verified is False
    assert result.signature_valid is False
    assert result.reason == "untrusted_signer"
    assert result.key_id is None


def test_payload_type_tamper_is_rejected_before_signature_verification(tmp_path: Path, signing_key) -> None:
    path = _write_sbom(tmp_path)
    sign_sbom_file(path)
    envelope_path = Path(str(path) + _ATTESTATION_SUFFIX)
    envelope = json.loads(envelope_path.read_text())
    envelope["payloadType"] = "application/attacker-controlled"
    envelope_path.write_text(json.dumps(envelope))

    result = verify_sbom_attestation(path, trust_policy=_policy(signing_key[2]))

    assert result.verified is False
    assert result.signature_valid is False
    assert result.reason == "payload_type_invalid"


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("envelope", "algorithm_metadata_invalid"),
        ("signature", "signature_metadata_invalid"),
    ],
)
def test_algorithm_metadata_cannot_select_a_different_verifier(tmp_path: Path, signing_key, target: str, reason: str) -> None:
    path = _write_sbom(tmp_path)
    sign_sbom_file(path)
    envelope_path = Path(str(path) + _ATTESTATION_SUFFIX)
    envelope = json.loads(envelope_path.read_text())
    if target == "envelope":
        envelope["_agentBom"]["algorithm"] = "HMAC-SHA256"
    else:
        envelope["signatures"][0]["algorithm"] = "HMAC-SHA256"
    envelope_path.write_text(json.dumps(envelope))

    result = verify_sbom_attestation(path, trust_policy=_policy(signing_key[2]))

    assert result.verified is False
    assert result.signature_valid is False
    assert result.reason == reason


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda envelope: envelope["signatures"].append(dict(envelope["signatures"][0])), "ambiguous_signatures"),
        (lambda envelope: envelope["signatures"][0].update({"keyid": ""}), "key_id_missing"),
        (lambda envelope: envelope["signatures"][0].update({"keyid": "f" * 64}), "untrusted_signer"),
    ],
)
def test_signature_and_key_id_ambiguity_fail_closed(tmp_path: Path, signing_key, mutate, reason: str) -> None:
    path = _write_sbom(tmp_path)
    sign_sbom_file(path)
    envelope_path = Path(str(path) + _ATTESTATION_SUFFIX)
    envelope = json.loads(envelope_path.read_text())
    mutate(envelope)
    envelope_path.write_text(json.dumps(envelope))

    result = verify_sbom_attestation(path, trust_policy=_policy(signing_key[2]))

    assert result.verified is False
    assert result.signature_valid is False
    assert result.reason == reason


def test_detached_key_id_must_match_the_dsse_signer(tmp_path: Path, signing_key) -> None:
    path = _write_sbom(tmp_path)
    sign_sbom_file(path)
    signature_path = Path(str(path) + _SIG_SUFFIX)
    detached = json.loads(signature_path.read_text())
    detached["keyId"] = "f" * 64
    signature_path.write_text(json.dumps(detached))

    result = verify_sbom_attestation(path, trust_policy=_policy(signing_key[2]))

    assert result.verified is False
    assert result.signature_valid is True
    assert result.reason == "detached_key_id_mismatch"


def test_tampered_sbom_and_dsse_signature_fail_independently(tmp_path: Path, signing_key) -> None:
    path = _write_sbom(tmp_path)
    sign_sbom_file(path)
    path.write_text(path.read_text() + "\n")

    digest_failure = verify_sbom_attestation(path, trust_policy=_policy(signing_key[2]))
    assert digest_failure.digest_matches is False
    assert digest_failure.signature_valid is True
    assert digest_failure.reason == "digest_mismatch"

    path = _write_sbom(tmp_path)
    sign_sbom_file(path)
    envelope_path = Path(str(path) + _ATTESTATION_SUFFIX)
    envelope = json.loads(envelope_path.read_text())
    envelope["signatures"][0]["sig"] = base64.b64encode(b"\0" * 64).decode()
    envelope_path.write_text(json.dumps(envelope))
    signature_failure = verify_sbom_attestation(path, trust_policy=_policy(signing_key[2]))
    assert signature_failure.digest_matches is True
    assert signature_failure.signature_valid is False
    assert signature_failure.reason == "signature_invalid"


def test_legacy_self_consistent_envelope_is_reported_but_never_verified(tmp_path: Path, signing_key) -> None:
    from agent_bom.sbom_attestation import _canonical_bytes, build_intoto_statement

    key, _private_pem, public_pem = signing_key
    path = _write_sbom(tmp_path)
    payload = _canonical_bytes(build_intoto_statement(path, path.read_bytes()))
    legacy = {
        "payloadType": _DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": "legacy", "sig": key.sign(payload).hex()}],
        "_agentBom": {"algorithm": "Ed25519", "cryptographic": True, "publicKeyPem": public_pem},
    }
    Path(str(path) + _ATTESTATION_SUFFIX).write_text(json.dumps(legacy))

    result = verify_sbom_attestation(path, trust_policy=_policy(public_pem))

    assert result.verified is False
    assert result.legacy is True
    assert result.format_version == "legacy"
    assert result.digest_matches is True
    assert result.signature_valid is False
    assert result.trust_status == "legacy_untrusted"
    assert result.reason == "legacy_attestation_untrusted"
    assert result.key_id is None


def test_malformed_and_oversized_envelopes_are_bounded(tmp_path: Path, signing_key, monkeypatch) -> None:
    import agent_bom.sbom_attestation as module

    path = _write_sbom(tmp_path)
    attestation_path = Path(str(path) + _ATTESTATION_SUFFIX)
    attestation_path.write_text("not-json")
    malformed = verify_sbom_attestation(path, trust_policy=_policy(signing_key[2]))
    assert malformed.reason == "malformed_attestation"
    assert "JSON" not in malformed.reason

    attestation_path.write_text("{}" * 32)
    monkeypatch.setattr(module, "_MAX_ENVELOPE_BYTES", 16)
    oversized = verify_sbom_attestation(path, trust_policy=_policy(signing_key[2]))
    assert oversized.reason == "attestation_too_large"


def test_cli_verify_requires_explicit_public_key(tmp_path: Path, signing_key) -> None:
    path = _write_sbom(tmp_path)
    runner = CliRunner()
    signed = runner.invoke(attest_group, ["sign", str(path), "--json"])
    assert signed.exit_code == 0, signed.output

    without_key = runner.invoke(attest_group, ["verify", str(path), "--json"])
    assert without_key.exit_code == 1
    assert json.loads(without_key.output)["reason"] == "trusted_public_key_required"

    public_key_file = tmp_path / "trusted.pub.pem"
    public_key_file.write_text(signing_key[2])
    with_key = runner.invoke(attest_group, ["verify", str(path), "--public-key", str(public_key_file), "--json"])
    assert with_key.exit_code == 0, with_key.output
    assert json.loads(with_key.output)["verified"] is True


def test_cli_cross_process_sign_then_verify_uses_only_explicit_public_key(tmp_path: Path) -> None:
    _key, private_pem, public_pem = _key_material()
    path = _write_sbom(tmp_path)
    private_file = tmp_path / "signing.pem"
    public_file = tmp_path / "trusted.pub.pem"
    private_file.write_text(private_pem)
    public_file.write_text(public_pem)
    command = [sys.executable, "-c", "from agent_bom.cli import cli_main; cli_main()"]
    source_path = str(Path(__file__).resolve().parents[1] / "src")
    sign_env = {
        **os.environ,
        "AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE": str(private_file),
        "PYTHONPATH": source_path + os.pathsep + os.environ.get("PYTHONPATH", ""),
    }
    sign_env.pop("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", None)

    signed = subprocess.run(
        [*command, "attest", "sign", str(path), "--json"],
        cwd=tmp_path,
        env=sign_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert signed.returncode == 0, signed.stderr

    verify_env = dict(os.environ)
    verify_env["PYTHONPATH"] = source_path + os.pathsep + verify_env.get("PYTHONPATH", "")
    verify_env.pop("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", None)
    verify_env.pop("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE", None)
    verified = subprocess.run(
        [*command, "attest", "verify", str(path), "--public-key", str(public_file), "--json"],
        cwd=tmp_path,
        env=verify_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["verified"] is True

    no_trust = subprocess.run(
        [*command, "attest", "verify", str(path), "--json"],
        cwd=tmp_path,
        env=verify_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert no_trust.returncode == 1
    assert json.loads(no_trust.stdout)["reason"] == "trusted_public_key_required"


def test_missing_attestation_reports_reason(tmp_path: Path) -> None:
    path = _write_sbom(tmp_path)
    result = verify_sbom_attestation(path)
    assert result.verified is False
    assert result.reason == "attestation_not_found"
