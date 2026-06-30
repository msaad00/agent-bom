"""Tests for signing + attesting generated SBOM output.

Verifies the supply-chain-integrity loop for emitted SBOMs:
- ``sign_sbom_file`` writes a detached signature and an in-toto attestation
- a clean SBOM verifies
- a tampered SBOM fails verification (digest binding is real)
- Ed25519 mode is genuinely asymmetric: a third party verifies with only the
  embedded public key
- the ``attest`` CLI group round-trips
"""

from __future__ import annotations

import base64
import json

from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bom.cli._attest_group import attest_group
from agent_bom.sbom_attestation import (
    _ATTESTATION_SUFFIX,
    _SIG_SUFFIX,
    sign_sbom_file,
    verify_sbom_attestation,
)


def _write_sbom(tmp_path) -> str:
    sbom = tmp_path / "report.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}), encoding="utf-8")
    return str(sbom)


def test_sign_emits_signature_and_attestation(tmp_path):
    path = _write_sbom(tmp_path)
    result = sign_sbom_file(path)

    assert result.signature_path.endswith(_SIG_SUFFIX)
    assert result.attestation_path.endswith(_ATTESTATION_SUFFIX)

    # in-toto Statement v1 with the SBOM digest bound in the subject.
    envelope = json.loads((tmp_path / ("report.cdx.json" + _ATTESTATION_SUFFIX)).read_text())
    statement = json.loads(base64.b64decode(envelope["payload"]))
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["subject"][0]["digest"]["sha256"] == result.sha256
    assert statement["predicateType"] == "https://slsa.dev/provenance/v1"
    assert envelope["signatures"][0]["sig"]


def test_clean_sbom_verifies(tmp_path):
    path = _write_sbom(tmp_path)
    sign_sbom_file(path)

    result = verify_sbom_attestation(path)
    assert result.verified is True
    assert result.digest_matches is True
    assert result.signature_valid is True
    assert result.reason == "verified"


def test_tampered_sbom_fails_verification(tmp_path):
    path = _write_sbom(tmp_path)
    sign_sbom_file(path)

    # Mutate the SBOM after signing.
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n")

    result = verify_sbom_attestation(path)
    assert result.verified is False
    assert result.digest_matches is False
    assert result.reason == "digest_mismatch"


def test_tampered_attestation_signature_fails(tmp_path):
    path = _write_sbom(tmp_path)
    sign_sbom_file(path)

    att_path = tmp_path / ("report.cdx.json" + _ATTESTATION_SUFFIX)
    envelope = json.loads(att_path.read_text())
    # Flip the signature so the digest still matches but the sig does not.
    envelope["signatures"][0]["sig"] = "00" * 32
    att_path.write_text(json.dumps(envelope))

    result = verify_sbom_attestation(path)
    assert result.verified is False
    assert result.signature_valid is False
    assert result.reason == "signature_invalid"


def test_ed25519_is_asymmetric_third_party_verifiable(tmp_path, monkeypatch):
    from agent_bom.api import compliance_signing

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", pem)
    compliance_signing.reset_signer_cache_for_tests()
    try:
        path = _write_sbom(tmp_path)
        signed = sign_sbom_file(path)
        assert signed.algorithm == "Ed25519"
        assert signed.cryptographic is True
        assert signed.public_key_pem

        # Verification succeeds using only the embedded public key.
        result = verify_sbom_attestation(path)
        assert result.verified is True
        assert result.cryptographic is True

        # Independently verify the in-toto payload with the public key alone.
        envelope = json.loads((tmp_path / ("report.cdx.json" + _ATTESTATION_SUFFIX)).read_text())
        payload = base64.b64decode(envelope["payload"])
        sig = bytes.fromhex(envelope["signatures"][0]["sig"])
        pub = serialization.load_pem_public_key(signed.public_key_pem.encode())
        pub.verify(sig, payload)  # raises on failure
    finally:
        compliance_signing.reset_signer_cache_for_tests()


def test_missing_attestation_reports_reason(tmp_path):
    path = _write_sbom(tmp_path)
    result = verify_sbom_attestation(path)
    assert result.verified is False
    assert result.reason == "attestation_not_found"


def test_cli_sign_and_verify_roundtrip(tmp_path):
    path = _write_sbom(tmp_path)
    runner = CliRunner()

    signed = runner.invoke(attest_group, ["sign", path, "--json"])
    assert signed.exit_code == 0, signed.output
    payload = json.loads(signed.output)
    assert payload["sha256"]
    assert payload["attestation"].endswith(_ATTESTATION_SUFFIX)

    verified = runner.invoke(attest_group, ["verify", path, "--json"])
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.output)["verified"] is True


def test_cli_verify_tampered_exits_nonzero(tmp_path):
    path = _write_sbom(tmp_path)
    runner = CliRunner()
    runner.invoke(attest_group, ["sign", path])

    with open(path, "a", encoding="utf-8") as fh:
        fh.write("tampered")

    verified = runner.invoke(attest_group, ["verify", path])
    assert verified.exit_code == 1
