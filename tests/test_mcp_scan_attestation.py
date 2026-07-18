"""Adversarial contract for signed per-instance MCP scan attestations.

These tests pin the security boundary for #4151 PR-1: a scanned MCP server
instance produces a portable, DSSE-signed evidence object that an independent
verifier validates only against an operator-configured trust policy. Trust is
never derived from key material embedded in the artifact being verified.
"""

from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bom.mcp_scan_attestation import (
    Ed25519MCPScanSigner,
    MCPScanEvidence,
    MCPScanTrustPolicy,
    MemoryAttestationReplayStore,
    accept_mcp_scan_attestation,
    compute_evidence_digest,
    mcp_catalog_attestation_receipt,
    sign_mcp_scan_attestation,
    verify_mcp_scan_attestation,
)
from agent_bom.sbom_attestation import AttestationSigningError, AttestationTrustError

_TENANT = "tenant-a"
_ISSUED = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
_OBSERVED = datetime(2026, 7, 18, 11, 59, tzinfo=timezone.utc)
_SHA_A = "a" * 64
_SHA_B = "b" * 64
_SHA_C = "c" * 64


def _private() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _public_pem(private: Ed25519PrivateKey) -> str:
    return private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _evidence(**over: Any) -> MCPScanEvidence:
    values: dict[str, Any] = dict(
        tenant_id=_TENANT,
        scan_id="scan-0001",
        run_id="run-0001",
        catalog_id="io.github.acme/mcp-weather",
        instance_digest=_SHA_A,
        capability_fingerprint="fp-" + "0" * 16,
        sbom_digest=_SHA_B,
        evidence_digest=_SHA_C,
        verdict="PASS",
        scanner_version="9.9.9",
        references={"transport": "stdio", "package": "pkg:npm/mcp-weather@1.2.3"},
        issued_at=_ISSUED,
        observed_at=_OBSERVED,
        ttl_seconds=3600,
        nonce="ab" * 16,
        attestation_id="018f1f5e-7b44-7a86-b5af-010203040506",
    )
    values.update(over)
    return MCPScanEvidence(**values)


def _policy(public_pem: str, **over: Any) -> MCPScanTrustPolicy:
    values: dict[str, Any] = dict(
        expected_tenant_id=_TENANT,
        max_age_seconds=7200,
        clock_skew_seconds=30,
    )
    values.update(over)
    return MCPScanTrustPolicy.from_public_key_pems([public_pem], **values)


def _now() -> datetime:
    return _ISSUED + timedelta(seconds=60)


# --- happy path -----------------------------------------------------------


def test_valid_attestation_signed_by_trusted_key_verifies() -> None:
    key = _private()
    envelope = sign_mcp_scan_attestation(_evidence(), signer=Ed25519MCPScanSigner(key))

    result = verify_mcp_scan_attestation(envelope, trust_policy=_policy(_public_pem(key)), now=_now())

    assert result.verified is True
    assert result.trust_state == "verified"
    assert result.reason == "verified"
    assert result.signature_valid is True
    assert result.verdict == "PASS"
    assert result.tenant_id == _TENANT
    assert result.instance_digest == _SHA_A
    assert result.sbom_digest == _SHA_B
    assert result.evidence_digest == _SHA_C
    assert result.catalog_id == "io.github.acme/mcp-weather"
    assert result.scanner_version == "9.9.9"


# --- THE adversarial core: forged artifact with embedded attacker key ------


def test_embedded_attacker_key_forgery_is_rejected() -> None:
    """An attacker signs a fresh forged attestation with their OWN key and
    embeds that public key in the artifact. A verifier pinned to the legitimate
    operator key MUST reject it; self-embedded key material is never trust."""
    operator_key = _private()
    attacker_key = _private()

    forged = sign_mcp_scan_attestation(
        _evidence(verdict="PASS", instance_digest=_SHA_A),
        signer=Ed25519MCPScanSigner(attacker_key),
    )
    # Attacker embeds their own public key as "evidence" inside the envelope.
    forged["_agentBom"]["publicKeyPem"] = _public_pem(attacker_key)

    result = verify_mcp_scan_attestation(
        forged,
        trust_policy=_policy(_public_pem(operator_key)),  # pins ONLY the operator key
        now=_now(),
    )

    assert result.verified is False
    assert result.trust_state == "invalid"
    assert result.reason == "untrusted_signer"


def test_untrusted_unknown_key_fails_closed() -> None:
    signing_key = _private()
    other_key = _private()
    envelope = sign_mcp_scan_attestation(_evidence(), signer=Ed25519MCPScanSigner(signing_key))

    result = verify_mcp_scan_attestation(envelope, trust_policy=_policy(_public_pem(other_key)), now=_now())

    assert result.verified is False
    assert result.reason == "untrusted_signer"


def test_missing_trust_policy_fails_closed() -> None:
    key = _private()
    envelope = sign_mcp_scan_attestation(_evidence(), signer=Ed25519MCPScanSigner(key))

    result = verify_mcp_scan_attestation(envelope, trust_policy=None, now=_now())

    assert result.verified is False
    assert result.trust_state in {"unknown", "unsigned"}
    assert result.reason == "trust_policy_required"


# --- tamper detection ------------------------------------------------------


def test_tampered_payload_field_fails_signature() -> None:
    key = _private()
    envelope = sign_mcp_scan_attestation(_evidence(instance_digest=_SHA_A), signer=Ed25519MCPScanSigner(key))
    tampered = copy.deepcopy(envelope)
    payload = json.loads(base64.b64decode(tampered["payload"]))
    payload["predicate"]["agentBom"]["instanceDigest"] = _SHA_B  # flip the bound identity
    tampered["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()

    result = verify_mcp_scan_attestation(tampered, trust_policy=_policy(_public_pem(key)), now=_now())

    assert result.verified is False
    assert result.reason == "signature_invalid"


def test_payload_type_tamper_is_rejected() -> None:
    key = _private()
    envelope = sign_mcp_scan_attestation(_evidence(), signer=Ed25519MCPScanSigner(key))
    tampered = copy.deepcopy(envelope)
    tampered["payloadType"] = "application/vnd.attacker+json"

    result = verify_mcp_scan_attestation(tampered, trust_policy=_policy(_public_pem(key)), now=_now())

    assert result.verified is False
    assert result.reason == "payload_type_invalid"


def test_multiple_signatures_are_rejected() -> None:
    key = _private()
    envelope = sign_mcp_scan_attestation(_evidence(), signer=Ed25519MCPScanSigner(key))
    envelope["signatures"] = [envelope["signatures"][0], envelope["signatures"][0]]

    result = verify_mcp_scan_attestation(envelope, trust_policy=_policy(_public_pem(key)), now=_now())

    assert result.verified is False
    assert result.reason == "ambiguous_signatures"


def test_algorithm_metadata_is_rejected() -> None:
    key = _private()
    envelope = sign_mcp_scan_attestation(_evidence(), signer=Ed25519MCPScanSigner(key))
    envelope["_agentBom"]["algorithm"] = "attacker-controlled"

    result = verify_mcp_scan_attestation(envelope, trust_policy=_policy(_public_pem(key)), now=_now())

    assert result.verified is False
    assert result.reason == "algorithm_metadata_invalid"


# --- tenant isolation ------------------------------------------------------


def test_tenant_isolation_rejects_cross_tenant_attestation() -> None:
    key = _private()
    envelope = sign_mcp_scan_attestation(_evidence(tenant_id="tenant-a"), signer=Ed25519MCPScanSigner(key))

    result = verify_mcp_scan_attestation(
        envelope,
        trust_policy=_policy(_public_pem(key), expected_tenant_id="tenant-b"),
        now=_now(),
    )

    assert result.verified is False
    assert result.signature_valid is True
    assert result.reason == "tenant_mismatch"


# --- freshness / expiry / precedence --------------------------------------


def test_expired_attestation_trust_state_expired() -> None:
    key = _private()
    envelope = sign_mcp_scan_attestation(_evidence(ttl_seconds=300), signer=Ed25519MCPScanSigner(key))

    result = verify_mcp_scan_attestation(envelope, trust_policy=_policy(_public_pem(key)), now=_ISSUED + timedelta(seconds=1000))

    assert result.verified is False
    assert result.trust_state == "expired"
    assert result.signature_valid is True
    assert result.reason == "attestation_expired"


def test_revocation_takes_precedence_over_verified() -> None:
    key = _private()
    evidence = _evidence()
    envelope = sign_mcp_scan_attestation(evidence, signer=Ed25519MCPScanSigner(key))

    result = verify_mcp_scan_attestation(
        envelope,
        trust_policy=_policy(_public_pem(key)),
        now=_now(),
        revoked_ids=frozenset({evidence.attestation_id}),
    )

    assert result.verified is False
    assert result.trust_state == "revoked"
    assert result.reason == "attestation_revoked"


# --- verdict is orthogonal to signature validity ---------------------------


def test_valid_fail_attestation_is_still_verified_evidence() -> None:
    """A correctly signed FAIL/BLOCK attestation is verified evidence OF failure,
    not flattened to 'unverified'."""
    key = _private()
    envelope = sign_mcp_scan_attestation(_evidence(verdict="FAIL"), signer=Ed25519MCPScanSigner(key))

    result = verify_mcp_scan_attestation(envelope, trust_policy=_policy(_public_pem(key)), now=_now())

    assert result.verified is True
    assert result.trust_state == "verified"
    assert result.verdict == "FAIL"


# --- unsigned / unknown ----------------------------------------------------


def test_unsigned_or_unrecognized_envelope_is_not_verified() -> None:
    key = _private()
    envelope = sign_mcp_scan_attestation(_evidence(), signer=Ed25519MCPScanSigner(key))
    del envelope["_agentBom"]["schemaVersion"]

    result = verify_mcp_scan_attestation(envelope, trust_policy=_policy(_public_pem(key)), now=_now())

    assert result.verified is False
    assert result.trust_state in {"unsigned", "unknown"}


# --- pure verify vs replay-consuming acceptance ----------------------------


def test_pure_verification_is_repeatable() -> None:
    key = _private()
    policy = _policy(_public_pem(key))
    envelope = sign_mcp_scan_attestation(_evidence(), signer=Ed25519MCPScanSigner(key))

    first = verify_mcp_scan_attestation(envelope, trust_policy=policy, now=_now())
    second = verify_mcp_scan_attestation(envelope, trust_policy=policy, now=_now())

    assert first.verified is True
    assert second.verified is True  # read-only verification never consumes replay


def test_acceptance_consumes_replay_once() -> None:
    key = _private()
    policy = _policy(_public_pem(key))
    store = MemoryAttestationReplayStore(max_entries=8)
    envelope = sign_mcp_scan_attestation(_evidence(), signer=Ed25519MCPScanSigner(key))

    first = accept_mcp_scan_attestation(envelope, trust_policy=policy, replay_store=store, now=_now())
    replay = accept_mcp_scan_attestation(envelope, trust_policy=policy, replay_store=store, now=_now())

    assert first.verified is True
    assert replay.verified is False
    assert replay.reason == "attestation_replay_detected"


# --- evidence digest normalization ----------------------------------------


def test_evidence_digest_is_order_independent_and_excludes_mutable_fields() -> None:
    a = {
        "finding_id": "F-2",
        "rule_id": "MCP-TOOL-POISON",
        "severity": "high",
        "category": "tool",
        "observed_at": "2026-07-18T11:00:00Z",
        "file_path": "/tmp/run-abc/report.json",
        "message": "run 1 wording",
    }
    b = {
        "finding_id": "F-1",
        "rule_id": "MCP-OAUTH",
        "severity": "critical",
        "category": "auth",
        "observed_at": "2026-07-18T12:34:56Z",
        "file_path": "/tmp/run-xyz/report.json",
        "message": "run 2 wording",
    }

    digest_forward = compute_evidence_digest([a, b])
    digest_reordered = compute_evidence_digest([b, a])
    # Same stable findings, different mutable timestamps/paths/messages/order.
    assert digest_forward == digest_reordered

    changed = compute_evidence_digest([{**a, "severity": "low"}, b])
    assert changed != digest_forward


# --- signer key domain: fail closed, no fallback ---------------------------


def test_env_signer_missing_key_fails_closed_with_no_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_MCP_SCAN_ED25519_PRIVATE_KEY_PEM", raising=False)
    monkeypatch.delenv("AGENT_BOM_MCP_SCAN_ED25519_PRIVATE_KEY_PEM_FILE", raising=False)

    with pytest.raises(AttestationSigningError):
        Ed25519MCPScanSigner.from_env()


def test_env_signer_uses_dedicated_mcp_key_not_compliance_key(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _private()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    # Only the SBOM/compliance key is configured; MCP signing must not borrow it.
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", pem)
    monkeypatch.delenv("AGENT_BOM_MCP_SCAN_ED25519_PRIVATE_KEY_PEM", raising=False)

    with pytest.raises(AttestationSigningError):
        Ed25519MCPScanSigner.from_env()


# --- catalog trust surface (representable, non-promoting) ------------------


def test_catalog_receipt_is_portable_and_non_promoting() -> None:
    key = _private()
    envelope = sign_mcp_scan_attestation(_evidence(verdict="FAIL"), signer=Ed25519MCPScanSigner(key))
    result = verify_mcp_scan_attestation(envelope, trust_policy=_policy(_public_pem(key)), now=_now())

    receipt = mcp_catalog_attestation_receipt(result)

    assert receipt["trust_state"] == "verified"
    assert receipt["verdict"] == "FAIL"
    assert receipt["instance_digest"] == _SHA_A
    assert receipt["sbom_digest"] == _SHA_B
    assert receipt["evidence_digest"] == _SHA_C
    assert receipt["catalog_id"] == "io.github.acme/mcp-weather"
    assert receipt["signer_key_id"] == result.key_id
    # Non-promotion: catalog membership / clean scan are never implied by this.
    assert "notice" in receipt
    assert "catalog_verified" not in receipt


def test_policy_requires_a_trusted_key() -> None:
    with pytest.raises(AttestationTrustError):
        MCPScanTrustPolicy.from_public_key_pems([], expected_tenant_id=_TENANT)


# --- regression: the generic SBOM verifier already rejects embedded forgery -
# (#4163 landed the external-trust fix on main; this pins that it holds and is
#  the trust model the MCP layer reuses.)


def test_generic_sbom_verifier_rejects_embedded_key_forgery(tmp_path: Any) -> None:
    from pathlib import Path

    from agent_bom.sbom_attestation import (
        AttestationTrustPolicy,
        sign_sbom_file,
    )

    sbom = tmp_path / "report.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    attacker = _private()
    attacker_pem = attacker.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    import os

    os.environ["AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM"] = attacker_pem
    os.environ.pop("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE", None)
    try:
        sign_sbom_file(sbom, tenant_id=_TENANT)
    finally:
        os.environ.pop("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", None)

    # Verifier pins a DIFFERENT (operator) key: the attacker's embedded/self key is not trust.
    operator = _private()
    operator_pem = _public_pem(operator)
    from agent_bom.sbom_attestation import verify_sbom_attestation

    result = verify_sbom_attestation(
        Path(sbom),
        trust_policy=AttestationTrustPolicy.from_public_key_pems([operator_pem], expected_tenant_id=_TENANT),
    )
    assert result.verified is False
    assert result.reason == "untrusted_signer"
