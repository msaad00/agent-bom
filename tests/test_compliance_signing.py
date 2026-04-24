"""Tests for Ed25519 asymmetric compliance-bundle signing.

Covers:
- HMAC is the default when AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM is unset
- Ed25519 kicks in when the env var is set, and the signature verifies with the
  public key from ``/v1/compliance/verification-key``
- Key rotation: swapping the env var produces a different key_id and old
  signatures no longer verify under the new key
- Malformed PEM falls back to HMAC without crashing the server
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from starlette.testclient import TestClient

from agent_bom.api import stores as _stores
from agent_bom.api.compliance_signing import (
    describe_current_signer,
    describe_signing_posture,
    reset_signer_cache_for_tests,
    sign_compliance_bundle,
)
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store


def _generate_ed25519_pem() -> tuple[str, Ed25519PublicKey]:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return pem, key.public_key()


def _seed_tagged_scan(tenant_id: str = "tenant-alpha") -> InMemoryJobStore:
    store = InMemoryJobStore()
    now = datetime.now(timezone.utc).isoformat()
    job = ScanJob(
        job_id="sig-scan",
        tenant_id=tenant_id,
        status=JobStatus.DONE,
        created_at=now,
        completed_at=now,
        request=ScanRequest(),
    )
    job.result = {
        "scan_id": "sig-scan",
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-SIG",
                "package": "axios@1.4.0",
                "severity": "high",
                "fixed_version": "1.7.4",
                "owasp_tags": ["LLM01"],
                "affected_agents": ["claude-desktop"],
            }
        ],
    }
    store.put(job)
    return store


@pytest.fixture
def clean_signer_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", raising=False)
    reset_signer_cache_for_tests()
    yield
    reset_signer_cache_for_tests()


def test_default_is_hmac_when_env_unset(clean_signer_env: None) -> None:
    algorithm, key_id, pem = describe_current_signer()
    assert algorithm == "HMAC-SHA256"
    assert key_id is None
    assert pem is None

    sig = sign_compliance_bundle(b"hello")
    assert sig.algorithm == "HMAC-SHA256"
    assert sig.key_id is None
    assert sig.public_key_pem is None
    # hex digest of HMAC-SHA256 is 64 chars
    assert len(sig.signature_hex) == 64


def test_ed25519_activated_when_env_set(monkeypatch: pytest.MonkeyPatch, clean_signer_env: None) -> None:
    pem, public_key = _generate_ed25519_pem()
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", pem)
    reset_signer_cache_for_tests()

    algorithm, key_id, reported_pem = describe_current_signer()
    assert algorithm == "Ed25519"
    assert key_id is not None and len(key_id) == 16
    assert reported_pem is not None
    assert "PUBLIC KEY" in reported_pem

    payload = b'{"hello":"world"}'
    sig = sign_compliance_bundle(payload)
    assert sig.algorithm == "Ed25519"
    # Raw Ed25519 signature is 64 bytes = 128 hex chars
    assert len(sig.signature_hex) == 128
    public_key.verify(bytes.fromhex(sig.signature_hex), payload)  # raises on bad sig


def test_bundle_roundtrip_verifies_with_verification_key_endpoint(monkeypatch: pytest.MonkeyPatch, clean_signer_env: None) -> None:
    pem, _ = _generate_ed25519_pem()
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", pem)
    reset_signer_cache_for_tests()

    previous_store = _stores._store
    set_job_store(_seed_tagged_scan())
    try:
        client = TestClient(app)

        # Pilot-team flow: fetch public key once, pin it, use it to verify bundles.
        key_resp = client.get(
            "/v1/compliance/verification-key",
            headers={"X-Agent-Bom-Role": "viewer", "X-Agent-Bom-Tenant-ID": "tenant-alpha"},
        )
        assert key_resp.status_code == 200
        key_body = key_resp.json()
        assert key_body["algorithm"] == "Ed25519"
        assert key_body["key_id"]
        assert "PUBLIC KEY" in key_body["public_key_pem"]
        pinned_public_key = serialization.load_pem_public_key(key_body["public_key_pem"].encode())
        assert isinstance(pinned_public_key, Ed25519PublicKey)

        # Now pull a bundle and verify it with the pinned public key.
        resp = client.get(
            "/v1/compliance/owasp-llm/report",
            headers={"X-Agent-Bom-Role": "viewer", "X-Agent-Bom-Tenant-ID": "tenant-alpha"},
        )
        assert resp.status_code == 200
        assert resp.headers["X-Agent-Bom-Compliance-Signature-Algorithm"] == "Ed25519"
        assert resp.headers["X-Agent-Bom-Compliance-Signature-KeyId"] == key_body["key_id"]
        body = resp.json()
        assert body["signature_algorithm"] == "Ed25519"
        assert body["signature_key_id"] == key_body["key_id"]
        assert "signature_public_key_pem" in body
        # Auditor reconstructs the canonical body and verifies against pinned public key.
        canonical = json.dumps(body, sort_keys=True).encode()
        sig_hex = resp.headers["X-Agent-Bom-Compliance-Report-Signature"]
        pinned_public_key.verify(bytes.fromhex(sig_hex), canonical)
    finally:
        _stores._store = previous_store
        reset_signer_cache_for_tests()


def test_key_rotation_changes_key_id_and_breaks_old_signature(monkeypatch: pytest.MonkeyPatch, clean_signer_env: None) -> None:
    old_pem, _ = _generate_ed25519_pem()
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", old_pem)
    reset_signer_cache_for_tests()
    _, old_key_id, old_pub = describe_current_signer()
    old_sig = sign_compliance_bundle(b"bundle-payload")

    new_pem, new_public = _generate_ed25519_pem()
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", new_pem)
    reset_signer_cache_for_tests()
    _, new_key_id, new_pub = describe_current_signer()

    assert old_key_id != new_key_id
    assert old_pub != new_pub
    with pytest.raises(Exception):
        new_public.verify(bytes.fromhex(old_sig.signature_hex), b"bundle-payload")


def test_malformed_pem_falls_back_to_hmac(monkeypatch: pytest.MonkeyPatch, clean_signer_env: None) -> None:
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", "not a valid pem")
    reset_signer_cache_for_tests()
    algorithm, key_id, pem = describe_current_signer()
    assert algorithm == "HMAC-SHA256"
    assert key_id is None
    assert pem is None


def test_describe_signing_posture_reports_ed25519(monkeypatch: pytest.MonkeyPatch, clean_signer_env: None) -> None:
    pem, _ = _generate_ed25519_pem()
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", pem)
    reset_signer_cache_for_tests()

    posture = describe_signing_posture()
    assert posture["algorithm"] == "Ed25519"
    assert posture["mode"] == "asymmetric_public_key"
    assert posture["auditor_distributable"] is True
    assert posture["public_key_endpoint"] == "/v1/compliance/verification-key"
