"""A compliance bundle must disclose whether its own signature is verifiable.

By default ``agent-bom serve`` runs with no ``AGENT_BOM_AUDIT_HMAC_KEY``, so the
audit HMAC key is generated per-process at import time. Bundles signed with it
are stamped ``signature_algorithm: HMAC-SHA256`` and cannot be verified by
anyone — not even the issuing deployment after a restart. That is a dishonest
artifact unless the bundle itself, and the endpoint auditors are pointed at,
say so.

Covered here:
- ``GET /v1/compliance/verification-key`` reports verifiability, not just the
  algorithm name, across all three deployments (ephemeral HMAC, configured
  HMAC, Ed25519), with remediation an operator can actually follow.
- The single-framework bundle, the jsonl rendering, and the all-framework pack
  each carry the disclosure INSIDE the signed envelope, so it cannot be
  stripped without invalidating the signature.
- The compliance narrative's "export a signed evidence bundle" recommendation
  carries the caveat when the active signer is ephemeral.
- A shipped CLI verifier (``agent-bom attest compliance-verify``) that never
  trusts the key material embedded in the bundle.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from starlette.testclient import TestClient

from agent_bom.api import audit_log as _audit_log
from agent_bom.api import stores as _stores
from agent_bom.api.compliance_signing import canonical_bundle_payload, reset_signer_cache_for_tests
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

TENANT = "tenant-disclosure"


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _generate_ed25519_pem() -> tuple[str, Ed25519PublicKey]:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return pem, key.public_key()


def _public_pem(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _seed_tagged_scan(tenant_id: str = TENANT) -> InMemoryJobStore:
    store = InMemoryJobStore()
    now = datetime.now(timezone.utc).isoformat()
    job = ScanJob(
        job_id="disclosure-scan",
        tenant_id=tenant_id,
        status=JobStatus.DONE,
        created_at=now,
        completed_at=now,
        request=ScanRequest(),
    )
    job.result = {
        "scan_id": "disclosure-scan",
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-DISCLOSE",
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
def ephemeral_hmac_env(monkeypatch: pytest.MonkeyPatch):
    """Default `agent-bom serve` deployment: no Ed25519, no persistent HMAC key."""
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", raising=False)
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE", raising=False)
    monkeypatch.setattr(_audit_log, "_HMAC_ENV_KEY", "")
    reset_signer_cache_for_tests()
    yield
    reset_signer_cache_for_tests()


@pytest.fixture
def configured_hmac_env(monkeypatch: pytest.MonkeyPatch):
    """Operator has set AGENT_BOM_AUDIT_HMAC_KEY — signatures survive restarts.

    ``_HMAC_ENV_KEY`` drives the posture read; ``_HMAC_KEY`` is what actually
    signs. Both are resolved at import, so both are patched — otherwise the
    bundle would claim a persistent signer while being signed with the random
    per-process key, which is precisely the bug under test.
    """
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", raising=False)
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE", raising=False)
    monkeypatch.setattr(_audit_log, "_HMAC_ENV_KEY", "persistent-shared-secret")
    monkeypatch.setattr(_audit_log, "_HMAC_KEY", b"persistent-shared-secret")
    reset_signer_cache_for_tests()
    yield
    reset_signer_cache_for_tests()


@pytest.fixture
def ed25519_env(monkeypatch: pytest.MonkeyPatch):
    """Positive control — asymmetric signing, auditor-distributable."""
    pem, public_key = _generate_ed25519_pem()
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE", raising=False)
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", pem)
    reset_signer_cache_for_tests()
    yield public_key
    reset_signer_cache_for_tests()


@pytest.fixture
def seeded_client():
    previous_store = _stores._store
    set_job_store(_seed_tagged_scan())
    try:
        yield TestClient(app)
    finally:
        _stores._store = previous_store


# ─── 1. /v1/compliance/verification-key must report verifiability ────────────


def test_verification_key_reports_ephemeral_hmac_as_not_verifiable(ephemeral_hmac_env: None, seeded_client: TestClient) -> None:
    body = seeded_client.get("/v1/compliance/verification-key", headers=proxy_headers(tenant=TENANT)).json()

    assert body["algorithm"] == "HMAC-SHA256"
    assert body["signature_verifiable"] is False, "an ephemeral per-process key can never be verified by anyone"
    assert body["persists_across_restart"] is False
    assert body["verification_status"] == "unverifiable_ephemeral_key"
    remediation = body["remediation"]
    assert remediation, "an unverifiable deployment must ship remediation the operator can follow"
    assert "AGENT_BOM_AUDIT_HMAC_KEY" in remediation
    assert "AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM" in remediation
    # The old copy told verifiers to "obtain AGENT_BOM_AUDIT_HMAC_KEY out-of-band"
    # for a key that never left the process. That instruction must be gone.
    assert "out-of-band" not in body["key_distribution"]


def test_verification_key_reports_configured_hmac_as_shared_secret_verifiable(configured_hmac_env: None, seeded_client: TestClient) -> None:
    body = seeded_client.get("/v1/compliance/verification-key", headers=proxy_headers(tenant=TENANT)).json()

    assert body["algorithm"] == "HMAC-SHA256"
    assert body["signature_verifiable"] is True
    assert body["persists_across_restart"] is True
    assert body["verification_status"] == "verifiable_shared_secret"
    # A shared secret is verifiable but not auditor-distributable, so the
    # response still points at the better option without calling it broken.
    assert body["remediation"] is None
    assert "AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM" in body["key_distribution"]


def test_verification_key_reports_ed25519_as_publicly_verifiable(ed25519_env: Ed25519PublicKey, seeded_client: TestClient) -> None:
    body = seeded_client.get("/v1/compliance/verification-key", headers=proxy_headers(tenant=TENANT)).json()

    assert body["algorithm"] == "Ed25519"
    assert body["signature_verifiable"] is True
    assert body["persists_across_restart"] is True
    assert body["verification_status"] == "verifiable_public_key"
    assert body["remediation"] is None
    assert body["key_id"] and len(body["key_id"]) == 16
    assert "PUBLIC KEY" in body["public_key_pem"]


# ─── 2. The bundle itself discloses its verifiability, inside the signature ──


def _fetch_bundle(client: TestClient, path: str = "/v1/compliance/owasp-llm/report") -> dict:
    resp = client.get(path, headers=proxy_headers(tenant=TENANT))
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_ephemeral_bundle_discloses_it_is_not_verifiable(ephemeral_hmac_env: None, seeded_client: TestClient) -> None:
    body = _fetch_bundle(seeded_client)

    assert body["signature_algorithm"] == "HMAC-SHA256"
    disclosure = body["signature_disclosure"]
    assert disclosure["signature_verifiable"] is False
    assert disclosure["persists_across_restart"] is False
    assert disclosure["verification_status"] == "unverifiable_ephemeral_key"
    assert "AGENT_BOM_AUDIT_HMAC_KEY" in disclosure["remediation"]


def test_disclosure_is_covered_by_the_signature(ephemeral_hmac_env: None, seeded_client: TestClient) -> None:
    """Stripping or flipping the disclosure must invalidate the signature."""
    body = _fetch_bundle(seeded_client)
    signature = body["signature"]

    # As delivered, the signature covers the body-minus-signature.
    from agent_bom.api.compliance_signing import verify_compliance_bundle

    assert verify_compliance_bundle(body) is True

    stripped = {k: v for k, v in body.items() if k != "signature_disclosure"}
    assert verify_compliance_bundle(stripped) is False, "disclosure could be removed without breaking the signature"

    flipped = json.loads(json.dumps(body))
    flipped["signature_disclosure"]["signature_verifiable"] = True
    assert verify_compliance_bundle(flipped) is False, "disclosure could be forged without breaking the signature"

    # Sanity: the canonical payload the signature covers really contains it.
    assert b"signature_disclosure" in canonical_bundle_payload(body)
    assert signature == body["signature"]


def test_jsonl_meta_line_carries_the_disclosure(ephemeral_hmac_env: None, seeded_client: TestClient) -> None:
    resp = seeded_client.get(
        "/v1/compliance/owasp-llm/report",
        params={"format": "jsonl"},
        headers=proxy_headers(tenant=TENANT),
    )
    assert resp.status_code == 200, resp.text
    meta = json.loads(resp.text.splitlines()[0])["meta"]
    assert meta["signature_disclosure"]["signature_verifiable"] is False


def test_evidence_pack_discloses_it_is_not_verifiable(ephemeral_hmac_env: None, seeded_client: TestClient) -> None:
    body = _fetch_bundle(seeded_client, "/v1/compliance/report/pack")

    disclosure = body["signature_disclosure"]
    assert disclosure["signature_verifiable"] is False
    assert disclosure["verification_status"] == "unverifiable_ephemeral_key"

    from agent_bom.api.compliance_signing import verify_compliance_bundle

    assert verify_compliance_bundle(body) is True
    stripped = {k: v for k, v in body.items() if k != "signature_disclosure"}
    assert verify_compliance_bundle(stripped) is False


def test_configured_hmac_bundle_discloses_it_is_verifiable(configured_hmac_env: None, seeded_client: TestClient) -> None:
    body = _fetch_bundle(seeded_client)
    disclosure = body["signature_disclosure"]
    assert disclosure["signature_verifiable"] is True
    assert disclosure["persists_across_restart"] is True
    assert disclosure["verification_status"] == "verifiable_shared_secret"


def test_ed25519_bundle_discloses_it_is_verifiable_and_still_verifies(ed25519_env: Ed25519PublicKey, seeded_client: TestClient) -> None:
    """Positive control — the Ed25519 path must keep verifying after the shape change."""
    body = _fetch_bundle(seeded_client)
    disclosure = body["signature_disclosure"]
    assert disclosure["signature_verifiable"] is True
    assert disclosure["verification_status"] == "verifiable_public_key"
    assert disclosure["remediation"] is None

    canonical = json.dumps({k: v for k, v in body.items() if k != "signature"}, sort_keys=True).encode()
    ed25519_env.verify(bytes.fromhex(body["signature"]), canonical)

    tampered = json.loads(json.dumps(body))
    tampered["framework_label"] = f"{tampered['framework_label']} tampered"
    from agent_bom.api.compliance_signing import verify_compliance_bundle

    assert verify_compliance_bundle(tampered) is False


def test_tampered_bundle_rejected_under_every_signer(
    ephemeral_hmac_env: None, configured_hmac_env: None, seeded_client: TestClient
) -> None:
    """configured_hmac_env applies last, so this is the shared-secret deployment."""
    from agent_bom.api.compliance_signing import verify_compliance_bundle

    body = _fetch_bundle(seeded_client)
    assert verify_compliance_bundle(body) is True
    tampered = json.loads(json.dumps(body))
    tampered["framework_label"] = f"{tampered['framework_label']} tampered"
    assert verify_compliance_bundle(tampered) is False


def test_signed_vex_export_discloses_verifiability(ephemeral_hmac_env: None, seeded_client: TestClient) -> None:
    """Same defect class: /v1/findings/triage/vex ships a signature block too."""
    resp = seeded_client.get("/v1/findings/triage/vex", headers=proxy_headers(tenant=TENANT))
    assert resp.status_code == 200, resp.text
    signature = resp.json()["signature"]
    assert signature["algorithm"] == "HMAC-SHA256"
    assert signature["signature_verifiable"] is False
    assert signature["verification_status"] == "unverifiable_ephemeral_key"


# ─── 3. The narrative recommendation must carry the caveat ──────────────────


def _bundle_recommendations(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    from agent_bom.models import Agent, AgentType, AIBOMReport
    from agent_bom.output.compliance_narrative import generate_compliance_narrative

    report = AIBOMReport(
        agents=[Agent(name="claude", agent_type=AgentType.CLAUDE_CODE, config_path="/tmp")],
        blast_radii=[],
    )
    narrative = generate_compliance_narrative(report, framework="owasp-llm")
    return [rec for rec in narrative.framework_narratives[0].recommendations if "evidence bundle" in rec]


def test_narrative_export_recommendation_warns_when_signer_is_ephemeral(ephemeral_hmac_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    recs = _bundle_recommendations(monkeypatch)
    assert recs, "the export-a-signed-bundle recommendation should exist"
    joined = " ".join(recs)
    assert "cannot be verified" in joined.lower() or "not verifiable" in joined.lower()
    assert "AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM" in joined


def test_narrative_export_recommendation_has_no_caveat_under_ed25519(
    ed25519_env: Ed25519PublicKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    joined = " ".join(_bundle_recommendations(monkeypatch))
    assert joined
    assert "cannot be verified" not in joined.lower()


# ─── 4. A shipped CLI verifier that does not trust the embedded key ─────────


def _write_bundle(tmp_path, body: dict, name: str = "bundle.json"):
    path = tmp_path / name
    path.write_text(json.dumps(body))
    return path


def _run_cli(args: list[str]):
    from agent_bom.cli import main

    return CliRunner().invoke(main, args)


def test_cli_verifies_ed25519_bundle_with_supplied_public_key(ed25519_env: Ed25519PublicKey, seeded_client: TestClient, tmp_path) -> None:
    body = _fetch_bundle(seeded_client)
    bundle = _write_bundle(tmp_path, body)
    key_file = tmp_path / "pub.pem"
    key_file.write_text(_public_pem(ed25519_env))

    result = _run_cli(["attest", "compliance-verify", str(bundle), "--public-key", str(key_file), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["verified"] is True
    assert payload["algorithm"] == "Ed25519"
    assert payload["signature_verifiable"] is True


def test_cli_refuses_to_trust_the_key_embedded_in_the_bundle(ed25519_env: Ed25519PublicKey, seeded_client: TestClient, tmp_path) -> None:
    body = _fetch_bundle(seeded_client)
    assert body["signature_public_key_pem"], "bundle embeds self-attesting key material"
    bundle = _write_bundle(tmp_path, body)

    result = _run_cli(["attest", "compliance-verify", str(bundle), "--json"])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["verified"] is False
    assert payload["reason"] == "no_trusted_public_key"


def test_cli_rejects_a_tampered_ed25519_bundle(ed25519_env: Ed25519PublicKey, seeded_client: TestClient, tmp_path) -> None:
    body = _fetch_bundle(seeded_client)
    body["framework_label"] = f"{body['framework_label']} tampered"
    bundle = _write_bundle(tmp_path, body)
    key_file = tmp_path / "pub.pem"
    key_file.write_text(_public_pem(ed25519_env))

    result = _run_cli(["attest", "compliance-verify", str(bundle), "--public-key", str(key_file), "--json"])
    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["reason"] == "signature_mismatch"


def test_cli_rejects_a_bundle_signed_with_a_different_key(ed25519_env: Ed25519PublicKey, seeded_client: TestClient, tmp_path) -> None:
    body = _fetch_bundle(seeded_client)
    bundle = _write_bundle(tmp_path, body)
    _, other_public = _generate_ed25519_pem()
    key_file = tmp_path / "other.pem"
    key_file.write_text(_public_pem(other_public))

    result = _run_cli(["attest", "compliance-verify", str(bundle), "--public-key", str(key_file), "--json"])
    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["reason"] == "signature_mismatch"


def test_cli_reports_an_ephemeral_hmac_bundle_as_unverifiable(ephemeral_hmac_env: None, seeded_client: TestClient, tmp_path) -> None:
    body = _fetch_bundle(seeded_client)
    bundle = _write_bundle(tmp_path, body)

    result = _run_cli(["attest", "compliance-verify", str(bundle), "--json"])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["verified"] is False
    assert payload["reason"] == "issuer_key_ephemeral"
    assert payload["signature_verifiable"] is False


def test_cli_verifies_a_configured_hmac_bundle_with_the_shared_secret(
    configured_hmac_env: None, seeded_client: TestClient, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = _fetch_bundle(seeded_client)
    bundle = _write_bundle(tmp_path, body)
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY", "persistent-shared-secret")

    result = _run_cli(["attest", "compliance-verify", str(bundle), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["verified"] is True
    assert payload["algorithm"] == "HMAC-SHA256"


def test_cli_verifies_the_jsonl_rendering(ed25519_env: Ed25519PublicKey, seeded_client: TestClient, tmp_path) -> None:
    resp = seeded_client.get(
        "/v1/compliance/owasp-llm/report",
        params={"format": "jsonl"},
        headers=proxy_headers(tenant=TENANT),
    )
    assert resp.status_code == 200, resp.text
    path = tmp_path / "bundle.jsonl"
    path.write_text(resp.text)
    key_file = tmp_path / "pub.pem"
    key_file.write_text(_public_pem(ed25519_env))

    result = _run_cli(["attest", "compliance-verify", str(path), "--public-key", str(key_file), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["verified"] is True
