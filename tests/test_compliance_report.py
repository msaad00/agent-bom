"""Tests for GET /v1/compliance/{framework}/report — signed evidence bundle.

Locks the auditor-facing contract:

- response carries ``X-Agent-Bom-Compliance-Report-Signature`` matching
  the HMAC-SHA256 of the canonical JSON body
- bundle pairs every framework control with the matching blast-radius
  evidence drawn from the tenant's completed scans
- audit events are filtered to the requested time window and the authed
  tenant — never cross-tenant leakage
- ``compliance.report_exported`` is appended to the audit log with the
  exporter's actor + tenant + scope so re-issued bundles leave a trail
- jsonl format streams one control per line for SIEM / security-lake
- unknown framework, malformed timestamps, and inverted ranges all 4xx
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from starlette.testclient import TestClient

from agent_bom.api.audit_log import (
    AuditEntry,
    InMemoryAuditLog,
    get_audit_log,
    set_audit_log,
)
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.routes import compliance as compliance_routes
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store, set_job_store


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _request(tenant_id: str, actor: str = "ci-bot") -> SimpleNamespace:
    state = SimpleNamespace(tenant_id=tenant_id, api_key_name=actor)
    return SimpleNamespace(state=state)


def _seed_jobs_with_findings(tenant_id: str = "tenant-alpha") -> list[ScanJob]:
    """Build two completed scans with blast-radius entries tagged for OWASP LLM and SOC 2."""
    job_a = ScanJob(
        job_id="scan-a",
        tenant_id=tenant_id,
        status=JobStatus.DONE,
        created_at=_now_iso(),
        completed_at=_now_iso(),
        request=ScanRequest(),
    )
    job_a.result = {
        "scan_id": "scan-a",
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-0001",
                "package": "axios@1.4.0",
                "severity": "high",
                "fixed_version": "1.7.4",
                "owasp_tags": ["LLM01"],
                "soc2_tags": ["CC6.1"],
                "affected_agents": ["claude-desktop"],
            },
            {
                "vulnerability_id": "CVE-2024-0002",
                "package": "certifi@2022.12.7",
                "severity": "critical",
                "fixed_version": "2024.7.4",
                "owasp_tags": ["LLM02"],
                "affected_agents": ["claude-desktop"],
            },
        ],
    }
    return [job_a]


def _setup_audit_log() -> InMemoryAuditLog:
    audit = InMemoryAuditLog()
    audit.append(
        AuditEntry(
            entry_id="e1",
            timestamp=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            action="auth.key_rotated",
            actor="ci-bot",
            resource="key/abc",
            details={"tenant_id": "tenant-alpha"},
        )
    )
    audit.append(
        AuditEntry(
            entry_id="e2",
            timestamp=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            action="scan.started",
            actor="ci-bot",
            resource="scan/scan-a",
            details={"tenant_id": "tenant-other"},  # cross-tenant — must NOT appear in tenant-alpha bundle
        )
    )
    set_audit_log(audit)
    return audit


def _patched_get_compliance_returns(payload: dict):
    return patch.object(compliance_routes, "get_compliance", return_value=payload)


def _export_with_real_producer(framework: str = "owasp-llm", *, format: str = "json"):
    """Call export_compliance_report against seeded real jobs — no get_compliance mock.

    The only patch is ``_tenant_jobs`` (the store accessor, which is test
    plumbing) so the real ``_build_controls`` / ``_evidence_for_control``
    pipeline runs end-to-end. This is the regression guard for the
    control-dict shape drift that the mock-heavy tests originally missed.
    """
    jobs = _seed_jobs_with_findings()
    req = _request("tenant-alpha")
    with patch.object(compliance_routes, "_tenant_jobs", return_value=jobs):
        return asyncio.run(compliance_routes.export_compliance_report(req, framework, format=format))


# ─── Happy-path JSON ─────────────────────────────────────────────────────────


def test_report_json_signature_matches_canonical_body() -> None:
    audit = _setup_audit_log()
    jobs = _seed_jobs_with_findings()

    full_payload = {
        "owasp_llm_top10": [
            {"control_id": "LLM01", "name": "Prompt Injection", "status": "fail", "tags": ["LLM01"]},
            {"control_id": "LLM02", "name": "Insecure Output Handling", "status": "warning", "tags": ["LLM02"]},
            {"control_id": "LLM03", "name": "Training Data Poisoning", "status": "pass", "tags": ["LLM03"]},
        ]
    }
    req = _request("tenant-alpha")

    with patch.object(compliance_routes, "_tenant_jobs", return_value=jobs):
        with _patched_get_compliance_returns(full_payload):
            resp = asyncio.run(compliance_routes.export_compliance_report(req, "owasp-llm"))

    assert isinstance(resp, JSONResponse)
    body = json.loads(resp.body)
    assert body["framework_key"] == "owasp_llm_top10"
    assert body["framework_label"] == "OWASP LLM Top 10"
    assert body["tenant_id"] == "tenant-alpha"
    assert body["scope"]["control_count"] == 3
    assert body["scope"]["finding_count"] == 2

    # Pass/warning/fail summary
    assert body["summary"]["fail"] == 1
    assert body["summary"]["warning"] == 1
    assert body["summary"]["pass"] == 1

    # Evidence wired to the right control
    by_id = {c["control_id"]: c for c in body["controls"]}
    assert by_id["LLM01"]["finding_count"] == 1
    assert by_id["LLM01"]["evidence"][0]["vulnerability_id"] == "CVE-2024-0001"
    assert by_id["LLM03"]["finding_count"] == 0

    # HMAC signature header matches canonical body
    sig = resp.headers["X-Agent-Bom-Compliance-Report-Signature"]
    canonical = json.dumps(body, sort_keys=True).encode()
    from agent_bom.api.audit_log import _HMAC_KEY  # noqa: PLC0415

    expected = hmac.new(_HMAC_KEY, canonical, hashlib.sha256).hexdigest()
    assert sig == expected

    # Content-Disposition + filename
    assert resp.headers["Content-Disposition"].endswith('agent-bom-compliance-owasp-llm-top10.json"')

    # compliance.report_exported emitted with full scope
    log_entries = list(audit._entries)  # type: ignore[attr-defined]
    exported_entries = [e for e in log_entries if e.action == "compliance.report_exported"]
    assert len(exported_entries) == 1
    exported = exported_entries[0]
    assert (exported.details or {}).get("tenant_id") == "tenant-alpha"
    assert exported.actor == "ci-bot"
    # Nonce from the body is recorded in the audit trail for forensic correlation
    assert (exported.details or {}).get("nonce") == body["nonce"]
    assert (exported.details or {}).get("expires_at") == body["expires_at"]


def test_real_compliance_export_wires_control_tags_and_non_empty_evidence() -> None:
    """Exercise the real producer path instead of patching in synthetic tags."""
    _setup_audit_log()
    jobs = _seed_jobs_with_findings()
    req = _request("tenant-alpha")

    with patch.object(compliance_routes, "_tenant_jobs", return_value=jobs):
        posture = asyncio.run(compliance_routes.get_compliance(req))
        resp = asyncio.run(compliance_routes.export_compliance_report(req, "owasp-llm"))

    controls = posture["owasp_llm_top10"]
    llm01 = next(c for c in controls if c["control_id"] == "LLM01")
    assert llm01["tags"] == ["LLM01"]

    body = json.loads(resp.body)
    exported = {c["control_id"]: c for c in body["controls"]}
    assert exported["LLM01"]["finding_count"] == 1
    assert exported["LLM01"]["evidence"][0]["control_tag"] == "LLM01"
    assert exported["LLM01"]["evidence"][0]["vulnerability_id"] == "CVE-2024-0001"


def test_compliance_report_route_exports_real_evidence_end_to_end() -> None:
    """Exercise the real FastAPI route with real auth, store, and audit wiring."""
    original_store = _get_store()
    original_audit_log = get_audit_log()
    audit = _setup_audit_log()
    store = InMemoryJobStore()
    set_job_store(store)
    try:
        for job in _seed_jobs_with_findings():
            store.put(job)

        client = TestClient(app)
        resp = client.get(
            "/v1/compliance/owasp-llm/report",
            headers={
                "X-Agent-Bom-Role": "viewer",
                "X-Agent-Bom-Tenant-ID": "tenant-alpha",
            },
        )
        assert resp.status_code == 200

        body = resp.json()
        assert body["tenant_id"] == "tenant-alpha"
        assert body["scope"]["finding_count"] == 2
        llm01 = next(control for control in body["controls"] if control["control_id"] == "LLM01")
        assert llm01["finding_count"] == 1
        assert llm01["evidence"]
        assert llm01["evidence"][0]["control_tag"] == "LLM01"
        assert llm01["evidence"][0]["scan_id"] == "scan-a"
        assert llm01["evidence"][0]["vulnerability_id"] == "CVE-2024-0001"
        assert {entry["details"]["tenant_id"] for entry in body["audit_events"]} == {"tenant-alpha"}

        log_entries = list(audit._entries)  # type: ignore[attr-defined]
        assert any(entry.action == "compliance.report_exported" for entry in log_entries)
    finally:
        set_job_store(original_store)
        set_audit_log(original_audit_log)


# ─── Replay-protection envelope ──────────────────────────────────────────────


def test_bundle_carries_nonce_and_expiry_in_signed_envelope() -> None:
    """nonce + expires_at must be inside the body and thus inside the signature."""
    _setup_audit_log()
    resp = _export_with_real_producer("owasp-llm")
    body = json.loads(resp.body)
    # 128-bit hex nonce
    assert isinstance(body["nonce"], str)
    assert len(body["nonce"]) == 32
    assert all(c in "0123456789abcdef" for c in body["nonce"])
    # expires_at is in the future
    expires = datetime.fromisoformat(body["expires_at"])
    assert expires > datetime.now(timezone.utc)
    # Signature covers the envelope — tampering with nonce breaks it
    tampered = dict(body)
    tampered["nonce"] = "00" * 16
    tampered_canonical = json.dumps(tampered, sort_keys=True).encode()
    from agent_bom.api.audit_log import _HMAC_KEY  # noqa: PLC0415

    tampered_sig = hmac.new(_HMAC_KEY, tampered_canonical, hashlib.sha256).hexdigest()
    assert resp.headers["X-Agent-Bom-Compliance-Report-Signature"] != tampered_sig


def test_every_export_gets_a_fresh_nonce() -> None:
    """Two consecutive exports for the same tenant must have different nonces."""
    _setup_audit_log()
    a = _export_with_real_producer("owasp-llm")
    b = _export_with_real_producer("owasp-llm")
    nonce_a = json.loads(a.body)["nonce"]
    nonce_b = json.loads(b.body)["nonce"]
    assert nonce_a != nonce_b


def test_threat_model_block_documents_guarantees() -> None:
    """The bundle must carry a threat_model block so auditors see the guarantees inline."""
    _setup_audit_log()
    resp = _export_with_real_producer("owasp-llm")
    body = json.loads(resp.body)
    tm = body["threat_model"]
    # Every documented guarantee has a block
    for key in ("integrity", "confidentiality", "replay", "non_repudiation"):
        assert key in tm, f"threat_model must document {key}"
        assert len(tm[key]) > 40


# ─── Tenant isolation ─────────────────────────────────────────────────────────


def test_report_audit_events_are_tenant_filtered() -> None:
    audit = _setup_audit_log()  # has one tenant-alpha and one tenant-other entry
    audit.append(
        AuditEntry(
            entry_id="e3",
            timestamp=(datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(),
            action="scan.completed",
            actor="system",
            resource="scan/scan-a",
            details={},  # missing tenant_id must NOT leak into default tenant exports
        )
    )
    resp = _export_with_real_producer("owasp-llm")
    body = json.loads(resp.body)
    # Cross-tenant audit entry must not leak into the bundle
    tenants = {e["details"].get("tenant_id") for e in body["audit_events"]}
    assert tenants == {"tenant-alpha"}
    assert all(e["details"].get("tenant_id") != "tenant-other" for e in body["audit_events"])
    assert len(body["audit_events"]) == 1
    assert body["audit_log_integrity"]["checked"] == 1


# ─── Format = jsonl ──────────────────────────────────────────────────────────


def test_report_jsonl_streams_one_record_per_line() -> None:
    _setup_audit_log()
    jobs = _seed_jobs_with_findings()
    full_payload = {
        "soc2": [
            {"control_id": "CC6.1", "name": "Logical Access", "status": "fail", "tags": ["CC6.1"]},
        ]
    }
    req = _request("tenant-alpha")

    with patch.object(compliance_routes, "_tenant_jobs", return_value=jobs):
        with _patched_get_compliance_returns(full_payload):
            resp = asyncio.run(compliance_routes.export_compliance_report(req, "soc2", format="jsonl"))

    # jsonl path is a StreamingResponse — drain the async iterator into bytes.
    from starlette.responses import StreamingResponse

    assert isinstance(resp, StreamingResponse)
    chunks: list[bytes] = []
    for chunk in asyncio.run(_drain_stream(resp)):
        chunks.append(chunk)
    raw = b"".join(chunks).decode()
    lines = [ln for ln in raw.split("\n") if ln]
    # First line is meta; followed by one control line; followed by the audit entry
    assert json.loads(lines[0])["meta"]["framework_key"] == "soc2"
    assert json.loads(lines[1])["control"]["control_id"] == "CC6.1"
    # The signature is over the canonical jsonl payload, not the json one
    sig = resp.headers["X-Agent-Bom-Compliance-Report-Signature"]
    from agent_bom.api.audit_log import _HMAC_KEY  # noqa: PLC0415

    expected = hmac.new(_HMAC_KEY, raw.encode(), hashlib.sha256).hexdigest()
    assert sig == expected


async def _drain_stream(resp) -> list[bytes]:
    """Drain a StreamingResponse into a list of bytes chunks for assertions."""
    collected: list[bytes] = []
    async for chunk in resp.body_iterator:
        collected.append(chunk if isinstance(chunk, bytes) else chunk.encode())
    return collected


# ─── Bad input ────────────────────────────────────────────────────────────────


def test_unknown_framework_returns_400() -> None:
    _setup_audit_log()
    req = _request("tenant-alpha")
    with patch.object(compliance_routes, "_tenant_jobs", return_value=[]):
        with _patched_get_compliance_returns({}):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(compliance_routes.export_compliance_report(req, "made-up-framework"))
    assert exc.value.status_code == 400
    assert "Unknown framework" in exc.value.detail


def test_invalid_format_returns_400() -> None:
    _setup_audit_log()
    req = _request("tenant-alpha")
    with patch.object(compliance_routes, "_tenant_jobs", return_value=[]):
        with _patched_get_compliance_returns({}):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(compliance_routes.export_compliance_report(req, "fedramp", format="csv"))
    assert exc.value.status_code == 400
    assert "format must be" in exc.value.detail


def test_malformed_since_returns_400() -> None:
    _setup_audit_log()
    req = _request("tenant-alpha")
    with patch.object(compliance_routes, "_tenant_jobs", return_value=[]):
        with _patched_get_compliance_returns({}):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(compliance_routes.export_compliance_report(req, "fedramp", since="not-a-date"))
    assert exc.value.status_code == 400
    assert "Invalid timestamp" in exc.value.detail


def test_since_after_until_returns_400() -> None:
    _setup_audit_log()
    req = _request("tenant-alpha")
    later = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    earlier = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with patch.object(compliance_routes, "_tenant_jobs", return_value=[]):
        with _patched_get_compliance_returns({}):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(
                    compliance_routes.export_compliance_report(
                        req,
                        "fedramp",
                        since=later,
                        until=earlier,
                    )
                )
    assert exc.value.status_code == 400
    assert "since must be earlier" in exc.value.detail
