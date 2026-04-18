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
from fastapi.responses import JSONResponse, PlainTextResponse

from agent_bom.api.audit_log import (
    AuditEntry,
    InMemoryAuditLog,
    set_audit_log,
)
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.routes import compliance as compliance_routes


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
            resp = asyncio.run(
                compliance_routes.export_compliance_report(req, "owasp-llm")
            )

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


# ─── Tenant isolation ─────────────────────────────────────────────────────────


def test_report_audit_events_are_tenant_filtered() -> None:
    _setup_audit_log()  # has one tenant-alpha and one tenant-other entry
    jobs = _seed_jobs_with_findings()
    full_payload = {"owasp_llm_top10": []}
    req = _request("tenant-alpha")

    with patch.object(compliance_routes, "_tenant_jobs", return_value=jobs):
        with _patched_get_compliance_returns(full_payload):
            resp = asyncio.run(
                compliance_routes.export_compliance_report(req, "owasp-llm")
            )

    body = json.loads(resp.body)
    # Cross-tenant audit entry must not leak into the bundle
    tenants = {e["details"].get("tenant_id") for e in body["audit_events"]}
    assert tenants == {"tenant-alpha"}
    assert all(e["details"].get("tenant_id") != "tenant-other" for e in body["audit_events"])


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
            resp = asyncio.run(
                compliance_routes.export_compliance_report(req, "soc2", format="jsonl")
            )

    assert isinstance(resp, PlainTextResponse)
    raw = resp.body.decode()
    lines = [ln for ln in raw.split("\n") if ln]
    # First line is meta; followed by one control line; followed by the audit entry
    assert json.loads(lines[0])["meta"]["framework_key"] == "soc2"
    assert json.loads(lines[1])["control"]["control_id"] == "CC6.1"
    # The signature is over the canonical jsonl payload, not the json one
    sig = resp.headers["X-Agent-Bom-Compliance-Report-Signature"]
    from agent_bom.api.audit_log import _HMAC_KEY  # noqa: PLC0415

    expected = hmac.new(_HMAC_KEY, raw.encode(), hashlib.sha256).hexdigest()
    assert sig == expected


# ─── Bad input ────────────────────────────────────────────────────────────────


def test_unknown_framework_returns_400() -> None:
    _setup_audit_log()
    req = _request("tenant-alpha")
    with patch.object(compliance_routes, "_tenant_jobs", return_value=[]):
        with _patched_get_compliance_returns({}):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(
                    compliance_routes.export_compliance_report(req, "made-up-framework")
                )
    assert exc.value.status_code == 400
    assert "Unknown framework" in exc.value.detail


def test_invalid_format_returns_400() -> None:
    _setup_audit_log()
    req = _request("tenant-alpha")
    with patch.object(compliance_routes, "_tenant_jobs", return_value=[]):
        with _patched_get_compliance_returns({}):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(
                    compliance_routes.export_compliance_report(req, "fedramp", format="csv")
                )
    assert exc.value.status_code == 400
    assert "format must be" in exc.value.detail


def test_malformed_since_returns_400() -> None:
    _setup_audit_log()
    req = _request("tenant-alpha")
    with patch.object(compliance_routes, "_tenant_jobs", return_value=[]):
        with _patched_get_compliance_returns({}):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(
                    compliance_routes.export_compliance_report(req, "fedramp", since="not-a-date")
                )
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
