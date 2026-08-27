"""One persisted scan-evidence contract across API, compliance, and MCP."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.routes.scan import _job_summary_payload, _redact_scan_result_for_response
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store, set_job_store
from agent_bom.finding_scope import safe_finding_response_payload


def _finding() -> dict[str, object]:
    return {
        "id": "finding-1",
        "canonical_id": "finding-1",
        "finding_type": "MCP_TOOL_POISONING",
        "source": "MCP_SCAN",
        "severity": "high",
        "title": "Tool description can redirect execution",
        "asset": {
            "name": "payments-mcp",
            "asset_type": "mcp_server",
            "identifier": "server:payments-mcp",
            "location": "/Users/example/.config/mcp.json",
            "stable_id": "asset-1",
        },
        "package": "mcp-payments@1.2.3",
        "cve_id": "CVE-2026-4242",
        "affected_agents": ["developer-agent"],
        "affected_servers": ["payments-mcp"],
        "framework_tags": ["owasp_llm:LLM01", "soc2:CC6.1"],
        "controls": [
            {"framework": "owasp_llm", "control": "LLM01", "source": "scanner"},
            {"framework": "soc2", "control_id": "CC6.1", "source": "scanner"},
        ],
        "owasp_tags": ["LLM01"],
        "soc2_tags": ["CC6.1"],
        "first_seen": "2026-08-17T12:00:00Z",
        "last_observed": "2026-08-17T12:05:00Z",
        "status": "open",
        "fixed_version": "1.2.4",
    }


def test_full_scan_job_and_findings_list_share_the_canonical_safe_projection() -> None:
    finding = _finding()

    list_projection = safe_finding_response_payload(finding)
    result_projection = _redact_scan_result_for_response(
        {
            "scan_id": "scan-1",
            "findings": [finding],
            "summary": {"total_findings": 1},
        }
    )

    assert result_projection is not None
    assert result_projection["findings"] == [list_projection]
    projected = list_projection
    assert projected["asset"] == {
        "name": "payments-mcp",
        "asset_type": "mcp_server",
        "stable_id": "asset-1",
    }
    assert projected["framework_tags"] == ["owasp_llm:LLM01", "soc2:CC6.1"]
    assert projected["controls"] == [
        {"framework": "owasp_llm", "control": "LLM01", "source": "scanner"},
        {"framework": "soc2", "control": "CC6.1", "source": "scanner"},
    ]
    assert safe_finding_response_payload({**finding, "asset": {"stable_id": "asset-only"}})["asset"] == {"stable_id": "asset-only"}


def test_full_scan_job_and_findings_list_redact_shaped_secret_text() -> None:
    secret = "ghp_" + "a" * 36
    finding = {**_finding(), "title": f"leaked token {secret}", "description": f"secret={secret}"}

    list_projection = safe_finding_response_payload(finding)
    result_projection = _redact_scan_result_for_response({"findings": [finding]})

    assert result_projection is not None
    assert secret not in json.dumps(list_projection)
    assert secret not in json.dumps(result_projection)


def test_unified_finding_drives_compliance_narrative_without_placeholder_entities() -> None:
    from agent_bom.output.compliance_narrative import generate_compliance_narrative_from_findings

    narrative = generate_compliance_narrative_from_findings(
        [_finding()],
        total_agents=1,
        total_packages=1,
        generated_at="2026-08-17T12:05:00Z",
        framework="owasp-llm",
    )

    framework = narrative.framework_narratives[0]
    llm01 = next(control for control in framework.failing_controls if control.control_id == "LLM01")
    assert llm01.affected_findings == ["CVE-2026-4242"]
    assert llm01.affected_packages == ["mcp-payments@1.2.3"]
    assert "agent-0" not in narrative.executive_summary
    assert "pkg-0" not in narrative.executive_summary


@pytest.mark.asyncio
async def test_mcp_blast_radius_prefers_the_persisted_tenant_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.mcp_tools.analysis import blast_radius_impl

    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")

    async def _must_not_scan_local():
        raise AssertionError("persisted control-plane evidence must not trigger a laptop scan")

    def _persisted(*, tenant_id: str, cve_id: str, scan_id: str | None) -> dict[str, object]:
        assert tenant_id == "tenant-a"
        assert cve_id == "CVE-2026-4242"
        assert scan_id == "scan-1"
        return {
            "available": True,
            "source": "persisted_scan_findings",
            "scope": {"tenant_id": tenant_id, "scan_id": scan_id},
            "completeness": {"status": "complete", "reason": ""},
            "findings": [safe_finding_response_payload(_finding())],
        }

    encoded = await blast_radius_impl(
        cve_id="CVE-2026-4242",
        tenant_id="tenant-a",
        scan_id="scan-1",
        _validate_cve_id=lambda value: value.upper(),
        _run_scan_pipeline=_must_not_scan_local,
        _get_persisted_evidence=_persisted,
        _truncate_response=lambda value: value,
    )
    payload = json.loads(encoded)

    assert payload["found"] is True
    assert payload["source"] == "persisted_scan_findings"
    assert payload["scope"] == {"tenant_id": "tenant-a", "scan_id": "scan-1"}
    assert payload["count"] == 1
    assert payload["blast_radii"][0]["affected_agents"] == ["developer-agent"]


def test_scan_job_model_keeps_the_same_result_summary_contract() -> None:
    """The additive projection must not mutate the durable job model itself."""
    job = ScanJob(
        job_id="scan-1",
        tenant_id="tenant-a",
        status=JobStatus.DONE,
        created_at="2026-08-17T12:00:00Z",
        completed_at="2026-08-17T12:05:00Z",
        request=ScanRequest(),
        result={"scan_id": "scan-1", "summary": {"total_findings": 1}, "findings": [_finding()]},
    )
    projected = _redact_scan_result_for_response(job.result)
    assert projected is not job.result
    assert job.result["findings"][0]["asset"]["location"] == "/Users/example/.config/mcp.json"
    assert projected["summary"] == job.result["summary"]


def test_full_scan_response_redacts_sensitive_top_level_side_blocks() -> None:
    secret = "ghp_" + "a" * 36
    email = "alice.sentinel@example.invalid"
    credential_url = "postgresql://admin:sentinel-password@db.internal/prod"
    durable = {
        "scan_id": "scan-1",
        "findings": [],
        "executive_summary": f"Exposed {secret}",
        "trust_assessment": {
            "owner_email": email,
            "connection_url": credential_url,
        },
    }

    projected = _redact_scan_result_for_response(durable)

    assert projected is not None
    rendered = json.dumps(projected)
    assert secret not in rendered
    assert email not in rendered
    assert credential_url not in rendered
    assert secret in durable["executive_summary"]


def test_scan_status_summary_redacts_warning_and_summary_payloads() -> None:
    secret = "ghp_" + "a" * 36
    email = "alice.sentinel@example.invalid"
    job = ScanJob(
        job_id="scan-1",
        tenant_id="tenant-a",
        status=JobStatus.DONE,
        created_at="2026-08-17T12:00:00Z",
        completed_at="2026-08-17T12:05:00Z",
        request=ScanRequest(),
        error=f"provider returned {secret}",
        result={
            "summary": {"detail": f"Contact {email}"},
            "warnings": [f"Credential {secret}"],
        },
    )

    rendered = json.dumps(_job_summary_payload(job))

    assert secret not in rendered
    assert email not in rendered


def test_compliance_endpoint_reads_the_current_persisted_finding_queue() -> None:
    from agent_bom.api.routes import compliance

    previous_store = _get_store()
    store = InMemoryJobStore()
    set_job_store(store)
    finding = _finding()
    finding["scan_id"] = "scan-persisted"
    job = ScanJob(
        job_id="scan-persisted",
        tenant_id="tenant-parity",
        status=JobStatus.DONE,
        created_at="2026-08-17T12:00:00Z",
        completed_at="2026-08-17T12:05:00Z",
        request=ScanRequest(),
        result={
            "scan_id": "scan-persisted",
            "generated_at": "2026-08-17T12:05:00Z",
            "summary": {"total_agents": 0, "total_packages": 0, "total_findings": 1},
            "findings": [finding],
            "blast_radius": [],
        },
    )
    store.put(job)
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-parity"), headers={})

    try:
        payload = asyncio.run(compliance.get_compliance_narrative(request))
    finally:
        set_job_store(previous_store)

    assert payload["evidence_snapshot"]["returned"] == 1
    assert payload["evidence_snapshot"]["total"] == 1
    assert payload["evidence_snapshot"]["scan_ids"] == ["scan-persisted"]
    assert "covers 1 AI agent and 1 package represented in current evidence through 2026-08-17" in payload["executive_summary"]
    assert "Current evidence identified 1 security finding across 1 agent" in payload["risk_narrative"]
    framework = next(item for item in payload["framework_narratives"] if item["slug"] == "owasp-llm")
    llm01 = next(item for item in framework["failing_controls"] if item["control_id"] == "LLM01")
    assert llm01["affected_findings"] == ["CVE-2026-4242"]
    assert "agent-0" not in payload["executive_summary"]
    assert "pkg-0" not in payload["executive_summary"]


def test_completed_empty_scan_is_not_reported_as_no_scan() -> None:
    from agent_bom.api.routes import compliance

    previous_store = _get_store()
    store = InMemoryJobStore()
    set_job_store(store)
    store.put(
        ScanJob(
            job_id="scan-empty",
            tenant_id="tenant-empty-scan",
            status=JobStatus.DONE,
            created_at="2026-08-17T12:00:00Z",
            completed_at="2026-08-17T12:05:00Z",
            request=ScanRequest(),
            result={
                "scan_id": "scan-empty",
                "generated_at": "2026-08-17T12:05:00Z",
                "summary": {"total_agents": 1, "total_packages": 1, "total_findings": 0},
                "findings": [],
                "blast_radius": [],
            },
        )
    )
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-empty-scan"), headers={})

    try:
        payload = asyncio.run(compliance.get_compliance_narrative(request))
    finally:
        set_job_store(previous_store)

    assert payload["evidence_snapshot"]["completed_scan_count"] == 1
    assert payload["evidence_snapshot"]["returned"] == 0
    assert "No completed scans available" not in payload["executive_summary"]
    assert "unavailable or unscanned sources are not claimed clean" in payload["executive_summary"]
