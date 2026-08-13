"""Owner + SLA are populated on the scan-spine finding surface.

Locks the P0 fix: finding-level ``owner`` and ``sla_due_at`` are declared in the
response contract but were never populated. The scan spine now derives an SLA
deadline (severity policy from the scan-observation anchor, KEV override) and
surfaces the triage assignee as the owner, defaulting to "Unassigned".
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_bom.api import stores as api_stores
from agent_bom.api.exception_store import ExceptionStatus, InMemoryExceptionStore, VulnException
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.routes import enterprise
from agent_bom.api.routes.enterprise import _triage_reason
from agent_bom.api.routes.scan import iter_tenant_scan_spine_findings
from agent_bom.api.store import InMemoryJobStore
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import AIBOMReport
from agent_bom.output import to_json
from agent_bom.sla import SEVERITY_SLA_DAYS


def _completed_job(tenant_id: str, findings: list[Finding], *, generated_at: datetime) -> ScanJob:
    report = AIBOMReport(agents=[], blast_radii=[], findings=findings, generated_at=generated_at)
    return ScanJob(
        job_id=f"job-{tenant_id}",
        tenant_id=tenant_id,
        status=JobStatus.DONE,
        created_at=generated_at.isoformat(),
        completed_at=generated_at.isoformat(),
        request=ScanRequest(),
        result=to_json(report),
    )


def _critical_finding() -> Finding:
    return Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="demo-lib", asset_type="package", identifier="pkg:pypi/demo-lib@1.0.0"),
        severity="critical",
        cve_id="CVE-2026-4242",
        title="CVE-2026-4242: demo-lib@1.0.0",
        evidence={"package_name": "demo-lib", "package_version": "1.0.0"},
    )


@pytest.fixture
def isolated_job_store():
    original = api_stores._store
    store = InMemoryJobStore()
    api_stores.set_job_store(store)
    try:
        yield store
    finally:
        api_stores.set_job_store(original)


@pytest.fixture
def isolated_exception_store(monkeypatch):
    store = InMemoryExceptionStore()
    monkeypatch.setattr(enterprise, "_get_exception_store", lambda: store)
    return store


def test_scan_spine_finding_defaults_owner_and_populates_sla(isolated_job_store, isolated_exception_store):
    generated_at = datetime(2026, 8, 1, tzinfo=timezone.utc)
    isolated_job_store.put(_completed_job("default", [_critical_finding()], generated_at=generated_at))

    rows = iter_tenant_scan_spine_findings("default")
    assert rows, "expected the seeded critical finding on the scan spine"
    row = rows[0]

    assert row["owner"] == "Unassigned"
    assert row["sla_due_at"] is not None
    delta = datetime.fromisoformat(row["sla_due_at"]) - generated_at
    assert delta.days == SEVERITY_SLA_DAYS["critical"]


def test_scan_spine_owner_reflects_triage_assignee(isolated_job_store, isolated_exception_store):
    generated_at = datetime(2026, 8, 1, tzinfo=timezone.utc)
    isolated_job_store.put(_completed_job("default", [_critical_finding()], generated_at=generated_at))
    isolated_exception_store.put(
        VulnException(
            vuln_id="CVE-2026-4242",
            package_name="demo-lib",
            reason=_triage_reason({"queue_state": "open", "assignee": "secops@example.com"}),
            approved_by="secops@example.com",
            status=ExceptionStatus.ACTIVE,
            tenant_id="default",
        )
    )

    from agent_bom.security import mask_email

    rows = iter_tenant_scan_spine_findings("default")
    # The assignee is surfaced as owner; the API masks the email for privacy.
    assert rows[0]["owner"] == mask_email("secops@example.com")
    assert rows[0]["owner"] != "Unassigned"


def test_triage_owner_does_not_leak_across_tenants(isolated_job_store, isolated_exception_store):
    generated_at = datetime(2026, 8, 1, tzinfo=timezone.utc)
    # Same finding in two tenants; only tenant-alpha has a triage assignee.
    isolated_job_store.put(_completed_job("tenant-alpha", [_critical_finding()], generated_at=generated_at))
    isolated_job_store.put(_completed_job("tenant-beta", [_critical_finding()], generated_at=generated_at))
    isolated_exception_store.put(
        VulnException(
            vuln_id="CVE-2026-4242",
            package_name="demo-lib",
            reason=_triage_reason({"queue_state": "open", "assignee": "alpha-owner@example.com"}),
            approved_by="alpha-owner@example.com",
            status=ExceptionStatus.ACTIVE,
            tenant_id="tenant-alpha",
        )
    )

    from agent_bom.security import mask_email

    alpha = iter_tenant_scan_spine_findings("tenant-alpha")
    beta = iter_tenant_scan_spine_findings("tenant-beta")

    assert alpha[0]["owner"] == mask_email("alpha-owner@example.com")
    # tenant-beta must not inherit tenant-alpha's assignee.
    assert beta[0]["owner"] == "Unassigned"
