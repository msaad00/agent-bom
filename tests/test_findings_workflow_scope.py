"""Owner/SLA list filters and scoped OpenVEX export stay server-owned."""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.exception_store import InMemoryExceptionStore
from agent_bom.api.models import JobStatus
from agent_bom.api.report_job_store import reset_report_job_store
from agent_bom.api.report_worker import _run_report_job_sync
from agent_bom.api.server import ScanJob, ScanRequest, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store, set_exception_store
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


@pytest.fixture(autouse=True)
def _isolated_stores() -> None:
    enable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    set_exception_store(InMemoryExceptionStore())
    reset_report_job_store()
    yield
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    set_exception_store(InMemoryExceptionStore())
    reset_report_job_store()
    disable_trusted_proxy_env()


def _headers() -> dict[str, str]:
    return proxy_headers(tenant="default", role="admin")


def _seed_owned_findings() -> None:
    observed_at = datetime.now(timezone.utc).isoformat()
    job = ScanJob(job_id="owned-scope", tenant_id="default", created_at=observed_at, request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = observed_at
    job.result = {
        "findings": [
            {
                "id": "overdue-payments",
                "finding_type": "CVE",
                "source": "SBOM",
                "cve_id": "CVE-2026-7001",
                "package": "payments-lib",
                "severity": "critical",
                "owner": "payments-security",
                "sla_due_at": "2020-01-01T00:00:00Z",
            },
            {
                "id": "future-payments",
                "finding_type": "CVE",
                "source": "SBOM",
                "cve_id": "CVE-2026-7002",
                "package": "payments-lib-next",
                "severity": "high",
                "owner": "payments-security",
                "sla_due_at": "2999-01-01T00:00:00Z",
            },
            {
                "id": "overdue-identity",
                "finding_type": "CVE",
                "source": "SBOM",
                "cve_id": "CVE-2026-7003",
                "package": "identity-lib",
                "severity": "high",
                "owner": "identity-security",
                "sla_due_at": "2020-01-01T00:00:00Z",
            },
        ]
    }
    _get_store().put(job)


def test_owner_and_overdue_filters_precede_pagination_and_match_async_export(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    _seed_owned_findings()
    monkeypatch.setenv("AGENT_BOM_REPORT_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr("agent_bom.api.routes.reports.submit_report_job", _run_report_job_sync)
    client = TestClient(app)

    listed = client.get(
        "/v1/findings?owner=payments-security&sla=overdue&window_days=0&limit=1",
        headers=_headers(),
    )

    assert listed.status_code == 200, listed.text
    assert [row["id"] for row in listed.json()["findings"]] == ["overdue-payments"]
    # Scope-filtered hub walks are deliberately bounded and do not claim an
    # exact COUNT. The page and export must still agree on the matching row.
    assert listed.json()["total"] is None
    assert listed.json()["total_approximate"] is True
    assert listed.json()["filters"] == {"owner": "payments-security", "sla": "overdue"}

    created = client.post(
        "/v1/reports",
        json={"owner": "payments-security", "sla": "overdue", "window_days": 0},
        headers=_headers(),
    )
    assert created.status_code == 202, created.text
    job = client.get(f"/v1/reports/{created.json()['job_id']}", headers=_headers()).json()
    downloaded = client.get(
        job["download_url"],
        headers={**_headers(), "X-Agent-Bom-Download-Token": job["download_token"]},
    )
    exported = [json.loads(line) for line in gzip.decompress(downloaded.content).decode().splitlines()]
    assert [row["id"] for row in exported] == ["overdue-payments"]


def test_openvex_export_filters_by_assignee_and_product() -> None:
    client = TestClient(app)
    for vulnerability_id, package, assignee in (
        ("CVE-2026-8001", "payments-lib", "payments-security"),
        ("CVE-2026-8002", "identity-lib", "identity-security"),
    ):
        created = client.post(
            "/v1/findings/triage",
            json={
                "vulnerability_id": vulnerability_id,
                "package": package,
                "assignee": assignee,
                "decision": "not_affected",
                "justification": "vulnerable_code_not_present",
            },
            headers=_headers(),
        )
        assert created.status_code == 201, created.text

    exported = client.get(
        "/v1/findings/triage/vex?assignee=payments-security&package=payments-lib",
        headers=_headers(),
    )

    assert exported.status_code == 200, exported.text
    body = exported.json()
    assert body["count"] == 1
    assert body["filters"] == {"assignee": "payments-security", "package": "payments-lib"}
    statement = body["vex"]["statements"][0]
    assert statement["vulnerability"]["name"] == "CVE-2026-8001"
    assert statement["products"] == [{"@id": "payments-lib"}]
