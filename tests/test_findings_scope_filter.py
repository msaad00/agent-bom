"""Scope + domain filter params on GET /v1/findings (issue #3946)."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.models import JobStatus
from agent_bom.api.server import ScanJob, ScanRequest, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())


def _seed_scan_findings() -> None:
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    job = ScanJob(
        job_id="scope-job",
        tenant_id="default",
        created_at="2026-02-22T10:00:00Z",
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = "2026-02-22T10:05:00Z"
    job.result = {
        "agents": [],
        "scan_sources": ["cloud"],
        "findings": [
            {
                "id": "f-aws-prod",
                "severity": "high",
                "security_domain": "cspm",
                "provider": "aws",
                "account_ref": "aws:111111111111",
                "environment": "prod",
                "title": "aws prod misconfig",
            },
            {
                "id": "f-aws-dev",
                "severity": "medium",
                "security_domain": "cspm",
                "provider": "aws",
                "account_ref": "aws:222222222222",
                "environment": "dev",
                "title": "aws dev misconfig",
            },
            {
                "id": "f-gcp-vuln",
                "severity": "critical",
                "security_domain": "vuln",
                "provider": "gcp",
                "account_ref": "gcp:my-project",
                "environment": "prod",
                "title": "gcp cve",
            },
        ],
    }
    _get_store().put(job)


def _ids(resp) -> set[str]:
    return {f.get("id") for f in resp.json()["findings"]}


def test_filter_by_provider() -> None:
    _seed_scan_findings()
    client = TestClient(app)
    resp = client.get("/v1/findings?provider=aws", headers=_AUTH)
    assert resp.status_code == 200
    assert _ids(resp) == {"f-aws-prod", "f-aws-dev"}


def test_filter_by_account_ref() -> None:
    _seed_scan_findings()
    client = TestClient(app)
    resp = client.get("/v1/findings?account=aws:111111111111", headers=_AUTH)
    assert resp.status_code == 200
    assert _ids(resp) == {"f-aws-prod"}


def test_filter_by_environment_and_domain() -> None:
    _seed_scan_findings()
    client = TestClient(app)
    resp = client.get("/v1/findings?environment=prod&domain=vuln", headers=_AUTH)
    assert resp.status_code == 200
    assert _ids(resp) == {"f-gcp-vuln"}


def test_filter_by_domain_cspm() -> None:
    _seed_scan_findings()
    client = TestClient(app)
    resp = client.get("/v1/findings?domain=cspm", headers=_AUTH)
    assert resp.status_code == 200
    assert _ids(resp) == {"f-aws-prod", "f-aws-dev"}


def test_unknown_filter_values_never_raise() -> None:
    _seed_scan_findings()
    client = TestClient(app)
    # Unknown domain / provider must not 4xx — normalize + return an empty match.
    resp = client.get("/v1/findings?domain=not-a-domain&provider=", headers=_AUTH)
    assert resp.status_code == 200
    assert resp.json()["findings"] == []


def test_no_scope_filter_is_backward_compatible() -> None:
    _seed_scan_findings()
    client = TestClient(app)
    resp = client.get("/v1/findings", headers=_AUTH)
    assert resp.status_code == 200
    assert len(resp.json()["findings"]) == 3
