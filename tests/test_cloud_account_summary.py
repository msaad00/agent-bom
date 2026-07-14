"""Per-account cloud drill summary — GET /v1/cloud/accounts/{account_ref}/summary.

Read-only aggregation over already-ingested findings + stored CIS benchmark
blocks, scoped to one provider+account (issue #3931). Reuses the #3946 scope
filters and the #3946 domain rollup; never triggers a live provider scan.
"""

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


def _seed() -> None:
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    job = ScanJob(
        job_id="acct-job",
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
                "id": "f-aws-prod-cspm",
                "severity": "high",
                "security_domain": "cspm",
                "provider": "aws",
                "account_ref": "aws:111111111111",
                "region": "us-east-1",
                "environment": "prod",
                "title": "aws prod misconfig",
                "asset": {"identifier": "arn:aws:s3:::bucket", "asset_type": "cloud_resource"},
            },
            {
                "id": "f-aws-prod-vuln",
                "severity": "critical",
                "security_domain": "vuln",
                "provider": "aws",
                "account_ref": "aws:111111111111",
                "region": "us-east-1",
                "environment": "prod",
                "title": "aws prod cve",
            },
            {
                "id": "f-aws-prod-iam",
                "severity": "medium",
                "security_domain": "aispm",
                "provider": "aws",
                "account_ref": "aws:111111111111",
                "environment": "prod",
                "title": "aws prod role risk",
                "asset": {"identifier": "role/admin", "asset_type": "role"},
            },
            {
                "id": "f-aws-dev-cspm",
                "severity": "medium",
                "security_domain": "cspm",
                "provider": "aws",
                "account_ref": "aws:222222222222",
                "environment": "dev",
                "title": "aws dev misconfig",
            },
        ],
        # Stored CIS benchmark side block for the prod account: 8 pass / 2 fail.
        "cis_benchmark_data": {
            "benchmark": "CIS AWS Foundations",
            "provider": "aws",
            "account_id": "111111111111",
            "passed": 8,
            "failed": 2,
            "evaluated": 10,
            "pass_rate": 80.0,
            "checks": [],
        },
    }
    _get_store().put(job)


def test_summary_scopes_to_account_and_reconciles_severity() -> None:
    _seed()
    client = TestClient(app)
    resp = client.get("/v1/cloud/accounts/aws:111111111111/summary", headers=_AUTH)
    assert resp.status_code == 200
    body = resp.json()

    assert body["schema_version"] == "cloud.account.summary.v1"
    assert body["provider"] == "aws"
    assert body["account"] == "111111111111"
    assert body["account_ref"] == "aws:111111111111"
    # Only the three prod-account findings; the dev-account one is excluded.
    assert body["findings_total"] == 3
    assert body["empty"] is False
    # Top-level severity strip sums to the counted total (honest invariant).
    assert sum(body["severity"].values()) == body["findings_total"]
    assert "us-east-1" in body["regions"]
    assert "prod" in body["environments"]


def test_summary_domains_are_five_lanes_each_reconciled() -> None:
    _seed()
    client = TestClient(app)
    body = client.get("/v1/cloud/accounts/aws:111111111111/summary", headers=_AUTH).json()

    lanes = {lane["domain"]: lane for lane in body["domains"]}
    assert set(lanes) == {"cspm", "vuln", "appsec_sca", "dspm", "aispm"}
    assert lanes["cspm"]["count"] == 1
    assert lanes["vuln"]["count"] == 1
    assert lanes["aispm"]["count"] == 1
    assert lanes["dspm"]["count"] == 0
    # Every lane's severity strip sums to its own count.
    for lane in body["domains"]:
        assert sum(lane["severity"].values()) == lane["count"]
    # Drill links carry the #3946 scope filter params for this account.
    assert "account=aws%3A111111111111" in lanes["cspm"]["href"] or "account=aws:111111111111" in lanes["cspm"]["href"]
    assert "domain=cspm" in lanes["cspm"]["href"]


def test_summary_surfaces_stored_cis_pass_rate() -> None:
    _seed()
    client = TestClient(app)
    body = client.get("/v1/cloud/accounts/aws:111111111111/summary", headers=_AUTH).json()

    comp = body["compliance"]
    assert comp["evaluated"] == 10
    assert comp["passed"] == 8
    assert comp["failed"] == 2
    assert comp["pass_rate"] == 80.0
    assert any(b["provider"] == "aws" for b in comp["benchmarks"])


def test_summary_counts_assets_and_roles_from_findings() -> None:
    _seed()
    client = TestClient(app)
    body = client.get("/v1/cloud/accounts/aws:111111111111/summary", headers=_AUTH).json()
    # Two findings carry an asset (bucket + role); one is a role identity.
    assert body["assets"]["count"] == 2
    assert body["identities"]["roles"] == 1


def test_unknown_account_never_raises_and_is_empty() -> None:
    _seed()
    client = TestClient(app)
    resp = client.get("/v1/cloud/accounts/aws:999999999999/summary", headers=_AUTH)
    assert resp.status_code == 200
    body = resp.json()
    assert body["findings_total"] == 0
    assert body["empty"] is True
    assert body["compliance"]["pass_rate"] is None
    # All five lanes still present at zero.
    assert len(body["domains"]) == 5


def test_malformed_account_ref_never_raises() -> None:
    _seed()
    client = TestClient(app)
    resp = client.get("/v1/cloud/accounts/not-an-account/summary", headers=_AUTH)
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == ""
    assert body["findings_total"] == 0
    assert body["empty"] is True


def test_summary_is_tenant_scoped() -> None:
    _seed()
    client = TestClient(app)
    other = proxy_headers(tenant="tenant-beta")
    body = client.get("/v1/cloud/accounts/aws:111111111111/summary", headers=other).json()
    # The seeded job belongs to tenant default; another tenant sees nothing.
    assert body["findings_total"] == 0
    assert body["empty"] is True


def test_case_insensitive_account_match() -> None:
    _seed()
    client = TestClient(app)
    body = client.get("/v1/cloud/accounts/AWS:111111111111/summary", headers=_AUTH).json()
    assert body["findings_total"] == 3
