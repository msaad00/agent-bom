from types import SimpleNamespace

from agent_bom.api.cloud_scan_scopes import cloud_account_summary, connection_scope, scanned_cloud_scopes, scopes_from_result
from agent_bom.api.models import JobStatus


def test_scopes_from_every_cis_bundle_and_finding_asset() -> None:
    result = {
        "gcp_cis_benchmark": {"project_id": "proj-a", "projects_scanned": ["proj-a", "proj-b"]},
        "snowflake_cis_benchmark": {"account": "ACME-XY"},
        "findings": [
            {"asset": {"account_ref": "azure:sub-9"}},
            {"account_ref": "github:org"},
            {"account_ref": ""},
            "not-a-row",
        ],
    }
    assert scopes_from_result(result) == {"gcp:proj-a", "gcp:proj-b", "snowflake:ACME-XY", "azure:sub-9"}


def test_non_cloud_or_empty_results_have_no_scope() -> None:
    assert scopes_from_result(None) == set()
    assert scopes_from_result({"findings": [{"id": "x", "severity": "low"}]}) == set()
    assert scopes_from_result({"cis_benchmark": {"account_id": ""}}) == set()


def test_scanned_scopes_ignore_unfinished_jobs_and_track_latest() -> None:
    cloud = {"cis_benchmark": {"account_id": "111"}}
    jobs = [
        SimpleNamespace(status=JobStatus.DONE, result=cloud, completed_at="2026-09-01T00:00:00+00:00"),
        SimpleNamespace(status=JobStatus.DONE, result=cloud, completed_at="2026-09-03T00:00:00+00:00"),
        SimpleNamespace(status=JobStatus.FAILED, result={"cis_benchmark": {"account_id": "222"}}, completed_at="2026-09-09T00:00:00+00:00"),
        SimpleNamespace(status=JobStatus.DONE, result={"findings": []}, completed_at="2026-09-10T00:00:00+00:00"),
    ]
    assert scanned_cloud_scopes(jobs) == {"scopes": ["aws:111"], "last_scan_at": "2026-09-03T00:00:00+00:00"}


def test_connection_scope_derives_account_or_falls_back_to_connection_id() -> None:
    aws = SimpleNamespace(id="c1", provider="aws", role_ref="arn:aws:iam::123:role/r", auth_params={}, last_scan_at=None)
    azure = SimpleNamespace(id="c2", provider="azure", role_ref="", auth_params={"subscription_id": "sub-1"}, last_scan_at=None)
    unknown = SimpleNamespace(id="c3", provider="gcp", role_ref="", auth_params={}, last_scan_at=None)
    assert connection_scope(aws) == "aws:123"
    assert connection_scope(azure) == "azure:sub-1"
    assert connection_scope(unknown) == "connection:c3"
    summary = cloud_account_summary([aws, azure], {"scopes": ["aws:123", "gcp:p"], "last_scan_at": "2026-09-02T00:00:00+00:00"})
    assert summary["count"] == 3
    assert summary["providers"] == ["aws", "azure", "gcp"]
    assert summary["last_scan_at"] == "2026-09-02T00:00:00+00:00"
