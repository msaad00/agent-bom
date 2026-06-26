"""CIS benchmark multi-boundary fan-out — Azure subscriptions and GCP projects.

Mirrors the inventory fan-out tests (test_azure_multi_subscription.py): assert the
CIS benchmark runs once per boundary and aggregates with per-boundary attribution,
and that a boundary the credential cannot read is skipped with a warning rather
than failing the whole run.
"""

from __future__ import annotations

import pytest

from agent_bom.cloud import azure_cis_benchmark as az_cis
from agent_bom.cloud import azure_inventory as az_inv
from agent_bom.cloud import gcp_cis_benchmark as gcp_cis
from agent_bom.cloud import gcp_inventory as gcp_inv
from agent_bom.cloud import gcp_organizations as gcp_orgs
from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.base import CloudDiscoveryError


def _report_azure(sub_id: str) -> az_cis.AzureCISReport:
    report = az_cis.AzureCISReport(subscription_id=sub_id)
    report.checks.append(CISCheckResult(check_id="1.1", title="t", status=CheckStatus.PASS, severity="high"))
    report.checks.append(CISCheckResult(check_id="3.1", title="t", status=CheckStatus.FAIL, severity="high"))
    return report


def _report_gcp(project_id: str) -> gcp_cis.GCPCISReport:
    report = gcp_cis.GCPCISReport(project_id=project_id)
    report.checks.append(CISCheckResult(check_id="1.1", title="t", status=CheckStatus.PASS, severity="high"))
    report.checks.append(CISCheckResult(check_id="3.1", title="t", status=CheckStatus.FAIL, severity="high"))
    return report


# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------


def test_azure_fanout_runs_cis_per_subscription_with_attribution(monkeypatch) -> None:
    monkeypatch.setattr(
        az_inv,
        "enumerate_subscription_ids",
        lambda cred: (["sub-a", "sub-b"], []),
    )
    scanned: list[str] = []

    def _fake_run(subscription_id=None, checks=None, credential=None):
        scanned.append(subscription_id)
        return _report_azure(subscription_id)

    monkeypatch.setattr(az_cis, "run_benchmark", _fake_run)

    report = az_cis.run_all_subscription_benchmarks(credential=object())

    assert sorted(scanned) == ["sub-a", "sub-b"]
    assert report.subscriptions_scanned == ["sub-a", "sub-b"]
    # Each check is attributed to its originating subscription.
    attributions = {c.account_id for c in report.checks}
    assert attributions == {"sub-a", "sub-b"}
    # Counts reflect BOTH boundaries (2 checks each => 2 passed, 2 failed).
    assert report.passed == 2
    assert report.failed == 2
    assert report.total == 4
    # to_dict surfaces per-check subscription attribution and the scanned set.
    payload = report.to_dict()
    assert payload["subscriptions_scanned"] == ["sub-a", "sub-b"]
    assert {c["subscription_id"] for c in payload["checks"]} == {"sub-a", "sub-b"}


def test_azure_fanout_skips_unreadable_subscription_with_warning(monkeypatch) -> None:
    monkeypatch.setattr(
        az_inv,
        "enumerate_subscription_ids",
        lambda cred: (["sub-ok", "sub-denied"], []),
    )

    def _fake_run(subscription_id=None, checks=None, credential=None):
        if subscription_id == "sub-denied":
            raise PermissionError("AuthorizationFailed: caller lacks read on sub-denied")
        return _report_azure(subscription_id)

    monkeypatch.setattr(az_cis, "run_benchmark", _fake_run)

    report = az_cis.run_all_subscription_benchmarks(credential=object())

    # Only the readable subscription contributes checks; the denied one is skipped.
    assert report.subscriptions_scanned == ["sub-ok"]
    assert {c.account_id for c in report.checks} == {"sub-ok"}
    assert any("sub-denied skipped" in w for w in report.warnings)
    # The whole run did NOT fail because one subscription was unreadable.
    assert report.total == 2


def test_azure_fanout_raises_when_no_subscriptions(monkeypatch) -> None:
    monkeypatch.setattr(az_inv, "enumerate_subscription_ids", lambda cred: ([], []))
    with pytest.raises(CloudDiscoveryError):
        az_cis.run_all_subscription_benchmarks(credential=object())


# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------


def test_gcp_fanout_runs_cis_per_project_with_attribution(monkeypatch) -> None:
    monkeypatch.setattr(gcp_inv, "_resolve_impersonation", lambda creds, warnings: creds)
    monkeypatch.setattr(gcp_orgs, "list_project_ids", lambda creds, force=False: ["proj-a", "proj-b"])
    scanned: list[str] = []

    def _fake_run(project_id=None, credentials=None, checks=None):
        scanned.append(project_id)
        return _report_gcp(project_id)

    monkeypatch.setattr(gcp_cis, "run_benchmark", _fake_run)

    report = gcp_cis.run_all_project_benchmarks(credentials=object())

    assert sorted(scanned) == ["proj-a", "proj-b"]
    assert report.projects_scanned == ["proj-a", "proj-b"]
    assert {c.account_id for c in report.checks} == {"proj-a", "proj-b"}
    assert report.passed == 2
    assert report.failed == 2
    assert report.total == 4
    payload = report.to_dict()
    assert payload["projects_scanned"] == ["proj-a", "proj-b"]
    assert {c["project_id"] for c in payload["checks"]} == {"proj-a", "proj-b"}


def test_gcp_fanout_skips_unreadable_project_with_warning(monkeypatch) -> None:
    monkeypatch.setattr(gcp_inv, "_resolve_impersonation", lambda creds, warnings: creds)
    monkeypatch.setattr(gcp_orgs, "list_project_ids", lambda creds, force=False: ["proj-ok", "proj-denied"])

    def _fake_run(project_id=None, credentials=None, checks=None):
        if project_id == "proj-denied":
            raise PermissionError("403 caller lacks read on proj-denied")
        return _report_gcp(project_id)

    monkeypatch.setattr(gcp_cis, "run_benchmark", _fake_run)

    report = gcp_cis.run_all_project_benchmarks(credentials=object())

    assert report.projects_scanned == ["proj-ok"]
    assert {c.account_id for c in report.checks} == {"proj-ok"}
    assert any("proj-denied skipped" in w for w in report.warnings)
    assert report.total == 2


def test_gcp_fanout_falls_back_to_ambient_project(monkeypatch) -> None:
    monkeypatch.setattr(gcp_inv, "_resolve_impersonation", lambda creds, warnings: creds)
    monkeypatch.setattr(gcp_orgs, "list_project_ids", lambda creds, force=False: [])
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "solo-project")

    def _fake_run(project_id=None, credentials=None, checks=None):
        return _report_gcp(project_id)

    monkeypatch.setattr(gcp_cis, "run_benchmark", _fake_run)

    report = gcp_cis.run_all_project_benchmarks(credentials=object())
    assert report.projects_scanned == ["solo-project"]
