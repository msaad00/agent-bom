"""AWS CIS scope must never turn partial or unauthenticated reads into PASS."""

from __future__ import annotations

import inspect
import sys
import types
from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import aws_cis_benchmark as cis


def _install_boto_modules(monkeypatch) -> None:
    boto3 = types.ModuleType("boto3")
    botocore = types.ModuleType("botocore")
    botocore.__path__ = []  # type: ignore[attr-defined]
    config = types.ModuleType("botocore.config")
    exceptions = types.ModuleType("botocore.exceptions")

    class ClientError(Exception):
        pass

    exceptions.ClientError = ClientError
    config.Config = MagicMock(side_effect=lambda **kwargs: types.SimpleNamespace(**kwargs))
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", config)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", exceptions)


def _passing_check(_client) -> cis.CISCheckResult:
    """CIS 5.2 — No unrestricted ingress to admin ports."""
    return cis.CISCheckResult(
        check_id="5.2",
        title="No unrestricted ingress to admin ports",
        status=cis.CheckStatus.PASS,
        severity="high",
        evidence="No security groups allow unrestricted ingress to SSH/RDP.",
    )


def _coverage_error_check(_client) -> cis.CISCheckResult:
    """CIS 5.2 — No unrestricted ingress to admin ports."""
    return cis.CISCheckResult(
        check_id="5.2",
        title="No unrestricted ingress to admin ports",
        status=cis.CheckStatus.ERROR,
        severity="high",
        evidence="Could not query security groups (AWS error code: ThrottlingException)",
    )


def _session(*, account: str | None = "123456789012") -> MagicMock:
    session = MagicMock()
    session.region_name = "us-east-1"
    sts = MagicMock()
    if account is None:
        sts.get_caller_identity.side_effect = RuntimeError("unverified")
    else:
        sts.get_caller_identity.return_value = {"Account": account}
    session.client.side_effect = lambda service, **_kwargs: sts if service == "sts" else MagicMock()
    return session


def test_single_region_result_cannot_certify_regional_pass(monkeypatch) -> None:
    _install_boto_modules(monkeypatch)
    monkeypatch.setattr(cis, "_CHECKS", [("ec2", _passing_check)])
    monkeypatch.setattr(cis, "_SPECIAL_CHECKS", [])

    report = cis.run_benchmark(session=_session(), checks=["5.2"])

    assert report.completeness == "partial"
    assert report.regions_scanned == ["us-east-1"]
    assert report.checks[0].status is cis.CheckStatus.ERROR
    assert "enabled AWS regions" in report.checks[0].evidence


def test_unverified_account_identity_cannot_report_pass(monkeypatch) -> None:
    _install_boto_modules(monkeypatch)
    monkeypatch.setattr(cis, "_CHECKS", [("ec2", _passing_check)])
    monkeypatch.setattr(cis, "_SPECIAL_CHECKS", [])

    report = cis.run_benchmark(session=_session(account=None), checks=["5.2"], region_scope_complete=True)

    assert report.completeness == "unavailable"
    assert report.account_id == ""
    assert report.checks[0].status is cis.CheckStatus.ERROR
    assert "GetCallerIdentity" in report.checks[0].evidence


def test_complete_region_enumeration_preserves_pass(monkeypatch) -> None:
    _install_boto_modules(monkeypatch)
    home = cis.CISBenchmarkReport(
        account_id="123456789012",
        checks=[_passing_check(None)],
        completeness="complete",
    )
    other = cis.CISBenchmarkReport(
        account_id="123456789012",
        checks=[_passing_check(None)],
        completeness="complete",
    )
    run = MagicMock(side_effect=[home, other])
    monkeypatch.setattr(cis, "run_benchmark", run)
    monkeypatch.setattr(
        "agent_bom.cloud.aws_inventory._resolve_region_list",
        lambda *_args, **_kwargs: ["us-east-1", "eu-west-1"],
    )

    report = cis.run_benchmark_all_regions(session=_session())

    assert report.completeness == "complete"
    assert report.regions_scanned == ["us-east-1", "eu-west-1"]
    assert report.checks[0].status is cis.CheckStatus.PASS
    assert all(call.kwargs["region_scope_complete"] is True for call in run.call_args_list)


def test_check_coverage_error_marks_complete_scope_partial(monkeypatch) -> None:
    _install_boto_modules(monkeypatch)
    monkeypatch.setattr(cis, "_CHECKS", [("ec2", _coverage_error_check)])
    monkeypatch.setattr(cis, "_SPECIAL_CHECKS", [])

    report = cis.run_benchmark(session=_session(), checks=["5.2"], region_scope_complete=True)

    assert report.completeness == "partial"
    assert any("coverage" in warning.lower() for warning in report.warnings)


def test_benchmark_clients_use_adaptive_retry_budget(monkeypatch) -> None:
    _install_boto_modules(monkeypatch)
    monkeypatch.setattr(cis, "_CHECKS", [("ec2", _passing_check)])
    monkeypatch.setattr(cis, "_SPECIAL_CHECKS", [])
    session = _session()

    cis.run_benchmark(session=session, checks=["5.2"], region_scope_complete=True)

    ec2_call = next(call for call in session.client.call_args_list if call.args == ("ec2",))
    assert ec2_call.kwargs["config"].retries == {"max_attempts": 5, "mode": "adaptive"}


def test_benchmark_clients_do_not_share_mutable_retry_state(monkeypatch) -> None:
    _install_boto_modules(monkeypatch)

    first = cis._aws_client_config()
    first.retries.clear()
    first.retries.update({"total_max_attempts": 6, "mode": "adaptive"})

    second = cis._aws_client_config()

    assert second.retries == {"max_attempts": 5, "mode": "adaptive"}
    assert cis._AWS_RETRY_CONFIG == {"max_attempts": 5, "mode": "adaptive"}


def test_root_usage_check_receives_logs_and_cloudwatch_clients(monkeypatch) -> None:
    _install_boto_modules(monkeypatch)
    monkeypatch.setattr(cis, "_CHECKS", [])
    session = _session()
    logs = MagicMock()
    cloudwatch = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "metricFilters": [
                {
                    "filterPattern": '{ $.userIdentity.type = "Root" }',
                    "metricTransformations": [{"metricName": "RootUsage", "metricNamespace": "Security"}],
                }
            ]
        }
    ]
    logs.get_paginator.return_value = paginator
    cloudwatch.describe_alarms_for_metric.return_value = {"MetricAlarms": [{"AlarmName": "RootUsageAlarm"}]}
    sts = session.client("sts")

    def client(service: str, **_kwargs):
        return {"sts": sts, "logs": logs, "cloudwatch": cloudwatch}.get(service, MagicMock())

    session.client.side_effect = client

    report = cis.run_benchmark(session=session, checks=["4.3"], region_scope_complete=True)

    assert report.checks[0].status is cis.CheckStatus.PASS
    cloudwatch.describe_alarms_for_metric.assert_called_once_with(MetricName="RootUsage", Namespace="Security")


@pytest.mark.parametrize(
    ("check", "pattern"),
    [
        (cis._check_4_1, "UnauthorizedAccess AccessDenied"),
        (cis._check_4_4, "DeleteGroupPolicy PutRolePolicy CreatePolicy"),
    ],
)
def test_monitoring_checks_cannot_pass_without_a_targeting_alarm(check, pattern: str) -> None:
    logs = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "metricFilters": [
                {
                    "filterPattern": pattern,
                    "metricTransformations": [{"metricName": "SecurityEvents", "metricNamespace": "Security"}],
                }
            ]
        }
    ]
    logs.get_paginator.return_value = paginator
    cloudwatch = MagicMock()
    cloudwatch.describe_alarms_for_metric.return_value = {"MetricAlarms": []}

    result = check(logs, cloudwatch)

    assert result.status is cis.CheckStatus.FAIL
    assert "alarm" in result.evidence.lower()


def test_failed_region_enumeration_marks_regional_pass_unknown(monkeypatch) -> None:
    _install_boto_modules(monkeypatch)
    home = cis.CISBenchmarkReport(
        account_id="123456789012",
        checks=[_passing_check(None)],
    )
    monkeypatch.setattr(cis, "run_benchmark", MagicMock(return_value=home))

    def _partial(_session, default_region, *, regions, warnings):
        warnings.append(f"Could not enumerate enabled AWS regions; scanning {default_region} only")
        return [default_region]

    monkeypatch.setattr("agent_bom.cloud.aws_inventory._resolve_region_list", _partial)

    report = cis.run_benchmark_all_regions(session=_session())

    assert report.completeness == "partial"
    assert report.checks[0].status is cis.CheckStatus.ERROR
    assert "Region enumeration was incomplete" in report.checks[0].evidence


def test_failed_regional_scan_marks_merged_pass_unknown(monkeypatch) -> None:
    _install_boto_modules(monkeypatch)
    home = cis.CISBenchmarkReport(
        account_id="123456789012",
        checks=[_passing_check(None)],
    )
    run = MagicMock(side_effect=[home, RuntimeError("regional failure")])
    monkeypatch.setattr(cis, "run_benchmark", run)
    monkeypatch.setattr(
        "agent_bom.cloud.aws_inventory._resolve_region_list",
        lambda *_args, **_kwargs: ["us-east-1", "eu-west-1"],
    )

    report = cis.run_benchmark_all_regions(session=_session())

    assert report.completeness == "partial"
    assert report.checks[0].status is cis.CheckStatus.ERROR
    assert any("skipped region eu-west-1" in warning for warning in report.warnings)


def test_report_serializes_scope_and_completeness() -> None:
    report = cis.CISBenchmarkReport(
        account_id="123456789012",
        accounts_scanned=["123456789012"],
        regions_scanned=["us-east-1", "eu-west-1"],
        completeness="complete",
        scope="enabled-regions",
    )

    payload = report.to_dict()

    assert payload["completeness"] == "complete"
    assert payload["scope"] == "enabled-regions"
    assert payload["accounts_scanned"] == ["123456789012"]
    assert payload["regions_scanned"] == ["us-east-1", "eu-west-1"]


@pytest.mark.parametrize(
    ("entrypoint", "explicit_scope_guard"),
    [
        pytest.param("cli", "if aws_region:", id="cli"),
        pytest.param("rest", "if region_arg:", id="rest"),
        pytest.param("mcp", "if region:", id="mcp"),
    ],
)
def test_public_estate_benchmark_entrypoints_preserve_explicit_region_scope(
    entrypoint: str,
    explicit_scope_guard: str,
) -> None:
    if entrypoint == "cli":
        from agent_bom.cli.agents._cloud import run_benchmarks as target
    elif entrypoint == "rest":
        from agent_bom.api.routes.cloud import _run_cis_benchmark as target
    else:
        from agent_bom.mcp_tools.compliance import cis_benchmark_impl as target

    source = inspect.getsource(target)
    assert "run_benchmark_all_regions" in source
    assert explicit_scope_guard in source


class _SerializedReport:
    def to_dict(self) -> dict[str, object]:
        return {"benchmark": "CIS AWS Foundations", "completeness": "complete", "checks": []}


@pytest.mark.asyncio
async def test_mcp_omitted_region_fans_out_but_explicit_region_stays_scoped(monkeypatch) -> None:
    from agent_bom.cloud import ambient_credentials, aws_cis_benchmark
    from agent_bom.mcp_tools.compliance import cis_benchmark_impl

    calls: list[tuple[str, str | None]] = []
    monkeypatch.setattr(ambient_credentials, "ambient_cis_enabled", lambda: True)
    monkeypatch.setattr(ambient_credentials, "configured_aws_profile", lambda: None)
    monkeypatch.setattr(
        aws_cis_benchmark,
        "run_benchmark_all_regions",
        lambda **kwargs: calls.append(("all", kwargs.get("region"))) or _SerializedReport(),
    )
    monkeypatch.setattr(
        aws_cis_benchmark,
        "run_benchmark",
        lambda **kwargs: calls.append(("one", kwargs.get("region"))) or _SerializedReport(),
    )

    await cis_benchmark_impl(
        provider="aws",
        region=None,
        profile=None,
        subscription_id=None,
        project_id=None,
        checks=None,
        _truncate_response=lambda value: value,
    )
    await cis_benchmark_impl(
        provider="aws",
        region="eu-west-1",
        profile=None,
        subscription_id=None,
        project_id=None,
        checks=None,
        _truncate_response=lambda value: value,
    )

    assert calls == [("all", None), ("one", "eu-west-1")]


def test_rest_omitted_region_fans_out_but_explicit_region_stays_scoped(monkeypatch) -> None:
    from agent_bom.api.routes.cloud import _run_cis_benchmark
    from agent_bom.cloud import aws_cis_benchmark

    calls: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        aws_cis_benchmark,
        "run_benchmark_all_regions",
        lambda **kwargs: calls.append(("all", kwargs.get("region"))) or _SerializedReport(),
    )
    monkeypatch.setattr(
        aws_cis_benchmark,
        "run_benchmark",
        lambda **kwargs: calls.append(("one", kwargs.get("region"))) or _SerializedReport(),
    )

    all_regions = _run_cis_benchmark("tenant-a", "aws", None, None, None, "", "")
    one_region = _run_cis_benchmark("tenant-a", "aws", None, "eu-west-1", None, "", "")

    assert all_regions["completeness"] == "complete"
    assert one_region["completeness"] == "complete"
    assert calls == [("all", None), ("one", "eu-west-1")]
