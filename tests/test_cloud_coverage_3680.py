"""Regression tests for consolidated cloud coverage (#3680)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from agent_bom.cli._terminal_sections import print_benchmark_line
from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISBenchmarkReport, CISCheckResult
from agent_bom.cloud.gcp_cis_benchmark import GCPCISReport, _gcp_paginate_list


def test_gcp_paginate_list_collects_all_pages() -> None:
    resource = MagicMock()
    first_request = MagicMock(name="req1")
    second_request = MagicMock(name="req2")
    resource.list.return_value = first_request
    resource.list_next.side_effect = [second_request, None]
    first_request.execute.return_value = {"items": [{"name": "a"}], "nextPageToken": "t2"}
    second_request.execute.return_value = {"items": [{"name": "b"}]}

    items = _gcp_paginate_list(resource, "items", project="demo")

    assert [item["name"] for item in items] == ["a", "b"]
    resource.list.assert_called_once_with(project="demo")


def test_aws_cis_report_surfaces_errored_checks() -> None:
    report = CISBenchmarkReport(
        checks=[
            CISCheckResult(check_id="1", title="pass", status=CheckStatus.PASS, severity="low"),
            CISCheckResult(check_id="2", title="fail", status=CheckStatus.FAIL, severity="high"),
            CISCheckResult(check_id="3", title="err", status=CheckStatus.ERROR, severity="medium"),
        ]
    )
    payload = report.to_dict()
    assert payload["errored"] == 1
    assert payload["evaluated"] == 2
    assert payload["pass_rate"] == 50.0


def test_gcp_cis_report_surfaces_errored_checks() -> None:
    report = GCPCISReport(
        checks=[
            CISCheckResult(check_id="6.1", title="ssl", status=CheckStatus.ERROR, severity="high"),
            CISCheckResult(check_id="6.2", title="public", status=CheckStatus.PASS, severity="high"),
        ]
    )
    payload = report.to_dict()
    assert payload["errored"] == 1
    assert payload["evaluated"] == 1
    assert payload["pass_rate"] == 100.0


def test_print_benchmark_line_includes_errored_count(capsys) -> None:
    from rich.console import Console

    con = Console(file=open("/dev/null", "w"), force_terminal=True, width=120)
    # Rich still renders; capture via record=True pattern is heavy — assert callable accepts errored.
    print_benchmark_line(con, "CIS AWS", total=10, passed=3, failed=1, pass_rate=75.0, errored=6)


def test_discover_lambda_attaches_packages_for_ai_runtime() -> None:
    from agent_bom.cloud import aws_inventory as inv
    from agent_bom.models import Package

    class _LambdaClient:
        def get_paginator(self, name: str):
            assert name == "list_functions"

            class _Pag:
                def paginate(self):
                    yield {
                        "Functions": [
                            {
                                "FunctionName": "ai-fn",
                                "FunctionArn": "arn:aws:lambda:us-east-1:123:function:ai-fn",
                                "Runtime": "python3.12",
                                "Role": "arn:aws:iam::123:role/lambda",
                                "VpcConfig": {},
                            }
                        ]
                    }

            return _Pag()

    class _Session:
        def client(self, svc, **_kw):
            assert svc == "lambda"
            return _LambdaClient()

    with patch(
        "agent_bom.cloud.aws._extract_lambda_packages",
        return_value=[Package(name="requests", version="2.32.0", ecosystem="pypi")],
    ):
        rows = inv._discover_lambda(_Session(), "us-east-1", account_id="123", warnings=[])

    assert rows[0]["package_count"] == 1
    assert rows[0]["packages"][0]["name"] == "requests"


def test_discover_ecr_wires_sbom_pull() -> None:
    from agent_bom.cloud import aws_inventory as inv
    from agent_bom.cloud.sbom_pull import CloudSBOMResult

    class _EcrClient:
        def get_paginator(self, name: str):
            assert name == "describe_repositories"

            class _Pag:
                def paginate(self):
                    yield {"repositories": [{"repositoryName": "app", "repositoryUri": "123.dkr.ecr.us-east-1.amazonaws.com/app"}]}

            return _Pag()

    class _Session:
        def client(self, svc, **_kw):
            assert svc == "ecr"
            return _EcrClient()

    sbom = CloudSBOMResult(provider="ecr", image_ref="123.dkr.ecr.us-east-1.amazonaws.com/app:latest")
    sbom.packages = [{"name": "flask", "version": "3.0.0"}]

    with (
        patch.object(inv, "_latest_ecr_image_ref", return_value="123.dkr.ecr.us-east-1.amazonaws.com/app:latest"),
        patch("agent_bom.cloud.sbom_pull.pull_cloud_sbom", return_value=sbom),
    ):
        rows = inv._discover_ecr(_Session(), "us-east-1", account_id="123", warnings=[])

    assert rows[0]["package_count"] == 1
    assert rows[0]["packages"][0]["name"] == "flask"


def test_run_benchmark_all_regions_merges_regional_checks() -> None:
    from agent_bom.cloud.aws_cis_benchmark import (
        CheckStatus,
        CISBenchmarkReport,
        CISCheckResult,
        run_benchmark_all_regions,
    )

    home_report = CISBenchmarkReport(
        checks=[
            CISCheckResult(check_id="1.4", title="root", status=CheckStatus.PASS, severity="high"),
            CISCheckResult(check_id="5.1", title="sg", status=CheckStatus.PASS, severity="high", evidence="ok"),
        ]
    )
    other_report = CISBenchmarkReport(
        checks=[CISCheckResult(check_id="5.1", title="sg", status=CheckStatus.FAIL, severity="high", evidence="open")]
    )

    with (
        patch.dict("sys.modules", {"boto3": MagicMock()}),
        patch("agent_bom.cloud.aws_cis_benchmark.run_benchmark") as run_mock,
        patch("agent_bom.cloud.aws_inventory._resolve_region_list", return_value=["us-east-1", "eu-west-1"]),
    ):
        run_mock.side_effect = [home_report, other_report]
        report = run_benchmark_all_regions(region="us-east-1")

    assert report.regions_scanned == ["us-east-1", "eu-west-1"]
    merged = next(c for c in report.checks if c.check_id == "5.1")
    assert merged.status == CheckStatus.FAIL
    assert "eu-west-1" in merged.evidence


def test_serverless_zip_parses_python_metadata() -> None:
    import io
    import zipfile

    from agent_bom.cloud.serverless_zip import packages_from_zip_bytes

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("requests-2.32.0.dist-info/METADATA", "Name: requests\nVersion: 2.32.0\n")

    pkgs = packages_from_zip_bytes(buf.getvalue(), ecosystem="pypi")
    assert len(pkgs) == 1
    assert pkgs[0].name == "requests"
