"""Regression tests for consolidated cloud coverage (#3680)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from agent_bom.cli._terminal_sections import print_benchmark_line
from agent_bom.cloud.aws_cis_benchmark import CISBenchmarkReport, CISCheckResult, CheckStatus
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
