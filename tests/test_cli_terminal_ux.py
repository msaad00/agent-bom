"""Terminal UX consistency — quiet mode, collapsed warnings, single CIS render."""

from __future__ import annotations

from io import StringIO
from unittest.mock import MagicMock

from click.testing import CliRunner
from rich.console import Console

from agent_bom.cli._terminal_sections import print_collapsed_warnings, print_scan_next_steps
from agent_bom.cli.agents._cloud import run_cloud_discovery
from agent_bom.cli.agents._context import ScanContext
from agent_bom.models import AIBOMReport


def test_collapsed_warnings_default_shows_count_hint():
    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=120)
    warnings = [f"warning-{i}" for i in range(5)]
    print_collapsed_warnings(con, warnings, verbose=False, max_visible=2)
    out = buf.getvalue()
    assert "warning-0" in out
    assert "warning-1" in out
    assert "3 more warning(s)" in out
    assert "warning-4" not in out


def test_collapsed_warnings_verbose_lists_all():
    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=120)
    warnings = ["alpha", "beta"]
    print_collapsed_warnings(con, warnings, verbose=True)
    out = buf.getvalue()
    assert "alpha" in out and "beta" in out


def test_quiet_discovery_suppresses_success_lines(monkeypatch):
    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=120)
    ctx = ScanContext(con=con, quiet=True)

    def _discover(provider, **kwargs):
        return ([], [f"{provider}-warn-1", f"{provider}-warn-2", f"{provider}-warn-3"])

    monkeypatch.setattr("agent_bom.cloud.discover_from_provider", _discover)

    run_cloud_discovery(
        ctx,
        skill_only=False,
        aws=True,
        aws_region=None,
        aws_profile=None,
        aws_include_lambda=False,
        aws_include_eks=False,
        aws_include_step_functions=False,
        aws_include_ec2=False,
        aws_include_iam=False,
        aws_ec2_tag=None,
        azure_flag=False,
        azure_subscription=None,
        gcp_flag=False,
        gcp_project=None,
        coreweave_flag=False,
        coreweave_context=None,
        coreweave_namespace=None,
        databricks_flag=False,
        snowflake_flag=False,
        snowflake_authenticator=None,
        nebius_flag=False,
        nebius_api_key=None,
        nebius_project_id=None,
        hf_flag=False,
        hf_token=None,
        hf_username=None,
        hf_organization=None,
        wandb_flag=False,
        wandb_api_key=None,
        wandb_entity=None,
        wandb_project=None,
        mlflow_flag=False,
        mlflow_tracking_uri=None,
        openai_flag=False,
        openai_api_key=None,
        openai_org_id=None,
        ollama_flag=False,
        ollama_host=None,
    )
    assert buf.getvalue() == ""


def test_scan_next_steps_footer():
    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=120)
    report = AIBOMReport(agents=[object(), object()])  # type: ignore[list-item]
    report.cis_benchmark_data = {"checks": [{"check_id": "1.1", "status": "fail"}]}
    print_scan_next_steps(con, report, quiet=False)
    out = buf.getvalue()
    assert "Next" in out
    assert "agent-bom graph" in out
    # The HTML report suggestion must use `scan` (which owns -f/-o); `report`
    # is a command group with no -f option and would error "No such option: -f".
    assert "agent-bom scan . -f html -o agent-bom-report.html" in out
    assert "agent-bom report -f html" not in out


def test_run_benchmarks_does_not_render_cis_inline(monkeypatch):
    """CIS grouped plan renders at report time only, not during benchmarks."""
    from agent_bom.cli.agents._cloud import run_benchmarks

    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=120)
    ctx = ScanContext(con=con, quiet=True)

    fake_report = MagicMock()
    fake_report.passed = 1
    fake_report.failed = 1
    fake_report.total = 2
    fake_report.pass_rate = 50.0
    fake_report.to_dict.return_value = {"checks": []}

    monkeypatch.setattr("agent_bom.cloud.aws_cis_benchmark.run_benchmark", lambda **kwargs: fake_report)
    monkeypatch.setattr(
        "agent_bom.cli.agents._cloud.render_cis_findings_from_context",
        lambda _ctx: (_ for _ in ()).throw(AssertionError("CIS must not render mid-scan")),
    )

    run_benchmarks(
        ctx,
        skill_only=False,
        verify_model_hashes=False,
        project=None,
        hf_token=None,
        aws_cis_benchmark=True,
        aws_region=None,
        aws_profile=None,
        snowflake_cis_benchmark=False,
        snowflake_authenticator=None,
        azure_cis_benchmark=False,
        azure_subscription=None,
        gcp_cis_benchmark=False,
        gcp_project=None,
        databricks_security=False,
        aisvs_flag=False,
        vector_db_scan=False,
        gpu_scan_flag=False,
        gpu_k8s_context=None,
        no_dcgm_probe=False,
        smithery_flag=False,
        smithery_token=None,
        mcp_registry_flag=False,
        snyk_flag=False,
        snyk_token=None,
        snyk_org=None,
        cortex_observability=False,
    )
    assert ctx.cis_benchmark_report is fake_report


def test_connect_aws_renders_next_command():
    from agent_bom.cli import main

    r = CliRunner().invoke(main, ["connect", "aws"])
    assert r.exit_code == 0
    assert "Next" in r.output
    assert "agent-bom scan --aws" in r.output
