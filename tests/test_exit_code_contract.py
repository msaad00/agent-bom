"""A non-zero scan exit must read as a verdict, not as a crash.

The first-run demo exits `1` because a fail-closed gate matched. Without an
explicit statement of the contract, that is indistinguishable from a scanner
failure to someone running agent-bom for the first time. The exit code itself
is correct and must not change; only its legibility does.
"""

from __future__ import annotations

from io import StringIO

from click.testing import CliRunner
from rich.console import Console

from agent_bom.cli import main
from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._post import EXIT_CODE_CONTRACT_URL, compute_exit_code
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import AIBOMReport


def _console() -> tuple[Console, StringIO]:
    buffer = StringIO()
    return Console(file=buffer, force_terminal=False, width=200), buffer


def _report_with_high_finding() -> AIBOMReport:
    finding = Finding(
        finding_type=FindingType.MCP_BLOCKLIST,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="bad-mcp", asset_type="mcp_server", location="mcp.json"),
        severity="high",
        title="Blocked MCP",
    )
    return AIBOMReport(findings=[finding])


def _compute(ctx: ScanContext, *, fail_on_severity: str | None, quiet: bool) -> int:
    return compute_exit_code(
        ctx,
        fail_on_severity=fail_on_severity,
        warn_on_severity=None,
        fail_on_kev=False,
        fail_if_ai_risk=False,
        push_url=None,
        push_api_key=None,
        quiet=quiet,
    )


def test_nonzero_exit_states_it_is_a_verdict_not_a_crash():
    """A non-zero exit prints the contract in plain language plus where to read it."""
    con, buffer = _console()
    ctx = ScanContext(con=con, report=_report_with_high_finding())

    assert _compute(ctx, fail_on_severity="high", quiet=False) == 1

    output = buffer.getvalue()
    assert "not a scanner error" in output
    assert "report above is complete" in output
    assert EXIT_CODE_CONTRACT_URL in output


def test_zero_exit_does_not_print_the_contract_note():
    """A clean scan must not print gate wording that implies something happened."""
    con, buffer = _console()
    ctx = ScanContext(con=con, report=_report_with_high_finding())

    assert _compute(ctx, fail_on_severity=None, quiet=False) == 0

    output = buffer.getvalue()
    assert "not a scanner error" not in output
    assert EXIT_CODE_CONTRACT_URL not in output


def test_quiet_suppresses_the_contract_note():
    """`--quiet` is used by CI presets; it must stay machine-clean."""
    con, buffer = _console()
    ctx = ScanContext(con=con, report=_report_with_high_finding())

    assert _compute(ctx, fail_on_severity="high", quiet=True) == 1
    assert buffer.getvalue() == ""


def test_scan_help_documents_the_flagless_fail_closed_gates():
    """`--help` listed exit 1 as flag-driven only, which the demo disproves.

    `agent-bom scan --demo --offline` exits 1 with no `--fail-on-*` flag set,
    because a known-malicious package is a fail-closed block. Help text that
    omits that reads as a contradiction the first time someone hits it.
    """
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])

    assert result.exit_code == 0
    assert "malicious" in result.output.lower()
    assert "not a crash" in result.output.lower()


def test_contract_note_reaches_real_cli_output():
    """The note must survive the actual `agent-bom scan` wiring, not just the unit."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["scan", "--demo", "--offline", "--no-auto-update-db", "--format", "console"],
            catch_exceptions=False,
        )

    assert result.exit_code == 1, result.output
    assert "not a scanner error" in result.output
    assert EXIT_CODE_CONTRACT_URL in result.output
