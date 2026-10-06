"""Package lookup output must not overstate incomplete imported evidence."""

import asyncio
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from rich.console import Console

from agent_bom.cli import main
from agent_bom.cli.agents.scan_pipeline.matching import _print_scan_verdict
from agent_bom.cli.agents.scan_pipeline.state import ScanState
from agent_bom.parsers.sbom_context import load_sbom_agents
from agent_bom.scanners import package_scan, state


@pytest.mark.parametrize("complete", [False, True])
def test_imported_completeness_controls_both_console_summaries(tmp_path, monkeypatch, complete):
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"type": "library", "name": "flask", "version": "3.1.3", "purl": "pkg:pypi/flask@3.1.3"}],
                **({"compositions": [{"aggregate": "complete"}]} if complete else {}),
            }
        )
    )
    agents, _ = load_sbom_agents(str(path), None)
    output = io.StringIO()
    con = Console(file=output)
    monkeypatch.setattr(package_scan, "console", con)
    state.reset_scan_warnings()

    # Exercise the actual scanner summary through the public asynchronous call.
    async def clean_lookup(*args, **kwargs):
        return 0

    monkeypatch.setattr("agent_bom.scanners.scan_packages", clean_lookup)

    asyncio.run(package_scan.scan_agents(agents))
    _print_scan_verdict(SimpleNamespace(offline=False), ScanState(agents=agents, con=con), 0)
    text = output.getvalue()
    if complete:
        assert "No known vulnerabilities found" in text
    else:
        assert "No known vulnerabilities found" not in text
        assert "coverage" in text.lower()
    state.reset_scan_warnings()


def test_dogfood_fixture_declares_complete_inventory(tmp_path):
    fixture = Path(__file__).parent / "fixtures/test-sbom.cdx.json"
    output = tmp_path / "result.json"
    result = CliRunner().invoke(
        main, ["scan", "--sbom", str(fixture), "--offline", "--no-scan", "--no-auto-update-db", "-f", "json", "-o", str(output)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())["scan_run"]["outcome"] == "complete"


def test_scanner_lookup_warning_prevents_clean_summary_and_is_retained(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(package_scan, "console", Console(file=output))
    state.reset_scan_warnings()
    try:
        state.record_scan_warning("advisory lookup incomplete")
        package_scan._print_vulnerability_summary(0, 0)
        assert "No known vulnerabilities found" not in output.getvalue()
        assert state.consume_scan_warnings() == ["advisory lookup incomplete"]
    finally:
        state.reset_scan_warnings()
