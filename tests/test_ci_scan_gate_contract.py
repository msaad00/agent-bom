"""Headless scan workflows must choose a failure policy explicitly."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_azure_ingestion_scan_uses_ci_preset() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "azure-ingestion.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["ingest"]["steps"]
    run = next(step["run"] for step in steps if step.get("name") == "Run Azure scan and push results")

    assert "--preset ci" in run


def test_interactive_scan_default_remains_threshold_free() -> None:
    from click.testing import CliRunner

    from agent_bom.cli import main

    result = CliRunner().invoke(main, ["scan", "--help"])

    assert result.exit_code == 0
    assert "--preset" in result.output
