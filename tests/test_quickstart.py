from __future__ import annotations

import tomllib
from pathlib import Path

from click.testing import CliRunner

from agent_bom.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_quickstart_dry_run_offline_prints_local_next_steps():
    result = CliRunner().invoke(main, ["quickstart", "--dry-run", "--offline"])

    assert result.exit_code == 0
    assert "agent-bom quickstart" in result.output
    assert "agent-bom agents --demo --offline" in result.output
    assert "agent-bom quickstart --write-sample --sample-dir agent-bom-first-run" in result.output
    assert "agent-bom agents --inventory agent-bom-first-run/inventory.json -p agent-bom-first-run --offline" in result.output
    assert "agent-bom serve --host 127.0.0.1 --port 8422" in result.output
    assert "http://127.0.0.1:8422/docs" in result.output
    assert "agent-bom[all]" in result.output
    assert "MLflow remains separate" in result.output


def test_quickstart_write_sample_creates_first_run_stack(tmp_path):
    sample_dir = tmp_path / "sample"

    result = CliRunner().invoke(main, ["quickstart", "--write-sample", "--sample-dir", str(sample_dir), "--offline"])

    assert result.exit_code == 0
    assert (sample_dir / "inventory.json").exists()
    assert "Wrote " in result.output
    assert f"agent-bom agents --inventory {sample_dir / 'inventory.json'} -p {sample_dir} --offline" in result.output


def test_quickstart_rejects_write_sample_dry_run():
    result = CliRunner().invoke(main, ["quickstart", "--dry-run", "--write-sample"])

    assert result.exit_code != 0
    assert "--dry-run cannot be combined with --write-sample" in result.output


def test_all_extra_composes_first_run_extras_without_mlflow():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    extras = pyproject["project"]["optional-dependencies"]

    all_extra = extras["all"]
    assert "agent-bom[ui]" in all_extra
    assert "agent-bom[mcp-server]" in all_extra
    assert "agent-bom[graph]" in all_extra
    assert "agent-bom[cloud]" in all_extra
    assert "agent-bom[dev]" not in all_extra
    assert "agent-bom[docs]" not in all_extra
    assert not any("mlflow" in dep.lower() for dep in all_extra)
    assert not any("mlflow" in dep.lower() for dep in extras["cloud"])
