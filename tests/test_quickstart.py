from __future__ import annotations

import json
import subprocess
import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def _fake_scan(monkeypatch):
    """Capture the scan subprocess instead of running a real scan."""
    calls: list[list[str]] = []

    def fake_run(args, check=False, **kwargs):  # noqa: ANN001, ANN003
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("agent_bom.cli._quickstart._resolve_agent_bom", lambda: "agent-bom")
    monkeypatch.setattr("agent_bom.cli._quickstart.subprocess.run", fake_run)
    return calls


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


def test_quickstart_rejects_dry_run_with_run():
    result = CliRunner().invoke(main, ["quickstart", "--dry-run", "--run"])

    assert result.exit_code != 0
    assert "--dry-run cannot be combined with --run" in result.output


def test_quickstart_run_scans_with_context_graph_and_seeds_policy(tmp_path, _fake_scan):
    sample_dir = tmp_path / "stack"

    result = CliRunner().invoke(main, ["quickstart", "--run", "--offline", "--sample-dir", str(sample_dir)])

    assert result.exit_code == 0, result.output
    # sample written
    assert (sample_dir / "inventory.json").exists()
    # scan invoked with --context-graph (graph persistence) and --offline
    assert len(_fake_scan) == 1
    scan_args = _fake_scan[0]
    assert scan_args[1] == "agents"
    assert "--context-graph" in scan_args
    assert "--offline" in scan_args
    assert str(sample_dir / "inventory.json") in scan_args
    # secure-by-default gateway baseline seeded and valid
    policy_path = sample_dir / "gateway-baseline-policy.json"
    assert policy_path.exists()
    policy = json.loads(policy_path.read_text())
    assert policy["mode"] == "audit"
    assert policy["rules"]
    # handoff printed
    assert "Onboarding complete" in result.output
    assert "/security-graph" in result.output


def test_quickstart_run_no_gateway_policy_skips_file(tmp_path, _fake_scan):
    sample_dir = tmp_path / "stack"

    result = CliRunner().invoke(main, ["quickstart", "--run", "--offline", "--no-gateway-policy", "--sample-dir", str(sample_dir)])

    assert result.exit_code == 0, result.output
    assert not (sample_dir / "gateway-baseline-policy.json").exists()
    assert "Skipped gateway baseline policy" in result.output


def test_quickstart_run_surfaces_scan_failure(tmp_path, monkeypatch):
    sample_dir = tmp_path / "stack"
    monkeypatch.setattr("agent_bom.cli._quickstart._resolve_agent_bom", lambda: "agent-bom")
    monkeypatch.setattr(
        "agent_bom.cli._quickstart.subprocess.run",
        lambda args, check=False, **kwargs: subprocess.CompletedProcess(args, 2),
    )

    result = CliRunner().invoke(main, ["quickstart", "--run", "--offline", "--sample-dir", str(sample_dir)])

    assert result.exit_code != 0
    assert "Scan exited with status 2" in result.output


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
