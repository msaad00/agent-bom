from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main

ROOT = Path(__file__).resolve().parents[1]
DURABLE_LOCAL_CONTROL_PLANE = "agent-bom serve --persist ~/.agent-bom/control-plane.db"
LOCAL_ANALYST_CONTROL_PLANE = f"AGENT_BOM_NO_AUTH_ROLE=analyst {DURABLE_LOCAL_CONTROL_PLANE}"


@pytest.fixture()
def _fake_scan(monkeypatch):
    """Capture the scan subprocess instead of running a real scan."""

    class CapturedScanCalls(list[list[str]]):
        environments: list[dict[str, str] | None]

        def __init__(self) -> None:
            super().__init__()
            self.environments = []

    calls = CapturedScanCalls()

    def fake_run(args, check=False, **kwargs):  # noqa: ANN001, ANN003
        calls.append(list(args))
        calls.environments.append(kwargs.get("env"))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("agent_bom.cli._quickstart._resolve_agent_bom", lambda: "agent-bom")
    monkeypatch.setattr("agent_bom.cli._quickstart.subprocess.run", fake_run)
    monkeypatch.setattr(
        "agent_bom.cli._quickstart._verify_persisted_graph",
        lambda **kwargs: {"scan_id": "fake-scan-id", "nodes": 3, "edges": 2},
    )
    return calls


def test_quickstart_dry_run_offline_prints_local_next_steps():
    result = CliRunner().invoke(main, ["quickstart", "--dry-run", "--offline"])

    assert result.exit_code == 0
    assert "agent-bom quickstart" in result.output
    assert "agent-bom scan --demo --offline" in result.output
    assert "agent-bom quickstart --write-sample --sample-dir agent-bom-first-run" in result.output
    assert "agent-bom scan --inventory agent-bom-first-run/inventory.json -p agent-bom-first-run --offline" in result.output
    assert f"{LOCAL_ANALYST_CONTROL_PLANE} --host 127.0.0.1 --port 8422" in result.output
    assert "http://127.0.0.1:8422/docs" in result.output
    assert "agent-bom[all]" in result.output
    assert "MLflow remains separate" in result.output


def test_quickstart_write_sample_creates_first_run_stack(tmp_path):
    sample_dir = tmp_path / "sample"

    result = CliRunner().invoke(main, ["quickstart", "--write-sample", "--sample-dir", str(sample_dir), "--offline"])

    assert result.exit_code == 0
    assert (sample_dir / "inventory.json").exists()
    assert "Wrote " in result.output
    assert f"agent-bom scan --inventory {sample_dir / 'inventory.json'} -p {sample_dir} --offline" in result.output


def test_quickstart_rejects_write_sample_dry_run():
    result = CliRunner().invoke(main, ["quickstart", "--dry-run", "--write-sample"])

    assert result.exit_code != 0
    assert "--dry-run cannot be combined with --write-sample" in result.output


def test_quickstart_rejects_dry_run_with_run():
    result = CliRunner().invoke(main, ["quickstart", "--dry-run", "--run"])

    assert result.exit_code != 0
    assert "--dry-run cannot be combined with --run" in result.output


def test_quickstart_run_scans_with_context_graph_and_seeds_policy(tmp_path, _fake_scan, monkeypatch):
    sample_dir = tmp_path / "stack"
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)

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
    assert "--no-scan" in scan_args
    assert "-o" in scan_args
    assert str(sample_dir / "agent-bom-report.json") in scan_args
    assert str(sample_dir / "inventory.json") in scan_args
    scan_env = _fake_scan.environments[0]
    assert scan_env is not None
    assert scan_env["AGENT_BOM_DB"] == str(Path.home() / ".agent-bom" / "control-plane.db")
    # secure-by-default gateway baseline seeded and valid
    policy_path = sample_dir / "gateway-baseline-policy.json"
    assert policy_path.exists()
    policy = json.loads(policy_path.read_text())
    assert policy["mode"] == "audit"
    assert policy["rules"]
    # handoff printed
    assert "Onboarding complete" in result.output
    assert "/security-graph" in result.output
    # cockpit handoff must pass a flag that actually lets /v1/overview load on loopback
    assert f"{LOCAL_ANALYST_CONTROL_PLANE} --host 127.0.0.1 --port 8422 --allow-insecure-no-auth" in result.output
    assert "--api-key <key>" in result.output
    assert "--from-control-plane http://127.0.0.1:8422" in result.output
    assert "upstreams.yaml" not in result.output
    assert "Run the gateway baseline (audit):" in result.output


def test_quickstart_run_prints_the_configured_control_plane_database(tmp_path, _fake_scan, monkeypatch):
    sample_dir = tmp_path / "stack"
    control_plane_db = tmp_path / "configured-control-plane.db"
    monkeypatch.setenv("AGENT_BOM_DB", str(control_plane_db))

    result = CliRunner().invoke(main, ["quickstart", "--run", "--offline", "--sample-dir", str(sample_dir)])

    assert result.exit_code == 0, result.output
    assert f"agent-bom serve --persist {control_plane_db}" in result.output
    assert "--persist ~/.agent-bom/control-plane.db" not in result.output


def test_quickstart_run_preserves_a_separate_configured_graph_database(tmp_path, _fake_scan, monkeypatch):
    sample_dir = tmp_path / "stack"
    control_plane_db = tmp_path / "control-plane.db"
    graph_db = tmp_path / "graphs.db"
    monkeypatch.setenv("AGENT_BOM_DB", str(control_plane_db))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(graph_db))

    result = CliRunner().invoke(main, ["quickstart", "--run", "--offline", "--sample-dir", str(sample_dir)])

    assert result.exit_code == 0, result.output
    assert _fake_scan.environments[0]["AGENT_BOM_DB"] == str(control_plane_db)
    assert _fake_scan.environments[0]["AGENT_BOM_GRAPH_DB"] == str(graph_db)
    assert f"AGENT_BOM_GRAPH_DB={graph_db}" in result.output
    assert f"agent-bom serve --persist {control_plane_db}" in result.output


def test_quickstart_run_offline_succeeds_with_empty_vulnerability_db(tmp_path, monkeypatch):
    """The advertised offline first run must work before `agent-bom db update`."""
    sample_dir = tmp_path / "stack"
    graph_db = tmp_path / "graph.db"
    wrapper = tmp_path / "agent-bom"
    wrapper.write_text(f"#!{sys.executable}\nfrom agent_bom.cli import main\nmain()\n")
    wrapper.chmod(0o755)

    monkeypatch.setattr("agent_bom.cli._quickstart._resolve_agent_bom", lambda: str(wrapper))
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(tmp_path / "no-profile.toml"))
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "control.db"))
    monkeypatch.setenv("AGENT_BOM_DB_PATH", str(tmp_path / "empty-vulns.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(graph_db))
    monkeypatch.setenv("AGENT_BOM_LOCAL_ANALYTICS_DB", str(tmp_path / "analytics.db"))

    result = CliRunner().invoke(
        main,
        ["quickstart", "--run", "--offline", "--force", "--sample-dir", str(sample_dir)],
    )

    assert result.exit_code == 0, result.output
    report = json.loads((sample_dir / "agent-bom-report.json").read_text())
    assert report["scan_run"]["outcome"] == "complete"
    assert report["scan_run"]["issues"] == []
    assert report["scan_run"]["warning_count"] == 0
    assert report["coverage_warnings"] == []
    assert report["summary"]["total_agents"] > 0
    assert report["summary"]["total_packages"] > 0
    assert report["summary"]["total_vulnerabilities"] == 0
    assert (sample_dir / "gateway-baseline-policy.json").is_file()

    with sqlite3.connect(graph_db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0] > 0
        assert connection.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0] > 0


def test_quickstart_run_no_gateway_policy_skips_file(tmp_path, _fake_scan):
    sample_dir = tmp_path / "stack"

    result = CliRunner().invoke(main, ["quickstart", "--run", "--offline", "--no-gateway-policy", "--sample-dir", str(sample_dir)])

    assert result.exit_code == 0, result.output
    assert not (sample_dir / "gateway-baseline-policy.json").exists()
    assert "Skipped gateway baseline policy" in result.output


def test_quickstart_run_treats_a_critical_verdict_as_completed_evidence(tmp_path, monkeypatch):
    sample_dir = tmp_path / "stack"
    calls: list[list[str]] = []

    def fake_run(args, check=False, **kwargs):  # noqa: ANN001, ANN003
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0 if "--exit-zero" in args else 1)

    monkeypatch.setattr("agent_bom.cli._quickstart._resolve_agent_bom", lambda: "agent-bom")
    monkeypatch.setattr("agent_bom.cli._quickstart.subprocess.run", fake_run)
    monkeypatch.setattr(
        "agent_bom.cli._quickstart._verify_persisted_graph",
        lambda **kwargs: {"scan_id": "fake-scan-id", "nodes": 3, "edges": 2},
    )

    result = CliRunner().invoke(main, ["quickstart", "--run", "--offline", "--sample-dir", str(sample_dir)])

    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    assert "--exit-zero" in calls[0]
    assert (sample_dir / "gateway-baseline-policy.json").is_file()
    assert "Onboarding complete" in result.output


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


def test_quickstart_run_rejects_a_success_exit_without_persisted_graph(tmp_path, monkeypatch):
    sample_dir = tmp_path / "stack"
    graph_db = tmp_path / "missing-graph.db"
    monkeypatch.setenv("AGENT_BOM_DB", str(graph_db))
    monkeypatch.setattr("agent_bom.cli._quickstart._resolve_agent_bom", lambda: "agent-bom")
    monkeypatch.setattr(
        "agent_bom.cli._quickstart.subprocess.run",
        lambda args, check=False, **kwargs: subprocess.CompletedProcess(args, 0),
    )

    result = CliRunner().invoke(main, ["quickstart", "--run", "--offline", "--sample-dir", str(sample_dir)])

    assert result.exit_code != 0
    assert "persisted graph could not be verified" in result.output.lower()
    assert "Onboarding complete" not in result.output


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
