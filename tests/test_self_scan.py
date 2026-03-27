"""Tests for --self-scan CLI flag."""

from __future__ import annotations

import importlib.metadata
import json
from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli.agents import _build_self_scan_inventory


class TestSelfScanInventory:
    """Unit tests for self-scan inventory generation logic."""

    def test_self_scan_builds_inventory(self):
        """--self-scan produces a valid inventory with agent-bom's own deps."""
        dist = importlib.metadata.distribution("agent-bom")
        requires = dist.requires or []
        assert len(requires) > 0, "agent-bom should have dependencies"

    def test_self_scan_parses_requirement_names(self):
        """Requirement strings are parsed to clean package names."""
        dist = importlib.metadata.distribution("agent-bom")
        requires = dist.requires or []
        for req_str in requires[:5]:
            name = req_str.split(";")[0].split("[")[0].strip()
            for op in (">=", "<=", "==", "!=", "~=", ">", "<"):
                if op in name:
                    name = name[: name.index(op)].strip()
                    break
            assert name, f"Failed to parse name from: {req_str}"
            assert " " not in name

    def test_self_scan_resolves_installed_versions(self):
        """At least some deps should be installed and have versions."""
        dist = importlib.metadata.distribution("agent-bom")
        requires = dist.requires or []
        resolved = 0
        for req_str in requires:
            name = req_str.split(";")[0].split("[")[0].strip()
            for op in (">=", "<=", "==", "!=", "~=", ">", "<"):
                if op in name:
                    name = name[: name.index(op)].strip()
                    break
            if not name:
                continue
            try:
                importlib.metadata.version(name)
                resolved += 1
            except importlib.metadata.PackageNotFoundError:
                pass
        assert resolved >= 5, f"Expected >=5 resolved deps, got {resolved}"

    def test_self_scan_inventory_deduplicates_and_hides_local_paths(self):
        """Self-scan inventory should not duplicate packages or leak temp paths."""

        class _FakeDist:
            requires = [
                "agent-bom>=0.75.9",
                "Agent-Bom>=0.75.9",
                "requests>=2.33.0",
                "requests>=2.33.0",
            ]

        def _fake_version(name: str) -> str:
            versions = {"agent-bom": "0.75.9", "Agent-Bom": "0.75.9", "requests": "2.33.0"}
            return versions[name]

        with (
            patch("importlib.metadata.distribution", return_value=_FakeDist()),
            patch("importlib.metadata.version", side_effect=_fake_version),
        ):
            inventory = _build_self_scan_inventory()

        agent = inventory["agents"][0]
        packages = agent["mcp_servers"][0]["packages"]
        assert agent["config_path"] == "self-scan://agent-bom"
        assert packages == [
            {"name": "agent-bom", "version": "0.75.9", "ecosystem": "pypi"},
            {"name": "requests", "version": "2.33.0", "ecosystem": "pypi"},
        ]


class TestSelfScanCLI:
    """Integration tests for --self-scan via CLI runner."""

    def test_self_scan_flag_runs(self):
        """--self-scan executes without crashing."""
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--self-scan", "--no-scan", "--quiet"])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"

    def test_self_scan_with_json_output(self, tmp_path):
        """--self-scan with JSON output produces valid report."""
        out_file = tmp_path / "self-scan.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--self-scan", "--no-scan", "--output", str(out_file), "--format", "json", "--quiet"],
        )
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(out_file.read_text())
        assert "agents" in data or "inventory" in data or "vulnerabilities" in data

    def test_self_scan_shows_packages(self):
        """--self-scan discovers agent-bom dependencies."""
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--self-scan", "--dry-run"])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"

    def test_self_scan_graph_export_is_not_empty(self, tmp_path):
        """self-scan JSON should remain compatible with graph export."""
        report = tmp_path / "self-scan.json"
        runner = CliRunner()

        scan_result = runner.invoke(
            main,
            ["scan", "--self-scan", "--no-scan", "--output", str(report), "--format", "json", "--quiet"],
        )
        assert scan_result.exit_code == 0, f"Exit {scan_result.exit_code}: {scan_result.output}"

        graph_result = runner.invoke(main, ["graph", str(report), "--format", "json"])
        assert graph_result.exit_code == 0, f"Exit {graph_result.exit_code}: {graph_result.output}"
        data = json.loads(graph_result.output)
        assert data["stats"]["node_count"] > 0
        assert data["stats"]["edge_count"] > 0
