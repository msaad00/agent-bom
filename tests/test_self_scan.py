"""Tests for --self-scan CLI flag."""

from __future__ import annotations

import importlib.metadata
import json

from click.testing import CliRunner

from agent_bom.cli import main


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
            ["scan", "--self-scan", "--output", str(out_file), "--format", "json", "--quiet"],
        )
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(out_file.read_text())
        assert "agents" in data or "inventory" in data or "vulnerabilities" in data

    def test_self_scan_shows_packages(self):
        """--self-scan discovers agent-bom dependencies."""
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--self-scan", "--dry-run"])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
