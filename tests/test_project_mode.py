"""Tests for --project directory scanner and --sbom-name attribution."""

from __future__ import annotations

import json

import pytest

from agent_bom.parsers import scan_project_directory
from agent_bom.sbom import detect_sbom_resource_name, load_sbom

# ── scan_project_directory ────────────────────────────────────────────────────


class TestScanProjectDirectory:
    def test_finds_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        result = scan_project_directory(tmp_path)
        assert tmp_path in result
        names = {p.name for p in result[tmp_path]}
        assert "requests" in names

    def test_finds_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"name": "myapp", "version": "1.0.0", "dependencies": {"lodash": "4.17.21"}}))
        result = scan_project_directory(tmp_path)
        assert tmp_path in result
        names = {p.name for p in result[tmp_path]}
        assert "lodash" in names

    def test_finds_go_sum(self, tmp_path):
        # parse_go_packages reads go.sum (go.mod triggers directory detection)
        (tmp_path / "go.mod").write_text("module example.com/myapp\n\ngo 1.21\n")
        (tmp_path / "go.sum").write_text(
            "github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=\n"
            "github.com/gin-gonic/gin v1.9.1/go.mod h1:hPys/inP3MwrfBnNErQn7CXHq/XCfBFpkAiQCDPF9GE=\n"
        )
        result = scan_project_directory(tmp_path)
        assert tmp_path in result
        names = {p.name for p in result[tmp_path]}
        assert "github.com/gin-gonic/gin" in names

    def test_finds_cargo_lock(self, tmp_path):
        # parse_cargo_packages reads Cargo.lock (Cargo.toml triggers detection)
        (tmp_path / "Cargo.toml").write_text('[package]\nname = "myapp"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0"\n')
        (tmp_path / "Cargo.lock").write_text(
            '[[package]]\nname = "serde"\nversion = "1.0.193"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )
        result = scan_project_directory(tmp_path)
        assert tmp_path in result
        names = {p.name for p in result[tmp_path]}
        assert "serde" in names

    def test_recursive_subdirectory(self, tmp_path):
        subdir = tmp_path / "backend"
        subdir.mkdir()
        (subdir / "requirements.txt").write_text("flask==3.0.0\n")
        result = scan_project_directory(tmp_path)
        assert subdir in result
        names = {p.name for p in result[subdir]}
        assert "flask" in names

    def test_skips_node_modules(self, tmp_path):
        node_modules = tmp_path / "node_modules"
        node_modules.mkdir()
        (node_modules / "package.json").write_text(json.dumps({"name": "internal", "version": "1.0.0"}))
        result = scan_project_directory(tmp_path)
        assert node_modules not in result

    def test_skips_venv(self, tmp_path):
        venv = tmp_path / ".venv"
        venv.mkdir()
        (venv / "requirements.txt").write_text("pip==23.0\n")
        result = scan_project_directory(tmp_path)
        assert venv not in result

    def test_empty_directory_returns_empty(self, tmp_path):
        result = scan_project_directory(tmp_path)
        assert result == {}

    def test_deduplicates_within_directory(self, tmp_path):
        # Both package.json and package-lock.json may yield the same package
        (tmp_path / "package.json").write_text(json.dumps({"name": "myapp", "version": "1.0.0", "dependencies": {"lodash": "4.17.21"}}))
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "name": "myapp",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "myapp", "version": "1.0.0"},
                        "node_modules/lodash": {"version": "4.17.21", "resolved": "https://r.npmjs.org/lodash"},
                    },
                }
            )
        )
        result = scan_project_directory(tmp_path)
        lodash_entries = [p for p in result.get(tmp_path, []) if p.name == "lodash"]
        assert len(lodash_entries) == 1

    def test_monorepo_multiple_manifests(self, tmp_path):
        frontend = tmp_path / "frontend"
        frontend.mkdir()
        backend = tmp_path / "backend"
        backend.mkdir()
        (frontend / "package.json").write_text(json.dumps({"name": "frontend", "version": "1.0.0", "dependencies": {"react": "18.2.0"}}))
        (backend / "requirements.txt").write_text("django==4.2.0\n")
        result = scan_project_directory(tmp_path)
        assert frontend in result
        assert backend in result
        assert any(p.name == "react" for p in result[frontend])
        assert any(p.name == "django" for p in result[backend])

    def test_max_depth_respected(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "d" / "e" / "f"
        deep.mkdir(parents=True)
        (deep / "requirements.txt").write_text("requests==2.31.0\n")
        # Default max_depth=5 should not reach depth 6
        result = scan_project_directory(tmp_path, max_depth=5)
        assert deep not in result

    def test_max_depth_custom(self, tmp_path):
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "requirements.txt").write_text("flask==3.0.0\n")
        result = scan_project_directory(tmp_path, max_depth=2)
        assert nested in result


# ── detect_sbom_resource_name ─────────────────────────────────────────────────


CYCLONEDX_WITH_NAME = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {
        "component": {"type": "application", "name": "nginx:1.25", "version": "1.25"},
    },
    "components": [],
}

CYCLONEDX_WITHOUT_NAME = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {},
    "components": [],
}

SPDX2_WITH_NAME = {
    "spdxVersion": "SPDX-2.3",
    "name": "prod-api-01",
    "packages": [],
}

SPDX2_DOCUMENT_PREFIX = {
    "spdxVersion": "SPDX-2.3",
    "name": "DOCUMENT-myservice",
    "packages": [],
}


class TestDetectSbomResourceName:
    def test_cyclonedx_metadata_component_name(self):
        assert detect_sbom_resource_name(CYCLONEDX_WITH_NAME) == "nginx:1.25"

    def test_cyclonedx_missing_name_returns_none(self):
        assert detect_sbom_resource_name(CYCLONEDX_WITHOUT_NAME) is None

    def test_spdx2_name_field(self):
        assert detect_sbom_resource_name(SPDX2_WITH_NAME) == "prod-api-01"

    def test_spdx2_strips_document_prefix(self):
        assert detect_sbom_resource_name(SPDX2_DOCUMENT_PREFIX) == "myservice"

    def test_empty_dict_returns_none(self):
        assert detect_sbom_resource_name({}) is None


# ── load_sbom returns 3-tuple ─────────────────────────────────────────────────


class TestLoadSbomTuple:
    def test_cyclonedx_returns_resource_name(self, tmp_path):
        sbom = tmp_path / "sbom.json"
        sbom.write_text(json.dumps(CYCLONEDX_WITH_NAME))
        pkgs, fmt, name = load_sbom(str(sbom))
        assert fmt == "cyclonedx"
        assert name == "nginx:1.25"

    def test_cyclonedx_no_name_returns_none(self, tmp_path):
        sbom = tmp_path / "sbom.json"
        sbom.write_text(json.dumps(CYCLONEDX_WITHOUT_NAME))
        pkgs, fmt, name = load_sbom(str(sbom))
        assert fmt == "cyclonedx"
        assert name is None

    def test_spdx2_returns_resource_name(self, tmp_path):
        sbom = tmp_path / "sbom.json"
        sbom.write_text(json.dumps(SPDX2_WITH_NAME))
        pkgs, fmt, name = load_sbom(str(sbom))
        assert fmt == "spdx-2"
        assert name == "prod-api-01"

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_sbom(str(tmp_path / "nonexistent.json"))

    def test_invalid_format_raises(self, tmp_path):
        sbom = tmp_path / "sbom.json"
        sbom.write_text(json.dumps({"foo": "bar"}))
        with pytest.raises(ValueError, match="Unrecognised"):
            load_sbom(str(sbom))


# ── CLI integration: --project and --sbom-name ────────────────────────────────


def test_cli_has_sbom_name_flag():
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "--project" in result.output
    assert "--sbom-name" in result.output


def test_project_scan_via_cli_no_agents(tmp_path):
    """--project DIR with no MCP configs triggers package manifest scan."""
    from unittest.mock import patch

    from click.testing import CliRunner

    from agent_bom.cli import main

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    runner = CliRunner()
    # Patch discover_all at the cli module level (imported at top of cli.py)
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = runner.invoke(main, ["scan", "--project", str(tmp_path), "--no-scan"])
    assert result.exit_code == 0
    assert "No MCP configurations" not in result.output
    # Should find the package manifest and show it
    assert "project" in result.output.lower() or "package" in result.output.lower()


def test_sbom_name_overrides_metadata(tmp_path):
    """--sbom-name takes precedence over auto-detected name."""
    from unittest.mock import AsyncMock, patch

    from click.testing import CliRunner

    from agent_bom.cli import main

    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(CYCLONEDX_WITH_NAME))

    runner = CliRunner()
    with patch("agent_bom.scanners.query_osv_batch", new_callable=AsyncMock) as mock_osv:
        mock_osv.return_value = {}
        result = runner.invoke(
            main,
            ["scan", "--sbom", str(sbom), "--sbom-name", "my-custom-name", "--no-scan"],
        )
    assert result.exit_code == 0
    assert "my-custom-name" in result.output


def test_sbom_auto_detects_name(tmp_path):
    """Auto-detect resource name from CycloneDX metadata.component.name."""
    from unittest.mock import AsyncMock, patch

    from click.testing import CliRunner

    from agent_bom.cli import main

    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(CYCLONEDX_WITH_NAME))

    runner = CliRunner()
    with patch("agent_bom.scanners.query_osv_batch", new_callable=AsyncMock) as mock_osv:
        mock_osv.return_value = {}
        result = runner.invoke(main, ["scan", "--sbom", str(sbom), "--no-scan"])
    assert result.exit_code == 0
    assert "nginx:1.25" in result.output
