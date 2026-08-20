"""Manifest parser failures become structured coverage gaps, never false-clean scans."""

from __future__ import annotations

import builtins
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from agent_bom.parsers.beam_parsers import parse_hex_packages, parse_pub_packages
from agent_bom.parsers.compiled_parsers import (
    parse_cargo_packages,
    parse_conda_packages,
    parse_go_packages,
    parse_go_workspace,
    parse_gradle_packages,
    parse_maven_packages,
)
from agent_bom.parsers.dotnet_parsers import parse_nuget_packages
from agent_bom.parsers.node_parsers import parse_bun_packages, parse_pnpm_lock, parse_yarn_lock
from agent_bom.parsers.php_parsers import parse_composer_lock, parse_php_packages
from agent_bom.parsers.python_parsers import parse_conda_environment, parse_pip_compile_inputs, parse_pip_packages
from agent_bom.parsers.ruby_parsers import parse_gemfile_lock, parse_ruby_packages
from agent_bom.parsers.swift_parsers import parse_package_resolved
from agent_bom.scanners import state as scanner_state

Parser = Callable[[Path], list]


@pytest.fixture(autouse=True)
def _reset_coverage_warnings():
    scanner_state.consume_coverage_warnings()
    yield
    scanner_state.consume_coverage_warnings()


def _go_packages(directory: Path) -> list:
    return parse_go_packages(directory, verify_checksums=False)


_READ_FAILURE_CASES: list[tuple[str, str, Parser]] = [
    ("yarn.lock", "npm", parse_yarn_lock),
    ("pnpm-lock.yaml", "npm", parse_pnpm_lock),
    ("bun.lock", "npm", parse_bun_packages),
    ("requirements.txt", "pypi", parse_pip_packages),
    ("Pipfile.lock", "pypi", parse_pip_packages),
    ("requirements.in", "pypi", parse_pip_compile_inputs),
    ("constraints.txt", "pypi", parse_pip_compile_inputs),
    ("environment.yml", "conda", parse_conda_environment),
    ("environment.yaml", "conda", parse_conda_packages),
    ("mix.lock", "hex", parse_hex_packages),
    ("pubspec.lock", "pub", parse_pub_packages),
    ("packages.lock.json", "nuget", parse_nuget_packages),
    ("Sample.csproj", "nuget", parse_nuget_packages),
    ("composer.lock", "composer", parse_composer_lock),
    ("composer.json", "composer", parse_php_packages),
    ("Gemfile.lock", "rubygems", parse_gemfile_lock),
    ("Gemfile", "rubygems", parse_ruby_packages),
    ("Package.resolved", "swift", parse_package_resolved),
    ("go.work", "go", parse_go_workspace),
    ("go.mod", "go", _go_packages),
    ("go.sum", "go", _go_packages),
    ("pom.xml", "maven", parse_maven_packages),
    ("Cargo.lock", "cargo", parse_cargo_packages),
    ("Cargo.toml", "cargo", parse_cargo_packages),
    ("gradle/libs.versions.toml", "maven", parse_gradle_packages),
    ("gradle.lockfile", "maven", parse_gradle_packages),
    ("build.gradle", "maven", parse_gradle_packages),
    ("build.gradle.kts", "maven", parse_gradle_packages),
    ("conda-lock.yml", "conda", parse_conda_packages),
]


@pytest.mark.parametrize(("relative_path", "ecosystem", "parser"), _READ_FAILURE_CASES)
def test_manifest_read_failure_records_named_coverage_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    ecosystem: str,
    parser: Parser,
) -> None:
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("placeholder", encoding="utf-8")

    original_path_open = Path.open
    original_builtin_open = builtins.open

    def denied_path_open(self: Path, *args, **kwargs):
        if self == target:
            raise OSError("simulated unreadable manifest")
        return original_path_open(self, *args, **kwargs)

    def denied_builtin_open(file, *args, **kwargs):
        if Path(file) == target:
            raise OSError("simulated unreadable manifest")
        return original_builtin_open(file, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied_path_open)
    monkeypatch.setattr(builtins, "open", denied_builtin_open)

    assert parser(tmp_path) == []
    warnings = scanner_state.consume_coverage_warnings()
    assert len(warnings) == 1, warnings
    assert warnings[0]["reason"] == "manifest_parse_error"
    assert warnings[0]["ecosystem"] == ecosystem
    assert target.name in warnings[0]["release"]
    assert "simulated unreadable manifest" not in warnings[0]["detail"]


def _scan_dir_to_json(directory: Path, output: Path) -> dict:
    from click.testing import CliRunner

    from agent_bom.cli import main

    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(directory),
            "--offline",
            "--no-auto-update-db",
            "--no-scan",
            "--format",
            "json",
            "--output",
            str(output),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.output
    assert output.exists(), result.output
    return json.loads(output.read_text(encoding="utf-8"))


def test_non_npm_manifest_warning_reaches_partial_scan_artifact(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "composer.lock").write_text("{not-json", encoding="utf-8")

    payload = _scan_dir_to_json(project, tmp_path / "report.json")

    parse_errors = [warning for warning in payload["coverage_warnings"] if warning["reason"] == "manifest_parse_error"]
    assert any(warning["ecosystem"] == "composer" for warning in parse_errors), parse_errors
    assert payload["scan_run"]["outcome"] == "partial"


def test_empty_project_does_not_invent_manifest_coverage_gaps(tmp_path: Path) -> None:
    assert parse_php_packages(tmp_path) == []
    assert parse_go_packages(tmp_path, verify_checksums=False) == []
    assert parse_gradle_packages(tmp_path) == []
    assert scanner_state.consume_coverage_warnings() == []


@pytest.mark.parametrize(
    ("relative_path", "ecosystem", "parser", "content", "expected_names"),
    [
        pytest.param(
            "Gemfile.lock",
            "rubygems",
            parse_gemfile_lock,
            """GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.3)
    truncated (

PLATFORMS
  ruby
""",
            {"rails"},
            id="gemfile-lock",
        ),
        pytest.param(
            "go.sum",
            "go",
            _go_packages,
            "example.com/valid v1.2.3 h1:YWJjZA==\nexample.com/nohash v9.9.9\n",
            {"example.com/valid"},
            id="go-sum",
        ),
        pytest.param(
            "requirements.txt",
            "pypi",
            parse_pip_packages,
            "requests==2.31.0\nflask==\n@@@broken\n",
            {"requests"},
            id="requirements",
        ),
    ],
)
def test_malformed_line_oriented_manifest_is_partial_not_silently_clean(
    tmp_path: Path,
    relative_path: str,
    ecosystem: str,
    parser: Parser,
    content: str,
    expected_names: set[str],
) -> None:
    target = tmp_path / relative_path
    target.write_text(content, encoding="utf-8")

    packages = parser(tmp_path)

    assert {package.name for package in packages} == expected_names
    warnings = scanner_state.consume_coverage_warnings()
    assert len(warnings) == 1, warnings
    assert warnings[0]["reason"] == "manifest_parse_error"
    assert warnings[0]["ecosystem"] == ecosystem
    assert target.name in warnings[0]["release"]
    assert "partial" in warnings[0]["detail"].lower()


def test_malformed_line_oriented_warning_reaches_partial_scan_artifact(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\nflask==\n", encoding="utf-8")

    payload = _scan_dir_to_json(project, tmp_path / "report.json")

    parse_errors = [warning for warning in payload["coverage_warnings"] if warning["reason"] == "manifest_parse_error"]
    assert any(warning["ecosystem"] == "pypi" for warning in parse_errors), parse_errors
    assert payload["scan_run"]["outcome"] == "partial"
