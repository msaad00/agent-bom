"""Artifact platforms and workspace declarations must not invent package versions."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.parsers.python_parsers import parse_pip_packages
from agent_bom.parsers.ruby_parsers import parse_gemfile_lock
from agent_bom.parsers.uv_workspace import uv_lock_owner
from agent_bom.scanners import state as scanner_state


@pytest.fixture(autouse=True)
def _isolate_coverage():
    scanner_state.consume_coverage_warnings()
    yield
    scanner_state.consume_coverage_warnings()


@pytest.mark.parametrize("platform", ["x86_64-linux-gnu", "x86_64-linux-musl", "arm64-darwin", "x64-mingw-ucrt"])
def test_ruby_artifact_platform_is_not_gem_version(platform):
    raw = f"1.19.0-{platform}"
    package = Package("nokogiri", raw, "rubygems", purl=f"pkg:gem/nokogiri@{raw}")
    assert package.version == "1.19.0"
    assert package.purl == "pkg:gem/nokogiri@1.19.0"
    assert any(item.get("raw_version") == raw and item.get("platform") == platform for item in package.version_evidence)


@pytest.mark.parametrize("version", ["1.19.0-rc1", "1.19.0.pre.1", "1.19.0-custom-linux", "1.19.0"])
def test_ruby_prerelease_and_unknown_suffix_are_preserved(version):
    assert Package("nokogiri", version, "rubygems").version == version


def test_non_ruby_platform_suffix_is_not_normalized():
    assert Package("example", "1.19.0-arm64-darwin", "npm").version == "1.19.0-arm64-darwin"


def test_uv_workspace_member_uses_shared_lock_versions(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.uv.workspace]\nmembers = ["packages/*"]\n')
    member = tmp_path / "packages" / "app"
    member.mkdir(parents=True)
    (member / "pyproject.toml").write_text('[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["httpx>=0.20"]\n')
    (tmp_path / "uv.lock").write_text("""version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "packages/app" }
dependencies = [{name = "httpx"}]
[[package]]
name = "httpx"
version = "0.24.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [{name = "httpcore"}]
[[package]]
name = "httpcore"
version = "0.17.3"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "unrelated"
version = "9.9.9"
source = { registry = "https://pypi.org/simple" }
""")
    packages = parse_pip_packages(member)
    assert {(p.name, p.version) for p in packages} == {("httpx", "0.24.1"), ("httpcore", "0.17.3")}
    assert all(p.reachability_evidence == "lockfile" and not p.resolved_from_registry for p in packages)


def test_invalid_uv_lock_does_not_fall_back_to_registry_declarations(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "app"\ndependencies = ["httpx>=0.20"]\n')
    (tmp_path / "uv.lock").write_text("[[package]\n")
    assert parse_pip_packages(tmp_path) == []
    assert scanner_state.consume_coverage_warnings()


@pytest.mark.parametrize(
    "location,owned", [("packages/app", True), ("packages/excluded", False), ("packages/nested/app", False), ("unrelated", False)]
)
def test_uv_workspace_membership_and_exclusions(tmp_path, location, owned):
    (tmp_path / "pyproject.toml").write_text('[tool.uv.workspace]\nmembers = ["packages/*"]\nexclude = ["packages/excluded"]\n')
    member = tmp_path / location
    member.mkdir(parents=True)
    assert uv_lock_owner(member) == (tmp_path.resolve() if owned else None)


def test_nested_lock_takes_precedence_over_parent_workspace(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.uv.workspace]\nmembers = ["packages/*"]\n')
    member = tmp_path / "packages" / "app"
    member.mkdir(parents=True)
    (member / "uv.lock").write_text("version = 1\n")
    assert uv_lock_owner(member) == member.resolve()


def test_uv_workspace_repeated_recursive_globs_remain_bounded(tmp_path):
    pattern = "**/" * 600 + "app"
    (tmp_path / "pyproject.toml").write_text(f'[tool.uv.workspace]\nmembers = ["{pattern}"]\n')
    member = tmp_path / "packages" / "app"
    member.mkdir(parents=True)
    assert uv_lock_owner(member) == tmp_path.resolve()


def test_missing_workspace_lock_is_incomplete_without_floating_fallback(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "app"\ndependencies = ["httpx>=0.20"]\n[tool.uv.workspace]\nmembers = []\n')
    assert parse_pip_packages(tmp_path) == []
    assert scanner_state.consume_coverage_warnings()


def test_empty_uv_lock_missing_declared_dependency_is_incomplete(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "app"\ndependencies = ["httpx>=0.20"]\n')
    (tmp_path / "uv.lock").write_text("version = 1\n")
    assert parse_pip_packages(tmp_path) == []
    assert scanner_state.consume_coverage_warnings()


def test_gem_lock_abi_variant_is_deduplicated_with_platform_evidence(tmp_path):
    (tmp_path / "Gemfile.lock").write_text(
        "GEM\n  specs:\n    nokogiri (1.19.0-x86_64-linux-gnu)\n    nokogiri (1.19.0-arm64-darwin)\n"
        "\nPLATFORMS\n  x86_64-linux\n  arm64-darwin\n"
    )
    packages = parse_gemfile_lock(tmp_path)
    assert len(packages) == 1
    assert packages[0].version == "1.19.0"
    assert {item["platform"] for item in packages[0].version_evidence} == {"x86_64-linux-gnu", "arm64-darwin"}


def test_ruby_prerelease_platform_and_purl_qualifiers_are_preserved():
    package = Package("nokogiri", "1.19.0-rc1-arm64-darwin", "gem", purl="pkg:gem/nokogiri@1.19.0-rc1-arm64-darwin?arch=arm64")
    assert package.version == "1.19.0-rc1"
    assert package.purl == "pkg:gem/nokogiri@1.19.0-rc1?arch=arm64"


@pytest.fixture
def ruby_advisory(monkeypatch):
    async def scan(packages, **kwargs):
        assert packages[0].version == "1.19.0"
        packages[0].vulnerabilities = [Vulnerability("CVE-2026-1234", "Regression fixture", Severity.HIGH)]

    monkeypatch.setattr("agent_bom.scanners.scan_packages", scan)


def test_cli_check_uses_canonical_gem_version_in_verdict(ruby_advisory):
    from agent_bom.cli import main

    result = CliRunner().invoke(main, ["check", "nokogiri@1.19.0-x86_64-linux-gnu", "--ecosystem", "rubygems", "--format", "json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["version"] == "1.19.0"
    assert payload["package_canonical_id"] == Package("nokogiri", "1.19.0", "rubygems").canonical_id


@pytest.mark.asyncio
async def test_mcp_check_uses_canonical_gem_version_in_verdict(ruby_advisory):
    from agent_bom.mcp_tools.scanning import check_impl

    result = await check_impl(
        package="nokogiri",
        version="1.19.0-arm64-darwin",
        ecosystem="rubygems",
        _validate_ecosystem=lambda value: value,
        _truncate_response=lambda value: value,
    )
    payload = json.loads(result)
    assert payload["version"] == "1.19.0"
    assert payload["package_canonical_id"] == Package("nokogiri", "1.19.0", "rubygems").canonical_id


def test_data_model_atlas_runs_without_installed_runtime_dependencies():
    script = Path(__file__).resolve().parents[1] / "scripts" / "regenerate_data_model_atlas.py"
    result = subprocess.run([sys.executable, "-I", "-S", str(script), "--check"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
