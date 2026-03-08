"""Tests for poetry.lock, uv.lock, conda environment.yml, and pnpm-lock.yaml parsers."""

from __future__ import annotations

import textwrap

from agent_bom.parsers import (
    parse_conda_environment,
    parse_pip_packages,
    parse_pnpm_lock,
    parse_poetry_lock,
    parse_uv_lock,
)

# ── poetry.lock ──────────────────────────────────────────────────────────────

POETRY_LOCK = textwrap.dedent("""\
    [[package]]
    name = "requests"
    version = "2.31.0"
    description = "Python HTTP for Humans."
    category = "main"
    optional = false
    python-versions = ">=3.7"

    [[package]]
    name = "pytest"
    version = "7.4.0"
    description = "pytest: simple powerful testing with Python"
    category = "dev"
    optional = false
    python-versions = ">=3.7"

    [[package]]
    name = "flask"
    version = "3.0.0"
    description = "A simple framework for building complex web applications."
    category = "main"
    optional = false
    python-versions = ">=3.8"
""")


class TestPoetryLock:
    def test_parses_main_packages(self, tmp_path):
        (tmp_path / "poetry.lock").write_text(POETRY_LOCK)
        pkgs = parse_poetry_lock(tmp_path)
        names = {p.name for p in pkgs}
        assert "requests" in names
        assert "flask" in names
        assert "pytest" in names

    def test_direct_flag_main_only(self, tmp_path):
        (tmp_path / "poetry.lock").write_text(POETRY_LOCK)
        pkgs = parse_poetry_lock(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["requests"].is_direct is True
        assert by_name["flask"].is_direct is True
        assert by_name["pytest"].is_direct is False  # dev category

    def test_versions_correct(self, tmp_path):
        (tmp_path / "poetry.lock").write_text(POETRY_LOCK)
        pkgs = parse_poetry_lock(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["requests"].version == "2.31.0"
        assert by_name["flask"].version == "3.0.0"

    def test_ecosystem_is_pypi(self, tmp_path):
        (tmp_path / "poetry.lock").write_text(POETRY_LOCK)
        pkgs = parse_poetry_lock(tmp_path)
        assert all(p.ecosystem == "pypi" for p in pkgs)

    def test_purl_format(self, tmp_path):
        (tmp_path / "poetry.lock").write_text(POETRY_LOCK)
        pkgs = parse_poetry_lock(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["requests"].purl == "pkg:pypi/requests@2.31.0"

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_poetry_lock(tmp_path) == []

    def test_integrated_via_parse_pip_packages(self, tmp_path):
        """parse_pip_packages() should prefer poetry.lock over requirements.txt."""
        (tmp_path / "poetry.lock").write_text(POETRY_LOCK)
        (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")
        pkgs = parse_pip_packages(tmp_path)
        by_name = {p.name: p for p in pkgs}
        # poetry.lock wins — version from poetry, not requirements.txt
        assert by_name["requests"].version == "2.31.0"


# ── uv.lock ──────────────────────────────────────────────────────────────────

UV_LOCK = textwrap.dedent("""\
    version = 1
    requires-python = ">=3.11"

    [[package]]
    name = "httpx"
    version = "0.27.0"
    source = { registry = "https://pypi.org/simple" }

    [[package]]
    name = "certifi"
    version = "2024.2.2"
    source = { registry = "https://pypi.org/simple" }

    [[package]]
    name = "anyio"
    version = "4.3.0"
    source = { registry = "https://pypi.org/simple" }
""")

PYPROJECT_WITH_DEPS = textwrap.dedent("""\
    [project]
    name = "myapp"
    version = "0.1.0"
    dependencies = ["httpx>=0.27"]
""")


class TestUvLock:
    def test_parses_all_packages(self, tmp_path):
        (tmp_path / "uv.lock").write_text(UV_LOCK)
        pkgs = parse_uv_lock(tmp_path)
        names = {p.name for p in pkgs}
        assert {"httpx", "certifi", "anyio"} == names

    def test_versions_correct(self, tmp_path):
        (tmp_path / "uv.lock").write_text(UV_LOCK)
        pkgs = parse_uv_lock(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["httpx"].version == "0.27.0"
        assert by_name["certifi"].version == "2024.2.2"

    def test_direct_flag_from_pyproject(self, tmp_path):
        (tmp_path / "uv.lock").write_text(UV_LOCK)
        (tmp_path / "pyproject.toml").write_text(PYPROJECT_WITH_DEPS)
        pkgs = parse_uv_lock(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["httpx"].is_direct is True
        assert by_name["certifi"].is_direct is False  # transitive

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_uv_lock(tmp_path) == []

    def test_ecosystem_is_pypi(self, tmp_path):
        (tmp_path / "uv.lock").write_text(UV_LOCK)
        pkgs = parse_uv_lock(tmp_path)
        assert all(p.ecosystem == "pypi" for p in pkgs)

    def test_integrated_via_parse_pip_packages(self, tmp_path):
        """parse_pip_packages() should use uv.lock when no poetry.lock exists."""
        (tmp_path / "uv.lock").write_text(UV_LOCK)
        (tmp_path / "requirements.txt").write_text("httpx==0.26.0\n")
        pkgs = parse_pip_packages(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["httpx"].version == "0.27.0"  # uv.lock wins


# ── conda environment.yml ─────────────────────────────────────────────────────

CONDA_ENV = textwrap.dedent("""\
    name: myenv
    channels:
      - conda-forge
      - defaults
    dependencies:
      - python=3.11.0
      - numpy=1.26.4
      - pandas=2.2.0
      - pip:
        - requests==2.31.0
        - flask>=3.0.0,<4.0.0
""")


class TestCondaEnvironment:
    def test_parses_conda_packages(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV)
        pkgs = parse_conda_environment(tmp_path)
        names = {p.name for p in pkgs}
        assert "numpy" in names
        assert "pandas" in names
        assert "python" in names

    def test_parses_pip_sub_list(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV)
        pkgs = parse_conda_environment(tmp_path)
        names = {p.name for p in pkgs}
        assert "requests" in names

    def test_conda_ecosystem_label(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV)
        pkgs = parse_conda_environment(tmp_path)
        conda_pkgs = [p for p in pkgs if p.ecosystem == "conda"]
        assert len(conda_pkgs) >= 2  # numpy, pandas, python

    def test_pip_packages_have_pypi_ecosystem(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV)
        pkgs = parse_conda_environment(tmp_path)
        pip_pkgs = [p for p in pkgs if p.name == "requests"]
        assert pip_pkgs[0].ecosystem == "pypi"

    def test_versions_correct(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV)
        pkgs = parse_conda_environment(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["numpy"].version == "1.26.4"
        assert by_name["requests"].version == "2.31.0"

    def test_environment_yaml_also_supported(self, tmp_path):
        (tmp_path / "environment.yaml").write_text(CONDA_ENV)
        pkgs = parse_conda_environment(tmp_path)
        assert len(pkgs) > 0

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_conda_environment(tmp_path) == []

    def test_skips_unpinned_conda_packages(self, tmp_path):
        (tmp_path / "environment.yml").write_text("name: test\ndependencies:\n  - numpy\n")
        pkgs = parse_conda_environment(tmp_path)
        # Unpinned packages (no version) are skipped
        assert all(p.version != "unknown" or p.name != "numpy" for p in pkgs)


# ── pnpm-lock.yaml ────────────────────────────────────────────────────────────

PNPM_LOCK_V6 = textwrap.dedent("""\
    lockfileVersion: '6.0'

    packages:

      /lodash@4.17.21:
        resolution: {integrity: sha512-xxx}

      /express@4.18.2:
        resolution: {integrity: sha512-yyy}

      /@types/node@20.0.0:
        resolution: {integrity: sha512-zzz}
        dev: true
""")

PNPM_LOCK_V9 = textwrap.dedent("""\
    lockfileVersion: '9.0'

    packages:
      lodash@4.17.21:
        resolution: {integrity: sha512-xxx}

      express@4.18.2:
        resolution: {integrity: sha512-yyy}
""")


class TestPnpmLock:
    def test_parses_v6_format(self, tmp_path):
        (tmp_path / "pnpm-lock.yaml").write_text(PNPM_LOCK_V6)
        pkgs = parse_pnpm_lock(tmp_path)
        names = {p.name for p in pkgs}
        assert "lodash" in names
        assert "express" in names

    def test_parses_v9_format(self, tmp_path):
        (tmp_path / "pnpm-lock.yaml").write_text(PNPM_LOCK_V9)
        pkgs = parse_pnpm_lock(tmp_path)
        names = {p.name for p in pkgs}
        assert "lodash" in names
        assert "express" in names

    def test_scoped_package(self, tmp_path):
        (tmp_path / "pnpm-lock.yaml").write_text(PNPM_LOCK_V6)
        pkgs = parse_pnpm_lock(tmp_path)
        names = {p.name for p in pkgs}
        assert "@types/node" in names

    def test_versions_correct(self, tmp_path):
        (tmp_path / "pnpm-lock.yaml").write_text(PNPM_LOCK_V6)
        pkgs = parse_pnpm_lock(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["lodash"].version == "4.17.21"
        assert by_name["express"].version == "4.18.2"

    def test_ecosystem_is_npm(self, tmp_path):
        (tmp_path / "pnpm-lock.yaml").write_text(PNPM_LOCK_V6)
        pkgs = parse_pnpm_lock(tmp_path)
        assert all(p.ecosystem == "npm" for p in pkgs)

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_pnpm_lock(tmp_path) == []


# ── ECOSYSTEM_MAP includes conda ──────────────────────────────────────────────


def test_conda_in_ecosystem_map():
    from agent_bom.scanners import ECOSYSTEM_MAP

    assert "conda" in ECOSYSTEM_MAP
    # conda maps to PyPI in OSV (conda packages are pip-installable)
    assert ECOSYSTEM_MAP["conda"] == "PyPI"
