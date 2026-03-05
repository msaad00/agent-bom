"""Tests for pre-install guard module."""

from agent_bom.guard import (
    GuardResult,
    _extract_npm_packages,
    _extract_pip_packages,
)


class TestExtractPipPackages:
    def test_basic_install(self):
        assert _extract_pip_packages(["install", "requests"]) == ["requests"]

    def test_multiple_packages(self):
        assert _extract_pip_packages(["install", "requests", "flask", "click"]) == ["requests", "flask", "click"]

    def test_with_version_spec(self):
        assert _extract_pip_packages(["install", "requests>=2.28"]) == ["requests"]

    def test_with_extras(self):
        assert _extract_pip_packages(["install", "agent-bom[mcp-server]"]) == ["agent-bom"]

    def test_skips_flags(self):
        assert _extract_pip_packages(["install", "--upgrade", "requests"]) == ["requests"]

    def test_skips_value_flags(self):
        assert _extract_pip_packages(["install", "-r", "requirements.txt", "requests"]) == ["requests"]

    def test_no_install_subcommand(self):
        assert _extract_pip_packages(["list"]) == []

    def test_empty(self):
        assert _extract_pip_packages([]) == []

    def test_index_url_flag(self):
        assert _extract_pip_packages(["install", "--index-url", "https://pypi.org/simple", "flask"]) == ["flask"]

    def test_editable_skip(self):
        assert _extract_pip_packages(["install", "-e", ".", "requests"]) == ["requests"]


class TestExtractNpmPackages:
    def test_basic_install(self):
        assert _extract_npm_packages(["install", "express"]) == ["express"]

    def test_scoped_package(self):
        assert _extract_npm_packages(["install", "@types/node"]) == ["@types/node"]

    def test_with_version(self):
        assert _extract_npm_packages(["install", "express@4.18"]) == ["express"]

    def test_multiple_packages(self):
        assert _extract_npm_packages(["install", "express", "lodash"]) == ["express", "lodash"]

    def test_i_alias(self):
        assert _extract_npm_packages(["i", "express"]) == ["express"]

    def test_add_alias(self):
        assert _extract_npm_packages(["add", "express"]) == ["express"]

    def test_skips_flags(self):
        assert _extract_npm_packages(["install", "--save-dev", "express"]) == ["express"]

    def test_no_install(self):
        assert _extract_npm_packages(["list"]) == []

    def test_empty(self):
        assert _extract_npm_packages([]) == []


class TestGuardResult:
    def test_defaults(self):
        r = GuardResult()
        assert r.packages_checked == 0
        assert r.packages_blocked == 0
        assert r.install_allowed is True
        assert r.blocked == []
        assert r.clean == []

    def test_blocked_result(self):
        r = GuardResult(
            packages_checked=3,
            packages_blocked=1,
            packages_clean=2,
            blocked=[{"name": "badpkg", "vulns": [{"id": "CVE-2024-1234"}]}],
            clean=["goodpkg1", "goodpkg2"],
            install_allowed=False,
        )
        assert not r.install_allowed
        assert len(r.blocked) == 1
        assert r.blocked[0]["name"] == "badpkg"
