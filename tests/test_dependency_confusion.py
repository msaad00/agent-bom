"""Tests for dependency confusion detection."""

from __future__ import annotations

from agent_bom.malicious import check_dependency_confusion
from agent_bom.models import Package, Severity, Vulnerability


def _pkg(name: str, ecosystem: str = "pypi", version: str = "1.0.0") -> Package:
    return Package(name=name, version=version, ecosystem=ecosystem)


def test_normal_package_no_confusion():
    assert check_dependency_confusion(_pkg("requests")) is None


def test_internal_name_pattern_flagged():
    pkg = _pkg("company-auth-internal")
    result = check_dependency_confusion(pkg)
    assert result is not None
    assert "confusion" in result.lower()


def test_private_prefix_flagged():
    pkg = _pkg("private-utils")
    result = check_dependency_confusion(pkg)
    assert result is not None


def test_corp_sdk_flagged():
    pkg = _pkg("corp-ml-sdk")
    result = check_dependency_confusion(pkg)
    assert result is not None


def test_internal_suffix_flagged():
    pkg = _pkg("auth-internal")
    result = check_dependency_confusion(pkg)
    assert result is not None


def test_known_public_package_with_internal_name_not_flagged():
    """If package has vulnerability data, it's a known public package."""
    pkg = _pkg("flask-internal-utils")
    pkg.vulnerabilities = [Vulnerability(id="CVE-2024-1234", summary="test", severity=Severity.LOW)]
    assert check_dependency_confusion(pkg) is None


def test_scoped_npm_safe():
    """Known npm scopes are not confusion risks."""
    assert check_dependency_confusion(_pkg("@modelcontextprotocol/server-internal", "npm")) is None
    assert check_dependency_confusion(_pkg("@anthropic-ai/sdk-internal", "npm")) is None
    assert check_dependency_confusion(_pkg("@aws-sdk/client-internal", "npm")) is None


def test_unknown_npm_scope_with_internal_name():
    pkg = _pkg("@evil-corp/internal-sdk", "npm")
    result = check_dependency_confusion(pkg)
    assert result is not None


def test_package_with_scorecard_not_flagged():
    """If package has OpenSSF scorecard data, it's verified public."""
    pkg = _pkg("company-core-lib")
    pkg.scorecard_score = 7.5
    assert check_dependency_confusion(pkg) is None


def test_platform_suffix_flagged():
    pkg = _pkg("mycompany-platform")
    result = check_dependency_confusion(pkg)
    assert result is not None


def test_service_suffix_flagged():
    pkg = _pkg("auth-service")
    result = check_dependency_confusion(pkg)
    assert result is not None


def test_no_pattern_match_not_flagged():
    """Normal package names without internal patterns are fine."""
    assert check_dependency_confusion(_pkg("express", "npm")) is None
    assert check_dependency_confusion(_pkg("django")) is None
    assert check_dependency_confusion(_pkg("react", "npm")) is None
    assert check_dependency_confusion(_pkg("tensorflow")) is None
