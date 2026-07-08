"""Tests for dependency confusion detection."""

from __future__ import annotations

from agent_bom.malicious import check_dependency_confusion, check_typosquat
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
    assert check_dependency_confusion(_pkg("@babel/core", "npm")) is None
    assert check_dependency_confusion(_pkg("@eslint-community/eslint-utils", "npm")) is None
    assert check_dependency_confusion(_pkg("@opentelemetry/api", "npm")) is None
    assert check_dependency_confusion(_pkg("@typescript-eslint/project-service", "npm")) is None
    assert check_dependency_confusion(_pkg("@typescript-eslint/tsconfig-utils", "npm")) is None


def test_safe_scoped_npm_not_flagged_as_typosquat():
    assert check_typosquat("@babel/core", "npm") is None


def test_unknown_npm_scope_with_internal_name():
    pkg = _pkg("@evil-corp/internal-sdk", "npm")
    result = check_dependency_confusion(pkg)
    assert result is not None


def test_package_with_scorecard_not_flagged():
    """If package has OpenSSF scorecard data, it's verified public."""
    pkg = _pkg("company-core-lib")
    pkg.scorecard_score = 7.5
    assert check_dependency_confusion(pkg) is None


def test_common_public_suffixes_not_flagged_as_confusion_without_org_signal():
    """Common public package suffixes alone are too broad for confusion risk."""
    assert check_dependency_confusion(_pkg("pydantic-core")) is None
    assert check_dependency_confusion(_pkg("cyclonedx-python-lib")) is None
    assert check_dependency_confusion(_pkg("openai-sdk")) is None


def test_public_cloud_and_telemetry_namespaces_not_flagged_as_confusion():
    """Cloud SDK namespaces use service-like public package names."""
    assert check_dependency_confusion(_pkg("azure-common")) is None
    assert check_dependency_confusion(_pkg("azure-mgmt-apimanagement")) is None
    assert check_dependency_confusion(_pkg("azure-mgmt-servicebus")) is None
    assert check_dependency_confusion(_pkg("google-api-core")) is None
    assert check_dependency_confusion(_pkg("google-api-python-client")) is None
    assert check_dependency_confusion(_pkg("googleapis-common-protos")) is None
    assert check_dependency_confusion(_pkg("opentelemetry-api")) is None
    assert check_dependency_confusion(_pkg("dom-accessibility-api", "npm")) is None
    assert check_dependency_confusion(_pkg("eslint-module-utils", "npm")) is None
    assert check_dependency_confusion(_pkg("graphology-utils", "npm")) is None
    assert check_dependency_confusion(_pkg("internal-slot", "npm")) is None
    assert check_dependency_confusion(_pkg("is-shared-array-buffer", "npm")) is None
    assert check_dependency_confusion(_pkg("jsx-ast-utils", "npm")) is None
    assert check_dependency_confusion(_pkg("ts-api-utils", "npm")) is None


def test_weak_internal_suffix_flagged_when_version_unresolved():
    pkg = _pkg("mycompany-platform", version="unknown")
    result = check_dependency_confusion(pkg)
    assert result is not None


def test_weak_service_suffix_flagged_when_version_unresolved():
    pkg = _pkg("auth-service", version="unknown")
    result = check_dependency_confusion(pkg)
    assert result is not None


def test_no_pattern_match_not_flagged():
    """Normal package names without internal patterns are fine."""
    assert check_dependency_confusion(_pkg("express", "npm")) is None
    assert check_dependency_confusion(_pkg("django")) is None
    assert check_dependency_confusion(_pkg("react", "npm")) is None
    assert check_dependency_confusion(_pkg("tensorflow")) is None
