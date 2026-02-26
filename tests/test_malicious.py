"""Tests for malicious package detection module."""

from agent_bom.malicious import (
    check_typosquat,
    flag_malicious_from_vulns,
    is_malicious_vuln,
)
from agent_bom.models import Package, Severity, Vulnerability

# ─── MAL- prefix detection ───────────────────────────────────────────────────


def test_is_malicious_vuln_mal_prefix():
    assert is_malicious_vuln("MAL-2024-1234") is True


def test_is_malicious_vuln_mal_lowercase():
    assert is_malicious_vuln("mal-2024-5678") is True


def test_is_malicious_vuln_cve_not_malicious():
    assert is_malicious_vuln("CVE-2024-1234") is False


def test_is_malicious_vuln_ghsa_not_malicious():
    assert is_malicious_vuln("GHSA-xxxx-yyyy") is False


def test_is_malicious_vuln_osv_not_malicious():
    assert is_malicious_vuln("PYSEC-2024-123") is False


# ─── flag_malicious_from_vulns ───────────────────────────────────────────────


def test_flag_malicious_from_vulns_with_mal():
    pkg = Package(name="evil-pkg", version="1.0.0", ecosystem="npm")
    pkg.vulnerabilities = [
        Vulnerability(id="MAL-2024-1234", summary="Malicious package", severity=Severity.CRITICAL),
    ]
    flag_malicious_from_vulns(pkg)
    assert pkg.is_malicious is True
    assert "MAL-2024-1234" in pkg.malicious_reason


def test_flag_malicious_from_vulns_without_mal():
    pkg = Package(name="normal-pkg", version="1.0.0", ecosystem="npm")
    pkg.vulnerabilities = [
        Vulnerability(id="CVE-2024-1234", summary="Normal vuln", severity=Severity.HIGH),
    ]
    flag_malicious_from_vulns(pkg)
    assert pkg.is_malicious is False
    assert pkg.malicious_reason is None


def test_flag_malicious_from_vulns_mixed():
    pkg = Package(name="sneaky-pkg", version="1.0.0", ecosystem="pypi")
    pkg.vulnerabilities = [
        Vulnerability(id="CVE-2024-1111", summary="Normal", severity=Severity.MEDIUM),
        Vulnerability(id="MAL-2024-9999", summary="Malicious!", severity=Severity.CRITICAL),
    ]
    flag_malicious_from_vulns(pkg)
    assert pkg.is_malicious is True
    assert "MAL-2024-9999" in pkg.malicious_reason


def test_flag_malicious_no_vulns():
    pkg = Package(name="safe-pkg", version="1.0.0", ecosystem="npm")
    flag_malicious_from_vulns(pkg)
    assert pkg.is_malicious is False


# ─── Typosquat detection ─────────────────────────────────────────────────────


def test_typosquat_detects_close_match_npm():
    # "expresss" is very close to "express"
    result = check_typosquat("expresss", "npm")
    assert result == "express"


def test_typosquat_detects_close_match_pypi():
    # "reqeusts" is close to "requests"
    result = check_typosquat("reqeusts", "pypi")
    assert result == "requests"


def test_typosquat_exact_match_not_flagged():
    result = check_typosquat("express", "npm")
    assert result is None


def test_typosquat_different_package_not_flagged():
    result = check_typosquat("totally-different-pkg", "npm")
    assert result is None


def test_typosquat_unknown_ecosystem():
    result = check_typosquat("some-pkg", "maven")
    assert result is None


def test_typosquat_case_insensitive():
    result = check_typosquat("Expresss", "npm")
    assert result == "express"


def test_typosquat_pypi_torch():
    # "torcch" is close to "torch"
    result = check_typosquat("torcch", "pypi")
    assert result is not None


def test_typosquat_threshold_respected():
    # Low similarity should not flag
    result = check_typosquat("xyzabc", "npm", threshold=0.85)
    assert result is None


# ─── Integration with Package model ─────────────────────────────────────────


def test_package_is_malicious_defaults_false():
    pkg = Package(name="test", version="1.0", ecosystem="npm")
    assert pkg.is_malicious is False
    assert pkg.malicious_reason is None


def test_package_malicious_fields_settable():
    pkg = Package(
        name="evil",
        version="1.0",
        ecosystem="npm",
        is_malicious=True,
        malicious_reason="Known malicious package (MAL-2024-1234)",
    )
    assert pkg.is_malicious is True
    assert "MAL-2024-1234" in pkg.malicious_reason
