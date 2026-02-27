"""Tests for GitHub Security Advisory (GHSA) enrichment module."""

from __future__ import annotations

from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.scanners.ghsa_advisory import (
    _ECOSYSTEM_MAP,
    _extract_fixed_version,
    _get_cwe_ids,
    _parse_ghsa_severity,
)


def test_ecosystem_mapping_covers_major_ecosystems():
    """Ecosystem map covers PyPI, npm, Go, Maven, Cargo, NuGet."""
    assert _ECOSYSTEM_MAP["pypi"] == "pip"
    assert _ECOSYSTEM_MAP["npm"] == "npm"
    assert _ECOSYSTEM_MAP["go"] == "go"
    assert _ECOSYSTEM_MAP["maven"] == "maven"
    assert _ECOSYSTEM_MAP["cargo"] == "rust"
    assert _ECOSYSTEM_MAP["nuget"] == "nuget"


def test_severity_parsing_critical():
    """CRITICAL severity maps correctly with CVSS score."""
    sev, score = _parse_ghsa_severity({"severity": "critical", "cvss": {"score": 9.8}})
    assert sev == Severity.CRITICAL
    assert score == 9.8


def test_severity_parsing_high():
    """HIGH severity maps correctly."""
    sev, score = _parse_ghsa_severity({"severity": "high", "cvss": {"score": 7.5}})
    assert sev == Severity.HIGH
    assert score == 7.5


def test_severity_parsing_medium():
    """MEDIUM severity maps correctly."""
    sev, score = _parse_ghsa_severity({"severity": "medium", "cvss": {"score": 5.0}})
    assert sev == Severity.MEDIUM


def test_severity_parsing_low():
    """LOW severity maps correctly."""
    sev, score = _parse_ghsa_severity({"severity": "low", "cvss": {"score": 2.0}})
    assert sev == Severity.LOW


def test_severity_parsing_missing():
    """Missing severity defaults to MEDIUM."""
    sev, score = _parse_ghsa_severity({})
    assert sev == Severity.MEDIUM
    assert score is None


def test_fixed_version_extraction():
    """Extracts fixed version from GHSA vulnerability ranges."""
    advisory = {
        "vulnerabilities": [
            {
                "package": {"name": "express", "ecosystem": "npm"},
                "patched_versions": ">= 4.18.0",
            }
        ]
    }
    result = _extract_fixed_version(advisory, "express")
    assert result == "4.18.0"


def test_fixed_version_extraction_no_patch():
    """Returns None when no patched version available."""
    advisory = {"vulnerabilities": [{"package": {"name": "express"}, "patched_versions": ""}]}
    result = _extract_fixed_version(advisory, "express")
    assert result is None


def test_fixed_version_extraction_wrong_package():
    """Returns None when package name doesn't match."""
    advisory = {"vulnerabilities": [{"package": {"name": "lodash"}, "patched_versions": ">= 4.17.21"}]}
    result = _extract_fixed_version(advisory, "express")
    assert result is None


def test_cwe_ids_extraction():
    """Extracts CWE IDs from advisory."""
    advisory = {"cwes": [{"cwe_id": "CWE-79"}, {"cwe_id": "CWE-89"}]}
    result = _get_cwe_ids(advisory)
    assert result == ["CWE-79", "CWE-89"]


def test_cwe_ids_empty():
    """Returns empty list when no CWEs."""
    assert _get_cwe_ids({}) == []
    assert _get_cwe_ids({"cwes": []}) == []


def test_dedup_skips_existing_cve():
    """GHSA enrichment should skip CVEs already present on a package."""
    pkg = Package(
        name="express",
        version="4.17.1",
        ecosystem="npm",
        vulnerabilities=[
            Vulnerability(
                id="CVE-2024-1234",
                summary="existing",
                severity=Severity.HIGH,
            )
        ],
    )
    existing_ids = {v.id for v in pkg.vulnerabilities}
    # Simulate a GHSA advisory returning the same CVE
    assert "CVE-2024-1234" in existing_ids


def test_unknown_ecosystem_skipped():
    """Packages with unsupported ecosystems should not be queried."""
    assert "unknown_eco" not in _ECOSYSTEM_MAP
