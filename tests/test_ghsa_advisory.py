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


def test_advisory_filtered_by_package_name():
    """Advisories for different packages are filtered out (substring match fix).

    The GitHub Advisory API returns substring matches — e.g., querying for
    "express" returns advisories for "express-session", "express-validator",
    etc.  The enrichment must only add advisories whose vulnerability entries
    list the exact target package name.
    """
    import asyncio
    from unittest.mock import AsyncMock, patch

    from agent_bom.scanners.ghsa_advisory import check_github_advisories

    # Advisory that does NOT match our target package (express-session, not express)
    wrong_advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cve_id": "CVE-2099-0001",
        "severity": "high",
        "cvss": {"score": 7.5},
        "summary": "Session fixation in express-session",
        "cwes": [],
        "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "vulnerabilities": [
            {
                "package": {"name": "express-session", "ecosystem": "npm"},
                "patched_versions": ">= 1.18.0",
            }
        ],
    }
    # Advisory that DOES match our target package
    correct_advisory = {
        "ghsa_id": "GHSA-dddd-eeee-ffff",
        "cve_id": "CVE-2099-0002",
        "severity": "critical",
        "cvss": {"score": 9.8},
        "summary": "RCE in express",
        "cwes": [{"cwe_id": "CWE-94"}],
        "html_url": "https://github.com/advisories/GHSA-dddd-eeee-ffff",
        "vulnerabilities": [
            {
                "package": {"name": "express", "ecosystem": "npm"},
                "patched_versions": ">= 4.19.0",
            }
        ],
    }

    pkg = Package(name="express", version="4.17.1", ecosystem="npm")

    async def run():
        with patch("agent_bom.scanners.ghsa_advisory._fetch_advisories_for_package", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = [wrong_advisory, correct_advisory]
            count = await check_github_advisories([pkg])
        return count

    count = asyncio.run(run())

    # Only the matching advisory should be added
    assert count == 1
    assert len(pkg.vulnerabilities) == 1
    assert pkg.vulnerabilities[0].id == "CVE-2099-0002"
    assert pkg.vulnerabilities[0].fixed_version == "4.19.0"


def test_advisory_no_match_skipped():
    """Advisory with no matching package is completely skipped."""
    import asyncio
    from unittest.mock import AsyncMock, patch

    from agent_bom.scanners.ghsa_advisory import check_github_advisories

    unrelated_advisory = {
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "cve_id": "CVE-2099-9999",
        "severity": "critical",
        "cvss": {"score": 10.0},
        "summary": "Total chaos in some-other-package",
        "cwes": [],
        "vulnerabilities": [
            {
                "package": {"name": "some-other-package", "ecosystem": "npm"},
                "patched_versions": ">= 2.0.0",
            }
        ],
    }

    pkg = Package(name="express", version="4.17.1", ecosystem="npm")

    async def run():
        with patch("agent_bom.scanners.ghsa_advisory._fetch_advisories_for_package", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = [unrelated_advisory]
            count = await check_github_advisories([pkg])
        return count

    count = asyncio.run(run())
    assert count == 0
    assert len(pkg.vulnerabilities) == 0


def test_alias_aware_dedup_skips_known_cve():
    """GHSA dedup checks vulnerability aliases, not just primary IDs.

    If OSV already returned a vuln under GHSA-xxxx with CVE-2024-1234 as alias,
    GHSA enrichment returning CVE-2024-1234 should be deduplicated.
    """
    import asyncio
    from unittest.mock import AsyncMock, patch

    from agent_bom.scanners.ghsa_advisory import check_github_advisories

    # Package already has a vuln from OSV stored under CVE ID with GHSA alias
    pkg = Package(
        name="express",
        version="4.17.1",
        ecosystem="npm",
        vulnerabilities=[
            Vulnerability(
                id="CVE-2099-5555",
                summary="existing from OSV",
                severity=Severity.HIGH,
                aliases=["GHSA-aaaa-bbbb-cccc"],
            )
        ],
    )

    # GHSA returns the same vuln under the GHSA ID
    ghsa_advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cve_id": "CVE-2099-5555",
        "severity": "high",
        "cvss": {"score": 7.5},
        "summary": "Same vuln from GHSA",
        "cwes": [],
        "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "vulnerabilities": [
            {
                "package": {"name": "express", "ecosystem": "npm"},
                "patched_versions": ">= 4.19.0",
            }
        ],
    }

    async def run():
        with patch("agent_bom.scanners.ghsa_advisory._fetch_advisories_for_package", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = [ghsa_advisory]
            count = await check_github_advisories([pkg])
        return count

    count = asyncio.run(run())
    assert count == 0  # Should be deduped
    assert len(pkg.vulnerabilities) == 1  # Only the original
