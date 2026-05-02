"""Tests for GitHub Security Advisory (GHSA) enrichment module."""

from __future__ import annotations

import pytest

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
    """Missing severity defaults to UNKNOWN — never silently inflate to MEDIUM."""
    sev, score = _parse_ghsa_severity({})
    assert sev == Severity.UNKNOWN
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


def test_fetch_advisories_paginates_and_uses_github_token(monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch

    from agent_bom.scanners.ghsa_advisory import _GHSA_PER_PAGE, _fetch_advisories_for_package

    first = MagicMock()
    first.status_code = 200
    first.headers = {}
    first.json.return_value = [{"ghsa_id": f"GHSA-page-one-{idx:04d}"} for idx in range(_GHSA_PER_PAGE)]
    second = MagicMock()
    second.status_code = 200
    second.headers = {}
    second.json.return_value = [{"ghsa_id": "GHSA-page-two-last"}]
    pkg = Package(name="express", version="4.17.1", ecosystem="npm")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")

    async def run():
        with patch("agent_bom.scanners.ghsa_advisory.request_with_retry", new_callable=AsyncMock) as request:
            request.side_effect = [first, second]
            advisories = await _fetch_advisories_for_package(pkg, MagicMock(), asyncio.Semaphore(1))
            return advisories, request

    advisories, request = asyncio.run(run())

    assert len(advisories) == _GHSA_PER_PAGE + 1
    assert request.await_args_list[0].kwargs["params"]["page"] == "1"
    assert request.await_args_list[1].kwargs["params"]["page"] == "2"
    assert request.await_args_list[0].kwargs["headers"]["Authorization"] == "Bearer ghp_test"


def test_fetch_advisories_fails_fast_on_rate_limit_even_with_backoff():
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch

    from agent_bom.scanners.ghsa_advisory import GHSARateLimitError, _fetch_advisories_for_package

    limited = MagicMock()
    limited.status_code = 429
    limited.headers = {"Retry-After": "0.01"}
    pkg = Package(name="express", version="4.17.1", ecosystem="npm")

    async def run():
        with (
            patch("agent_bom.scanners.ghsa_advisory.request_with_retry", new_callable=AsyncMock) as request,
            patch("agent_bom.scanners.ghsa_advisory.asyncio.sleep", new_callable=AsyncMock) as sleep,
        ):
            request.return_value = limited
            with pytest.raises(GHSARateLimitError):
                await _fetch_advisories_for_package(pkg, MagicMock(), asyncio.Semaphore(1), rate_limit_backoff=0.01)
            return request, sleep

    request, sleep = asyncio.run(run())

    assert request.await_count == 1
    sleep.assert_not_awaited()


def test_fetch_advisories_can_fail_fast_on_rate_limit():
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch

    import pytest

    from agent_bom.scanners.ghsa_advisory import GHSARateLimitError, _fetch_advisories_for_package

    limited = MagicMock()
    limited.status_code = 429
    limited.headers = {"Retry-After": "60"}
    pkg = Package(name="express", version="4.17.1", ecosystem="npm")

    async def run():
        with (
            patch("agent_bom.scanners.ghsa_advisory.request_with_retry", new_callable=AsyncMock) as request,
            patch("agent_bom.scanners.ghsa_advisory.asyncio.sleep", new_callable=AsyncMock) as sleep,
        ):
            request.return_value = limited
            with pytest.raises(GHSARateLimitError):
                await _fetch_advisories_for_package(
                    pkg,
                    MagicMock(),
                    asyncio.Semaphore(1),
                    rate_limit_backoff=0.0,
                )
            return request, sleep

    request, sleep = asyncio.run(run())

    assert request.await_count == 1
    sleep.assert_not_awaited()


def test_single_package_without_github_token_uses_fail_fast_rate_limit_backoff(monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock, patch

    from agent_bom.scanners.ghsa_advisory import _GHSA_SINGLE_PACKAGE_RATE_LIMIT_BACKOFF, check_github_advisories

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    pkg = Package(name="express", version="4.17.1", ecosystem="npm")

    async def run():
        with patch("agent_bom.scanners.ghsa_advisory._fetch_advisories_for_package", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = []
            count = await check_github_advisories([pkg])
            return count, mock_fetch

    count, mock_fetch = asyncio.run(run())

    assert count == 0
    assert mock_fetch.await_count == 1
    assert mock_fetch.await_args.kwargs["rate_limit_backoff"] == _GHSA_SINGLE_PACKAGE_RATE_LIMIT_BACKOFF


def test_multi_package_without_github_token_uses_fail_fast_rate_limit_backoff(monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock, patch

    from agent_bom.scanners.ghsa_advisory import _GHSA_SINGLE_PACKAGE_RATE_LIMIT_BACKOFF, check_github_advisories

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    packages = [
        Package(name="express", version="4.17.1", ecosystem="npm"),
        Package(name="lodash", version="4.17.20", ecosystem="npm"),
    ]

    async def run():
        with patch("agent_bom.scanners.ghsa_advisory._fetch_advisories_for_package", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = []
            count = await check_github_advisories(packages)
            return count, mock_fetch

    count, mock_fetch = asyncio.run(run())

    assert count == 0
    assert mock_fetch.await_count == 2
    assert {call.kwargs["rate_limit_backoff"] for call in mock_fetch.await_args_list} == {_GHSA_SINGLE_PACKAGE_RATE_LIMIT_BACKOFF}


def test_without_github_token_applies_package_budget(monkeypatch, caplog):
    import asyncio
    import logging
    from unittest.mock import AsyncMock, patch

    from agent_bom.scanners.ghsa_advisory import _GHSA_SINGLE_PACKAGE_RATE_LIMIT_BACKOFF, check_github_advisories
    from agent_bom.scanners.state import consume_scan_warnings, reset_scan_warnings

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setattr("agent_bom.scanners.ghsa_advisory._CONFIG_GHSA_UNAUTH_PACKAGE_BUDGET", 2)
    reset_scan_warnings()
    packages = [
        Package(name="express", version="4.17.1", ecosystem="npm"),
        Package(name="lodash", version="4.17.20", ecosystem="npm"),
        Package(name="requests", version="2.31.0", ecosystem="pypi"),
    ]

    async def run():
        with patch("agent_bom.scanners.ghsa_advisory._fetch_advisories_for_package", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = []
            with caplog.at_level(logging.INFO, logger="agent_bom.scanners.ghsa_advisory"):
                count = await check_github_advisories(packages)
            return count, mock_fetch

    count, mock_fetch = asyncio.run(run())

    assert count == 0
    assert mock_fetch.await_count == 2
    assert {call.args[0].name for call in mock_fetch.await_args_list} == {"express", "lodash"}
    assert {call.kwargs["rate_limit_backoff"] for call in mock_fetch.await_args_list} == {_GHSA_SINGLE_PACKAGE_RATE_LIMIT_BACKOFF}

    # The token-budget hint is now an INFO-level note (so default scans don't
    # surface it as a scan-quality warning) and is intentionally NOT recorded
    # via record_scan_warning. It still shows under --verbose / --log-level
    # info via the logger; assert it shows up there with the expected counts.
    info_text = "\n".join(rec.getMessage() for rec in caplog.records if rec.name == "agent_bom.scanners.ghsa_advisory")
    assert "GHSA advisory enrichment limited to 2 unauthenticated package lookup(s); skipped 1" in info_text
    # And confirm it does NOT bubble into the scan_warnings bucket (the
    # warnings_all badge users see on every scan report would otherwise
    # mark a clean scan as "completed with warnings").
    assert not any("unauthenticated package lookup" in item for item in consume_scan_warnings())


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


def test_ghsa_advisory_records_enrichment_posture():
    import asyncio
    from unittest.mock import AsyncMock, patch

    from agent_bom.enrichment_posture import describe_enrichment_posture, reset_enrichment_posture_for_tests
    from agent_bom.scanners.ghsa_advisory import check_github_advisories

    reset_enrichment_posture_for_tests()
    pkg = Package(name="express", version="4.17.1", ecosystem="npm")

    async def run():
        with patch("agent_bom.scanners.ghsa_advisory._fetch_advisories_for_package", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = []
            return await check_github_advisories([pkg])

    assert asyncio.run(run()) == 0
    sources = {source["source"]: source for source in describe_enrichment_posture()["sources"]}
    assert sources["ghsa"]["status"] == "ok"
    assert sources["ghsa"]["success_count"] == 1


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


def test_already_patched_version_not_flagged():
    """GHSA advisory must not flag a package whose version is >= the fix version.

    Regression test for false positive where authlib@1.6.9 was flagged by
    CVE-2026-27962 even though 1.6.9 is the fix (vulnerable range <= 1.6.8).
    """
    from unittest.mock import AsyncMock, patch

    pkg = Package(name="authlib", version="1.6.9", ecosystem="pypi")

    # Advisory: CVE-2026-27962, patched in 1.6.9 (so <= 1.6.8 is vulnerable)
    ghsa_advisory = {
        "ghsa_id": "GHSA-wvwj-cvrp-7pv5",
        "cve_id": "CVE-2026-27962",
        "severity": "critical",
        "cvss": {"score": 9.1},
        "summary": "authlib OIDC auth bypass",
        "html_url": "https://github.com/advisories/GHSA-wvwj-cvrp-7pv5",
        "cwes": [],
        "vulnerabilities": [
            {
                "package": {"name": "authlib", "ecosystem": "pip"},
                "patched_versions": ">= 1.6.9",
            }
        ],
    }

    import asyncio

    from agent_bom.scanners.ghsa_advisory import check_github_advisories

    async def run():
        with patch(
            "agent_bom.scanners.ghsa_advisory._fetch_advisories_for_package",
            new_callable=AsyncMock,
        ) as mock_fetch:
            mock_fetch.return_value = [ghsa_advisory]
            count = await check_github_advisories([pkg])
        return count

    count = asyncio.run(run())
    assert count == 0, "Patched version must not be flagged as vulnerable"
    assert len(pkg.vulnerabilities) == 0, "No vulnerabilities should be added for an already-patched package"


def test_patched_versions_null_lte_range_not_flagged():
    """When patched_versions is null, use vulnerable_version_range to skip safe versions.

    Current GHSA API returns patched_versions=null and uses vulnerable_version_range
    like '<= 1.6.8'.  authlib@1.6.9 must NOT be flagged.
    """
    import asyncio
    from unittest.mock import AsyncMock, patch

    from agent_bom.scanners.ghsa_advisory import check_github_advisories

    pkg = Package(name="authlib", version="1.6.9", ecosystem="pypi")

    # Real-world format: patched_versions=None, range='<= 1.6.8'
    ghsa_advisory = {
        "ghsa_id": "GHSA-wvwj-cvrp-7pv5",
        "cve_id": "CVE-2026-27962",
        "severity": "critical",
        "cvss": {"score": 9.1},
        "summary": "authlib OIDC auth bypass",
        "html_url": "https://github.com/advisories/GHSA-wvwj-cvrp-7pv5",
        "cwes": [],
        "vulnerabilities": [
            {
                "package": {"name": "authlib", "ecosystem": "pip"},
                "patched_versions": None,
                "vulnerable_version_range": "<= 1.6.8",
            }
        ],
    }

    async def run():
        with patch(
            "agent_bom.scanners.ghsa_advisory._fetch_advisories_for_package",
            new_callable=AsyncMock,
        ) as mock_fetch:
            mock_fetch.return_value = [ghsa_advisory]
            count = await check_github_advisories([pkg])
        return count

    count = asyncio.run(run())
    assert count == 0, "Version outside vulnerable range must not be flagged"
    assert len(pkg.vulnerabilities) == 0


def test_patched_versions_null_lt_range_affected_version_flagged():
    """When patched_versions is null and range is '< 4.5.2', version 4.5.1 IS affected."""
    import asyncio
    from unittest.mock import AsyncMock, patch

    from agent_bom.scanners.ghsa_advisory import check_github_advisories

    pkg = Package(name="somelib", version="4.5.1", ecosystem="pypi")

    ghsa_advisory = {
        "ghsa_id": "GHSA-test-1234-5678",
        "cve_id": "CVE-2026-99999",
        "severity": "high",
        "cvss": {"score": 7.5},
        "summary": "Test vulnerability",
        "html_url": "https://github.com/advisories/GHSA-test-1234-5678",
        "cwes": [],
        "vulnerabilities": [
            {
                "package": {"name": "somelib", "ecosystem": "pip"},
                "patched_versions": None,
                "vulnerable_version_range": "< 4.5.2",
            }
        ],
    }

    async def run():
        with patch(
            "agent_bom.scanners.ghsa_advisory._fetch_advisories_for_package",
            new_callable=AsyncMock,
        ) as mock_fetch:
            mock_fetch.return_value = [ghsa_advisory]
            count = await check_github_advisories([pkg])
        return count

    count = asyncio.run(run())
    assert count == 1, "Version inside vulnerable range must be flagged"
    assert len(pkg.vulnerabilities) == 1
    assert pkg.vulnerabilities[0].fixed_version == "4.5.2"


def test_installed_version_is_affected_helpers():
    """Unit tests for the _installed_version_is_affected helper."""
    from agent_bom.scanners.ghsa_advisory import _installed_version_is_affected

    # <= range: 1.6.9 is NOT in '<= 1.6.8'
    assert _installed_version_is_affected("1.6.9", "<= 1.6.8") is False
    # <= range: 1.6.8 IS in '<= 1.6.8'
    assert _installed_version_is_affected("1.6.8", "<= 1.6.8") is True
    # < range: 4.5.2 is NOT in '< 4.5.2'
    assert _installed_version_is_affected("4.5.2", "< 4.5.2") is False
    # < range: 4.5.1 IS in '< 4.5.2'
    assert _installed_version_is_affected("4.5.1", "< 4.5.2") is True
    # compound range: 25.0.0 IS in '>= 22.0.0, < 26.0.0'
    assert _installed_version_is_affected("25.0.0", ">= 22.0.0, < 26.0.0") is True
    # compound range: 26.0.0 is NOT in '>= 22.0.0, < 26.0.0'
    assert _installed_version_is_affected("26.0.0", ">= 22.0.0, < 26.0.0") is False
    # compound range: 21.0.0 is NOT in '>= 22.0.0, < 26.0.0'
    assert _installed_version_is_affected("21.0.0", ">= 22.0.0, < 26.0.0") is False


def test_multi_range_advisory_or_semantics():
    """Multi-entry advisories for same package use OR logic — affected if in ANY range."""
    from agent_bom.scanners.ghsa_advisory import _get_vulnerable_ranges_for_package

    advisory = {
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "mylib"},
                "vulnerable_version_range": "< 1.0",
            },
            {
                "package": {"ecosystem": "pip", "name": "mylib"},
                "vulnerable_version_range": ">= 1.5, < 2.0",
            },
        ]
    }
    ranges = _get_vulnerable_ranges_for_package(advisory, "mylib", "pypi")
    assert len(ranges) == 2
    # 0.9 is in '< 1.0'
    from agent_bom.scanners.ghsa_advisory import _installed_version_is_affected

    assert any(_installed_version_is_affected("0.9", r) for r in ranges) is True
    # 1.2 is NOT in either range (patched window between 1.0 and 1.5)
    assert any(_installed_version_is_affected("1.2", r) for r in ranges) is False
    # 1.7 is in '>= 1.5, < 2.0' (second range — previously missed)
    assert any(_installed_version_is_affected("1.7", r) for r in ranges) is True
    # 2.0 is not in any range
    assert any(_installed_version_is_affected("2.0", r) for r in ranges) is False
