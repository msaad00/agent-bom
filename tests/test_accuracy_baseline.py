"""Accuracy baseline tests — known-vulnerable packages must be flagged.

These tests query the OSV API with packages that have well-known CVEs.
They act as regression tests: if the scanner ever stops finding these,
something is broken in the OSV query or parsing pipeline.

Marked with ``pytest.mark.network`` so they can be skipped in offline CI.
"""

from __future__ import annotations

import asyncio

import pytest

from agent_bom.models import Package, Severity
from agent_bom.scanners import build_vulnerabilities, parse_osv_severity, query_osv_batch

pytestmark = pytest.mark.network


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_pkg(name: str, version: str, ecosystem: str = "pypi") -> Package:
    """Create a Package with normalised lowercase ecosystem (matches ECOSYSTEM_MAP)."""
    return Package(name=name, version=version, ecosystem=ecosystem.lower())


def _scan_one(pkg: Package) -> list:
    """Run OSV batch query for a single package and return raw vuln dicts."""
    results = asyncio.run(query_osv_batch([pkg]))
    # query_osv_batch normalises ecosystem keys to lowercase + PEP 503 name
    from agent_bom.models import normalize_package_name

    key = f"{pkg.ecosystem.lower()}:{normalize_package_name(pkg.name, pkg.ecosystem)}@{pkg.version}"
    return results.get(key, [])


# ── Known-vulnerable packages ───────────────────────────────────────────────


class TestKnownVulnerablePackages:
    """Packages with well-known CVEs that MUST be detected."""

    def test_flask_2_2_0(self):
        """Flask 2.2.0 has known vulnerabilities (e.g. debugger pin)."""
        pkg = _make_pkg("flask", "2.2.0")
        vulns = _scan_one(pkg)
        assert len(vulns) > 0, "Flask 2.2.0 should have known vulnerabilities"

    def test_requests_2_25_0(self):
        """requests 2.25.0 has CVE-2023-32681 (header leak on redirect)."""
        pkg = _make_pkg("requests", "2.25.0")
        vulns = _scan_one(pkg)
        assert len(vulns) > 0, "requests 2.25.0 should have known vulnerabilities"

    def test_jinja2_3_1_2(self):
        """Jinja2 3.1.2 has CVE-2024-22195 (XSS in xmlattr filter)."""
        pkg = _make_pkg("jinja2", "3.1.2")
        vulns = _scan_one(pkg)
        assert len(vulns) > 0, "Jinja2 3.1.2 should have known vulnerabilities"

    def test_werkzeug_2_2_0(self):
        """Werkzeug 2.2.0 has known debugger vulnerabilities."""
        pkg = _make_pkg("werkzeug", "2.2.0")
        vulns = _scan_one(pkg)
        assert len(vulns) > 0, "Werkzeug 2.2.0 should have known vulnerabilities"

    def test_django_3_2_0_npm(self):
        """Django 3.2.0 has multiple known CVEs."""
        pkg = _make_pkg("Django", "3.2.0")
        vulns = _scan_one(pkg)
        assert len(vulns) >= 2, "Django 3.2.0 should have multiple vulnerabilities"

    def test_pillow_9_0_0(self):
        """Pillow 9.0.0 has multiple known buffer overflow CVEs."""
        pkg = _make_pkg("Pillow", "9.0.0")
        vulns = _scan_one(pkg)
        assert len(vulns) >= 2, "Pillow 9.0.0 should have multiple vulnerabilities"


# ── Clean packages should have zero vulns ────────────────────────────────────


class TestCleanPackages:
    """Very recent stable packages should have zero (or very few) vulns."""

    def test_recent_package_low_vulns(self):
        """A current, well-maintained package should not have critical vulns."""
        # Using a recent pip version as baseline
        pkg = _make_pkg("pip", "24.0")
        vulns = _scan_one(pkg)
        if vulns:
            built = build_vulnerabilities(vulns, pkg)
            critical = [v for v in built if v.severity == Severity.CRITICAL]
            assert len(critical) == 0, f"pip 24.0 should not have CRITICAL vulns, got {len(critical)}"


# ── Severity parsing accuracy ────────────────────────────────────────────────


class TestSeverityParsing:
    """Verify severity extraction from real OSV-format entries."""

    def test_critical_score(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        severity, score = parse_osv_severity(vuln)
        assert score == 9.8
        assert severity == Severity.CRITICAL

    def test_medium_score(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"}]}
        severity, score = parse_osv_severity(vuln)
        assert score is not None
        assert severity in (Severity.LOW, Severity.MEDIUM)

    def test_no_severity_returns_default(self):
        """No severity data → defaults to UNKNOWN (not MEDIUM — never silently inflate)."""
        vuln = {}
        severity, score = parse_osv_severity(vuln)
        assert severity == Severity.UNKNOWN
        assert score is None

    def test_numeric_score_fallback(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "8.1"}]}
        severity, score = parse_osv_severity(vuln)
        assert score == 8.1
        assert severity == Severity.HIGH

    def test_build_vulnerabilities_deduplicates(self):
        """Same vuln ID should not appear twice."""
        pkg = _make_pkg("test-pkg", "1.0.0")
        raw = [
            {"id": "CVE-2024-0001", "summary": "Test vuln", "severity": []},
            {"id": "CVE-2024-0001", "summary": "Test vuln (duplicate)", "severity": []},
        ]
        built = build_vulnerabilities(raw, pkg)
        ids = [v.id for v in built]
        assert len(ids) == len(set(ids)), f"Duplicate vuln IDs found: {ids}"
