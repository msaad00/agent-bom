"""Tests for enrichment accuracy — CVE alias extraction & EPSS/KEV with aliases."""

from __future__ import annotations

from agent_bom.enrichment import extract_cve_ids
from agent_bom.models import Severity, Vulnerability


def test_extract_cve_ids_from_primary_id():
    """CVE IDs are extracted from primary vulnerability ID."""
    vulns = [
        Vulnerability(id="CVE-2024-1234", summary="test", severity=Severity.HIGH),
        Vulnerability(id="CVE-2024-5678", summary="test", severity=Severity.MEDIUM),
    ]
    cve_ids = extract_cve_ids(vulns)
    assert sorted(cve_ids) == ["CVE-2024-1234", "CVE-2024-5678"]


def test_extract_cve_ids_from_aliases():
    """CVE IDs are extracted from vulnerability aliases when primary ID is GHSA."""
    vulns = [
        Vulnerability(
            id="GHSA-aaaa-bbbb-cccc",
            summary="test",
            severity=Severity.HIGH,
            aliases=["CVE-2024-9999"],
        ),
    ]
    cve_ids = extract_cve_ids(vulns)
    assert cve_ids == ["CVE-2024-9999"]


def test_extract_cve_ids_deduplicates():
    """Same CVE in primary ID and alias is not duplicated."""
    vulns = [
        Vulnerability(
            id="CVE-2024-1111",
            summary="test",
            severity=Severity.HIGH,
            aliases=["GHSA-xxxx-yyyy-zzzz", "CVE-2024-1111"],
        ),
    ]
    cve_ids = extract_cve_ids(vulns)
    assert cve_ids == ["CVE-2024-1111"]


def test_extract_cve_ids_no_cve():
    """Non-CVE IDs with no CVE aliases return empty list."""
    vulns = [
        Vulnerability(
            id="GHSA-aaaa-bbbb-cccc",
            summary="test",
            severity=Severity.HIGH,
            aliases=["RUSTSEC-2024-0001"],
        ),
    ]
    assert extract_cve_ids(vulns) == []


def test_extract_cve_ids_mixed():
    """Mix of primary CVEs, alias CVEs, and non-CVE vulns."""
    vulns = [
        Vulnerability(id="CVE-2024-0001", summary="a", severity=Severity.HIGH),
        Vulnerability(
            id="GHSA-xxxx-yyyy-zzzz",
            summary="b",
            severity=Severity.MEDIUM,
            aliases=["CVE-2024-0002"],
        ),
        Vulnerability(id="MAL-2024-0003", summary="c", severity=Severity.LOW),
    ]
    cve_ids = sorted(extract_cve_ids(vulns))
    assert cve_ids == ["CVE-2024-0001", "CVE-2024-0002"]


def test_vulnerability_aliases_field_default():
    """Vulnerability aliases field defaults to empty list."""
    vuln = Vulnerability(id="CVE-2024-0001", summary="test", severity=Severity.HIGH)
    assert vuln.aliases == []


def test_vulnerability_aliases_populated():
    """Vulnerability aliases can be set at construction."""
    vuln = Vulnerability(
        id="CVE-2024-0001",
        summary="test",
        severity=Severity.HIGH,
        aliases=["GHSA-aaaa-bbbb-cccc", "OSV-2024-0001"],
    )
    assert len(vuln.aliases) == 2
    assert "GHSA-aaaa-bbbb-cccc" in vuln.aliases
