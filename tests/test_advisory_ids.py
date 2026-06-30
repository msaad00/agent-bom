"""Tests for canonical advisory ID normalization and match-confidence tiers."""

from __future__ import annotations

import pytest

from agent_bom.advisory_ids import (
    MATCH_CONFIDENCE_DISTRO_CONFIRMED,
    MATCH_CONFIDENCE_OSV_RANGE,
    MATCH_CONFIDENCE_UNFIXED_DISTRO,
    all_cve_identifiers,
    canonical_vulnerability_id,
    derive_cve_from_advisory_id,
    match_confidence_tier,
)
from agent_bom.db.lookup import LocalVuln
from agent_bom.models import Package, Severity
from agent_bom.scanners import _local_vuln_to_vulnerability, build_vulnerabilities


@pytest.mark.parametrize(
    ("advisory_id", "expected"),
    [
        ("CVE-2022-0778", "CVE-2022-0778"),
        ("ALPINE-CVE-2022-0778", "CVE-2022-0778"),
        ("DEBIAN-CVE-2026-0001", "CVE-2026-0001"),
        ("GHSA-xxxx-yyyy-zzzz", None),
    ],
)
def test_derive_cve_from_advisory_id(advisory_id: str, expected: str | None) -> None:
    assert derive_cve_from_advisory_id(advisory_id) == expected


def test_canonical_vulnerability_id_prefers_explicit_cve_alias() -> None:
    canonical, aliases = canonical_vulnerability_id("GHSA-abcd-1234", ["CVE-2024-0001"])
    assert canonical == "CVE-2024-0001"
    assert "GHSA-abcd-1234" in aliases


def test_canonical_vulnerability_id_maps_alpine_distro_id() -> None:
    canonical, aliases = canonical_vulnerability_id("ALPINE-CVE-2022-0778", [])
    assert canonical == "CVE-2022-0778"
    assert aliases == ["ALPINE-CVE-2022-0778"]


def test_all_cve_identifiers_deduplicates_aliases() -> None:
    assert all_cve_identifiers("ALPINE-CVE-2022-0778", ["CVE-2022-0778"]) == ["CVE-2022-0778"]


def test_match_confidence_tier_distro_secdb() -> None:
    assert (
        match_confidence_tier(
            advisory_source="alpine-secdb",
            db_ecosystem="alpine:v3.14",
            package_ecosystem="apk",
            fixed_version="1.35.0-r18",
        )
        == MATCH_CONFIDENCE_DISTRO_CONFIRMED
    )


def test_match_confidence_tier_unfixed_os() -> None:
    assert (
        match_confidence_tier(
            advisory_source="osv",
            db_ecosystem=None,
            package_ecosystem="apk",
            fixed_version=None,
        )
        == MATCH_CONFIDENCE_UNFIXED_DISTRO
    )


def test_match_confidence_tier_osv_range() -> None:
    assert (
        match_confidence_tier(
            advisory_source="osv",
            db_ecosystem=None,
            package_ecosystem="pypi",
            fixed_version="2.0.1",
        )
        == MATCH_CONFIDENCE_OSV_RANGE
    )


def test_local_vuln_to_vulnerability_canonicalizes_alpine_id() -> None:
    lv = LocalVuln(
        id="ALPINE-CVE-2022-0778",
        summary="OpenSSL advisory",
        severity="high",
        cvss_score=7.5,
        fixed_version="1.1.1n-r0",
        source="alpine-secdb",
        ecosystem="alpine:v3.14",
    )
    vuln = _local_vuln_to_vulnerability(lv)
    assert vuln.id == "CVE-2022-0778"
    assert "ALPINE-CVE-2022-0778" in vuln.aliases
    assert vuln.match_confidence_tier == MATCH_CONFIDENCE_DISTRO_CONFIRMED


def test_local_vuln_to_vulnerability_canonicalizes_debian_id() -> None:
    lv = LocalVuln(
        id="DEBIAN-CVE-2026-0001",
        summary="Debian advisory",
        severity="",
        cvss_score=None,
        fixed_version="2.0.1-1",
        source="debian-tracker",
        ecosystem="debian:12",
    )
    vuln = _local_vuln_to_vulnerability(lv)
    assert vuln.id == "CVE-2026-0001"
    assert vuln.severity == Severity.MEDIUM
    assert vuln.match_confidence_tier == MATCH_CONFIDENCE_DISTRO_CONFIRMED


def test_build_vulnerabilities_canonicalizes_osv_alpine_alias() -> None:
    pkg = Package(name="busybox", version="1.33.1-r3", ecosystem="apk", distro_version="3.14.2")
    raw = [
        {
            "id": "ALPINE-CVE-2022-28391",
            "summary": "Busybox zlib issue",
            "aliases": [],
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "affected": [
                {
                    "package": {"name": "busybox", "ecosystem": "Alpine:v3.14"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.34.1-r5"}]}],
                }
            ],
        }
    ]
    vulns = build_vulnerabilities(raw, pkg)
    assert len(vulns) == 1
    assert vulns[0].id == "CVE-2022-28391"
    assert vulns[0].match_confidence_tier == MATCH_CONFIDENCE_OSV_RANGE
