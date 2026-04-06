"""Tests for advisory source attribution and coverage summaries."""

from __future__ import annotations

from agent_bom.advisory_sources import primary_advisory_source, summarize_advisory_coverage
from agent_bom.models import Package, Severity, Vulnerability


def test_vulnerability_derives_all_advisory_sources_from_enrichment_fields() -> None:
    vuln = Vulnerability(
        id="CVE-2026-1000",
        summary="test",
        severity=Severity.HIGH,
        references=[
            "https://github.com/advisories/GHSA-abcd-efgh",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-1000",
        ],
        advisory_sources=["osv"],
        epss_score=0.91,
        is_kev=True,
        nvd_status="ANALYZED",
    )

    assert vuln.all_advisory_sources == ["osv", "ghsa", "nvd", "epss", "cisa_kev"]
    assert vuln.advisory_coverage_state == "enriched"
    assert primary_advisory_source(vuln) == "osv"


def test_summarize_advisory_coverage_counts_primary_and_enrichment_sources() -> None:
    osv_vuln = Vulnerability(
        id="CVE-2026-2000",
        summary="osv vuln",
        severity=Severity.HIGH,
        advisory_sources=["osv"],
        epss_score=0.4,
    )
    ghsa_vuln = Vulnerability(
        id="GHSA-1234-5678",
        summary="ghsa vuln",
        severity=Severity.MEDIUM,
        advisory_sources=["ghsa"],
    )
    pkg = Package(name="demo", version="1.0.0", ecosystem="npm", vulnerabilities=[osv_vuln, ghsa_vuln])

    summary = summarize_advisory_coverage([pkg])

    assert summary["finding_records"] == 2
    assert summary["primary_sources"]["osv"] == 1
    assert summary["primary_sources"]["ghsa"] == 1
    assert summary["enrichment_sources"]["epss"] == 1
    assert summary["records_with_enrichment"] == 1
    assert summary["records_primary_only"] == 1
    assert summary["records_with_multiple_sources"] == 1
