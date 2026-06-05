"""Test vulnerability confidence scoring."""

from agent_bom.models import Severity, Vulnerability, compute_confidence


def test_full_data_high_confidence():
    v = Vulnerability(
        id="CVE-2024-1234",
        summary="test vuln",
        severity=Severity.HIGH,
        cvss_score=8.5,
        epss_score=0.5,
        severity_source="cvss",
        fixed_version="2.0.0",
    )
    c = compute_confidence(v)
    assert c >= 0.7


def test_minimal_data_low_confidence():
    v = Vulnerability(
        id="CVE-2024-1234",
        summary="unknown vuln",
        severity=Severity.UNKNOWN,
    )
    c = compute_confidence(v)
    assert c <= 0.3


def test_confidence_capped_at_1():
    v = Vulnerability(
        id="CVE-2024-1234",
        summary="critical vuln",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        epss_score=0.95,
        severity_source="cvss",
        fixed_version="3.0",
        cwe_ids=["CWE-79"],
        is_kev=True,
    )
    c = compute_confidence(v)
    assert c <= 1.0


def test_enrichment_pass_populates_confidence_on_native_findings():
    """The enrichment pass sets confidence on native (OSV/GHSA) findings, so a
    finding's trustworthiness no longer depends on whether it came from an
    external scanner."""
    import asyncio

    from agent_bom import enrichment

    rich = Vulnerability(
        id="CVE-2024-1234",
        summary="rich",
        severity=Severity.HIGH,
        cvss_score=8.5,
        epss_score=0.5,
        severity_source="cvss",
        fixed_version="2.0.0",
    )
    minimal = Vulnerability(id="CVE-2024-5678", summary="minimal", severity=Severity.UNKNOWN)
    assert rich.confidence is None and minimal.confidence is None

    # Offline + all external fetches disabled: the pass does nothing but finalize
    # confidence, so the assertion is deterministic and network-free.
    asyncio.run(enrichment.enrich_vulnerabilities([rich, minimal], enable_nvd=False, enable_epss=False, enable_kev=False, offline=True))
    assert rich.confidence is not None and minimal.confidence is not None
    assert rich.confidence > minimal.confidence


def test_enrichment_populates_confidence_for_non_cve_findings():
    """Findings with no CVE id (e.g. malware/GHSA-only) still get confidence."""
    import asyncio

    from agent_bom import enrichment

    mal = Vulnerability(id="MAL-2024-0003", summary="malware", severity=Severity.HIGH, severity_source="osv")
    asyncio.run(enrichment.enrich_vulnerabilities([mal], offline=True))
    assert mal.confidence is not None
