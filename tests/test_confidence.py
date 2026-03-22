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
