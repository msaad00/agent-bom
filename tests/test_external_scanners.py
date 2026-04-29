"""Tests for external scanner JSON ingestion (Trivy, Grype, Syft)."""

from __future__ import annotations

import pytest

from agent_bom.models import Severity
from agent_bom.parsers.external_scanners import (
    detect_and_parse,
    parse_grype_json,
    parse_syft_json,
    parse_trivy_json,
)

# ── Trivy fixtures ─────────────────────────────────────────────────────────


TRIVY_BASIC = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-12345",
                    "PkgName": "requests",
                    "InstalledVersion": "2.27.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "HIGH",
                    "Title": "Request smuggling",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"],
                }
            ],
        }
    ]
}

TRIVY_MULTIPLE_ECOSYSTEMS = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-00001",
                    "PkgName": "flask",
                    "InstalledVersion": "1.0.0",
                    "Severity": "MEDIUM",
                }
            ],
        },
        {
            "Target": "package-lock.json",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-00002",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.0",
                    "Severity": "CRITICAL",
                }
            ],
        },
    ]
}

TRIVY_EMPTY: dict[str, list[object]] = {"Results": []}

# ── Grype fixtures ─────────────────────────────────────────────────────────


GRYPE_BASIC = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2023-99999",
                "severity": "High",
                "description": "Remote code execution",
                "fix": {"versions": ["2.31.0"], "state": "fixed"},
                "cvss": [{"metrics": {"baseScore": 8.1}}],
                "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2023-99999"],
            },
            "artifact": {
                "name": "requests",
                "version": "2.27.0",
                "type": "python",
            },
        }
    ]
}

GRYPE_MULTIPLE_TYPES = {
    "matches": [
        {
            "vulnerability": {"id": "CVE-2023-10001", "severity": "Medium"},
            "artifact": {"name": "pkg-a", "version": "1.0.0", "type": "python"},
        },
        {
            "vulnerability": {"id": "CVE-2023-10002", "severity": "Low"},
            "artifact": {"name": "pkg-b", "version": "2.0.0", "type": "go-module"},
        },
    ]
}

GRYPE_EMPTY: dict[str, list[object]] = {"matches": []}

# ── Syft fixtures ──────────────────────────────────────────────────────────


SYFT_BASIC = {
    "schema": {"version": "16.0.0", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.0.json"},
    "artifacts": [
        {
            "name": "requests",
            "version": "2.28.0",
            "type": "python",
            "licenses": [{"value": "Apache-2.0"}],
            "metadata": {"author": "Kenneth Reitz", "summary": "HTTP library"},
        }
    ],
}

SYFT_EMPTY = {
    "schema": {"version": "16.0.0"},
    "artifacts": [],
}

# ── Trivy tests ────────────────────────────────────────────────────────────


def test_parse_trivy_json_basic():
    packages = parse_trivy_json(TRIVY_BASIC)
    assert len(packages) == 1
    pkg = packages[0]
    assert pkg.name == "requests"
    assert pkg.version == "2.27.0"
    assert len(pkg.vulnerabilities) == 1
    vuln = pkg.vulnerabilities[0]
    assert vuln.id == "CVE-2023-12345"
    assert vuln.severity == Severity.HIGH
    assert vuln.summary == "Request smuggling"


def test_parse_trivy_ecosystem_mapping():
    packages = parse_trivy_json(TRIVY_MULTIPLE_ECOSYSTEMS)
    ecosystems = {p.ecosystem for p in packages}
    # pip→pypi, npm→npm
    assert "pypi" in ecosystems
    assert "npm" in ecosystems


def test_parse_trivy_cvss_score():
    packages = parse_trivy_json(TRIVY_BASIC)
    assert packages[0].vulnerabilities[0].cvss_score == 7.5


def test_parse_trivy_fixed_version():
    packages = parse_trivy_json(TRIVY_BASIC)
    assert packages[0].vulnerabilities[0].fixed_version == "2.31.0"


def test_parse_trivy_empty_results():
    packages = parse_trivy_json(TRIVY_EMPTY)
    assert packages == []


def test_parse_trivy_references():
    packages = parse_trivy_json(TRIVY_BASIC)
    refs = packages[0].vulnerabilities[0].references
    assert len(refs) == 1
    assert "CVE-2023-12345" in refs[0]


def test_parse_trivy_ghsa_cvss_fallback():
    """GHSA CVSS score used when NVD is absent."""
    data = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "GHSA-abcd-1234",
                        "PkgName": "mypkg",
                        "InstalledVersion": "1.0",
                        "Severity": "MEDIUM",
                        "CVSS": {"ghsa": {"V3Score": 5.3}},
                    }
                ],
            }
        ]
    }
    packages = parse_trivy_json(data)
    assert packages[0].vulnerabilities[0].cvss_score == 5.3


def test_parse_trivy_preserves_advisory_metadata():
    data = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-11111",
                        "PkgName": "django",
                        "InstalledVersion": "4.2.0",
                        "Severity": "HIGH",
                        "SeveritySource": "ghsa",
                        "Title": "Django advisory",
                        "DataSource": {
                            "ID": "ghsa",
                            "Name": "GitHub Security Advisory pip",
                            "URL": "https://github.com/advisories",
                        },
                        "VendorIDs": ["GHSA-abcd-efgh-ijkl"],
                        "CweIDs": ["CWE-79", "CWE-352"],
                        "PublishedDate": "2024-01-02T03:04:05Z",
                        "LastModifiedDate": "2024-01-03T03:04:05Z",
                    }
                ],
            }
        ]
    }

    packages = parse_trivy_json(data)

    vuln = packages[0].vulnerabilities[0]
    assert vuln.cwe_ids == ["CWE-79", "CWE-352"]
    assert vuln.aliases == ["GHSA-abcd-efgh-ijkl"]
    assert vuln.severity_source == "ghsa"
    assert vuln.published_at == "2024-01-02T03:04:05Z"
    assert vuln.modified_at == "2024-01-03T03:04:05Z"
    assert vuln.advisory_sources == ["ghsa"]


# ── Grype tests ────────────────────────────────────────────────────────────


def test_parse_grype_json_basic():
    packages = parse_grype_json(GRYPE_BASIC)
    assert len(packages) == 1
    pkg = packages[0]
    assert pkg.name == "requests"
    assert pkg.version == "2.27.0"
    assert len(pkg.vulnerabilities) == 1
    vuln = pkg.vulnerabilities[0]
    assert vuln.id == "CVE-2023-99999"
    assert vuln.severity == Severity.HIGH
    assert vuln.summary == "Remote code execution"


def test_parse_grype_ecosystem_mapping():
    packages = parse_grype_json(GRYPE_MULTIPLE_TYPES)
    by_name = {p.name: p for p in packages}
    assert by_name["pkg-a"].ecosystem == "pypi"
    assert by_name["pkg-b"].ecosystem == "go"


def test_parse_grype_fixed_version():
    packages = parse_grype_json(GRYPE_BASIC)
    assert packages[0].vulnerabilities[0].fixed_version == "2.31.0"


def test_parse_grype_empty_matches():
    packages = parse_grype_json(GRYPE_EMPTY)
    assert packages == []


def test_parse_grype_cvss_score():
    packages = parse_grype_json(GRYPE_BASIC)
    assert packages[0].vulnerabilities[0].cvss_score == 8.1


def test_parse_grype_unfixed_no_fixed_version():
    """fix.state != 'fixed' → fixed_version is None."""
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-77777",
                    "severity": "Low",
                    "fix": {"versions": [], "state": "not-fixed"},
                },
                "artifact": {"name": "oldpkg", "version": "0.1.0", "type": "python"},
            }
        ]
    }
    packages = parse_grype_json(data)
    assert packages[0].vulnerabilities[0].fixed_version is None


def test_parse_grype_preserves_advisory_metadata():
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-abcd-efgh-ijkl",
                    "severity": "High",
                    "namespace": "github:language:python",
                    "dataSource": "https://github.com/advisories/GHSA-abcd-efgh-ijkl",
                    "description": "Django advisory",
                    "cwes": ["CWE-79", "CWE-352"],
                    "aliases": ["PYSEC-2024-1"],
                    "relatedVulnerabilities": [
                        {
                            "id": "CVE-2024-22222",
                            "namespace": "nvd:cpe",
                            "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-22222",
                        }
                    ],
                    "publishedDate": "2024-02-02T00:00:00Z",
                    "modifiedDate": "2024-02-03T00:00:00Z",
                },
                "artifact": {
                    "name": "django",
                    "version": "4.2.0",
                    "type": "python",
                },
            }
        ]
    }

    packages = parse_grype_json(data)

    vuln = packages[0].vulnerabilities[0]
    assert vuln.cwe_ids == ["CWE-79", "CWE-352"]
    assert vuln.aliases == ["PYSEC-2024-1", "CVE-2024-22222"]
    assert vuln.severity_source == "github:language:python"
    assert vuln.published_at == "2024-02-02T00:00:00Z"
    assert vuln.modified_at == "2024-02-03T00:00:00Z"
    assert vuln.advisory_sources == ["github:language:python"]


# ── Syft tests ─────────────────────────────────────────────────────────────


def test_parse_syft_json_basic():
    packages = parse_syft_json(SYFT_BASIC)
    assert len(packages) == 1
    pkg = packages[0]
    assert pkg.name == "requests"
    assert pkg.version == "2.28.0"
    assert pkg.ecosystem == "pypi"
    # Syft has no vulns
    assert pkg.vulnerabilities == []
    assert pkg.license == "Apache-2.0"
    assert pkg.author == "Kenneth Reitz"


def test_parse_syft_empty_artifacts():
    packages = parse_syft_json(SYFT_EMPTY)
    assert packages == []


# ── detect_and_parse tests ─────────────────────────────────────────────────


def test_detect_trivy():
    packages = detect_and_parse(TRIVY_BASIC)
    assert len(packages) == 1
    assert packages[0].name == "requests"


def test_detect_grype():
    packages = detect_and_parse(GRYPE_BASIC)
    assert len(packages) == 1
    assert packages[0].name == "requests"


def test_detect_syft():
    packages = detect_and_parse(SYFT_BASIC)
    assert len(packages) == 1
    assert packages[0].name == "requests"


def test_detect_unknown_raises():
    with pytest.raises(ValueError, match="Unrecognized scanner JSON format"):
        detect_and_parse({"foo": "bar"})
