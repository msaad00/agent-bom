"""Tests for external scanner JSON ingestion (Trivy, Grype, Syft, SARIF)."""

from __future__ import annotations

import json

import pytest

from agent_bom.models import Severity
from agent_bom.parsers.external_scanners import (
    detect_and_parse,
    parse_grype_json,
    parse_sarif_json,
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


def test_parse_trivy_confidence_uses_preserved_fields():
    packages = parse_trivy_json(TRIVY_BASIC)
    vuln = packages[0].vulnerabilities[0]

    assert vuln.confidence == pytest.approx(0.35)


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


@pytest.mark.parametrize(
    ("vendor", "score"),
    [
        ("redhat", 6.1),
        ("amazon", 7.0),
        ("oracle", 8.2),
    ],
)
def test_parse_trivy_vendor_cvss_sources(vendor: str, score: float) -> None:
    data = {
        "Results": [
            {
                "Target": "image",
                "Type": "rpm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-99999",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1",
                        "Severity": "HIGH",
                        "CVSS": {vendor: {"V3Score": score}},
                    }
                ],
            }
        ]
    }
    packages = parse_trivy_json(data)
    assert packages[0].vulnerabilities[0].cvss_score == score


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
    assert vuln.confidence == pytest.approx(0.30)


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


def test_parse_grype_confidence_uses_preserved_fields():
    packages = parse_grype_json(GRYPE_BASIC)
    vuln = packages[0].vulnerabilities[0]

    assert vuln.confidence == pytest.approx(0.35)


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
    assert vuln.confidence == pytest.approx(0.30)


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


SARIF_BASIC = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "bandit",
                    "rules": [
                        {
                            "id": "B105",
                            "properties": {"tags": ["CWE-259"]},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "B105",
                    "level": "warning",
                    "message": {"text": "Possible hardcoded password"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/app.py"},
                                "region": {"startLine": 12},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def test_parse_sarif_json_groups_by_file():
    packages = parse_sarif_json(SARIF_BASIC)
    assert len(packages) == 1
    pkg = packages[0]
    assert pkg.ecosystem == "sast"
    assert pkg.name == "src/app.py"
    assert len(pkg.vulnerabilities) == 1
    assert pkg.vulnerabilities[0].id == "B105"
    assert pkg.vulnerabilities[0].cwe_ids == ["CWE-259"]


def test_detect_sarif():
    packages = detect_and_parse(SARIF_BASIC)
    assert len(packages) == 1
    assert packages[0].name == "src/app.py"


# ── Structured external import: SARIF by rule type, SBOM routing ──────────


def _sarif_location(uri: str, line: int) -> list[dict]:
    return [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}]


SARIF_MIXED = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "DepScanner",
                    "rules": [
                        {"id": "CVE-2023-32681", "properties": {"security-severity": "6.1"}},
                        {"id": "GHSA-j8r2-6x86-q33q", "properties": {"security-severity": "7.5"}},
                        {"id": "CVE-2020-14343"},
                        {"id": "PYSEC-2099-1"},
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "CVE-2023-32681",
                    "level": "warning",
                    "message": {"text": "Package: requests\nInstalled Version: 2.25.0\nFixed Version: 2.31.0"},
                    "locations": _sarif_location("requirements.txt", 1),
                },
                {
                    "ruleId": "GHSA-j8r2-6x86-q33q",
                    "level": "error",
                    "message": {"text": "vulnerable dependency found"},
                    "locations": _sarif_location("requirements.txt", 1),
                },
                {
                    "ruleId": "CVE-2020-14343",
                    "level": "error",
                    "message": {"text": "yaml full_load RCE"},
                    "properties": {"purl": "pkg:pypi/pyyaml@5.3"},
                    "locations": _sarif_location("requirements.txt", 2),
                },
                {
                    "ruleId": "PYSEC-2099-1",
                    "level": "error",
                    "message": {"text": "name only"},
                    "properties": {"packageName": "flask"},
                    "locations": _sarif_location("requirements.txt", 3),
                },
            ],
        },
        {
            "tool": {
                "driver": {
                    "name": "CodeScanner",
                    "rules": [
                        {
                            "id": "python.lang.security.audit.subprocess-shell-true",
                            "shortDescription": {"text": "subprocess shell=True"},
                            "properties": {"tags": ["CWE-78: OS Command Injection", "security"]},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python.lang.security.audit.subprocess-shell-true",
                    "level": "error",
                    "message": {"text": "subprocess call with shell=True"},
                    "locations": _sarif_location("app/admin.py", 11),
                }
            ],
        },
    ],
}


def test_ingest_sarif_dependency_result_resolves_real_package_identity():
    from agent_bom.parsers.external_scanners import ingest_external_report

    imported = ingest_external_report(SARIF_MIXED)

    assert imported.format == "sarif"
    by_name = {(p.name, p.version, p.ecosystem): p for p in imported.packages}
    assert ("requests", "2.25.0", "pypi") in by_name
    assert ("pyyaml", "5.3", "pypi") in by_name
    requests_pkg = by_name[("requests", "2.25.0", "pypi")]
    assert [v.id for v in requests_pkg.vulnerabilities] == ["CVE-2023-32681"]
    assert "external:DepScanner" in requests_pkg.vulnerabilities[0].advisory_sources
    assert requests_pkg.vulnerabilities[0].fixed_version == "2.31.0"
    # No invented coordinates anywhere in the package inventory.
    assert all(p.version != "0.0.0" for p in imported.packages)
    assert all(p.ecosystem != "sast" for p in imported.packages)
    assert all("requirements.txt" not in p.name for p in imported.packages)


def test_ingest_sarif_name_only_dependency_keeps_manifest_for_native_resolution():
    from agent_bom.parsers.external_scanners import ingest_external_report

    imported = ingest_external_report(SARIF_MIXED)

    pending = [p for p in imported.packages if p.name == "flask"]
    assert len(pending) == 1
    assert pending[0].version == ""
    assert pending[0].ecosystem == "pypi"
    assert pending[0].version_evidence[0]["source_file"] == "requirements.txt"
    assert [v.id for v in pending[0].vulnerabilities] == ["PYSEC-2099-1"]


def test_ingest_sarif_unresolvable_dependency_is_labelled_finding_not_fake_package():
    from agent_bom.finding import FindingSource, FindingType
    from agent_bom.parsers.external_scanners import ingest_external_report

    imported = ingest_external_report(SARIF_MIXED)

    unresolved = [f for f in imported.findings if f.finding_type is FindingType.CVE]
    assert len(unresolved) == 1
    finding = unresolved[0]
    assert finding.cve_id == "GHSA-j8r2-6x86-q33q"
    assert finding.source is FindingSource.EXTERNAL
    assert finding.sources == ["external:DepScanner"]
    assert finding.evidence["package_resolution"] == "unresolved"
    assert finding.asset.location == "requirements.txt"
    assert "0.0.0" not in finding.title
    assert "0.0.0" not in (finding.asset.identifier or "")
    assert not any(v.id == "GHSA-j8r2-6x86-q33q" for p in imported.packages for v in p.vulnerabilities)


def test_ingest_sarif_code_result_stays_sast_with_file_and_line():
    from agent_bom.finding import FindingSource, FindingType
    from agent_bom.parsers.external_scanners import ingest_external_report

    imported = ingest_external_report(SARIF_MIXED)

    code = [f for f in imported.findings if f.finding_type is FindingType.SAST]
    assert len(code) == 1
    finding = code[0]
    assert finding.source is FindingSource.EXTERNAL
    assert finding.cve_id is None
    assert finding.cwe_ids == ["CWE-78"]
    assert finding.asset.location == "app/admin.py"
    assert finding.evidence["line"] == 11
    assert finding.evidence["rule_id"] == "python.lang.security.audit.subprocess-shell-true"
    assert finding.sources == ["external:CodeScanner"]
    assert imported.tool_names == ["DepScanner", "CodeScanner"]


def test_detect_and_parse_sarif_dependency_result_resolves_package():
    packages = detect_and_parse(SARIF_MIXED)

    names = {(p.name, p.version, p.ecosystem) for p in packages}
    assert ("requests", "2.25.0", "pypi") in names
    assert not any(v.id == "CVE-2023-32681" for p in packages if p.ecosystem == "sast" for v in p.vulnerabilities)


CYCLONEDX_SBOM_PLAIN = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"tools": [{"name": "sbom-generator"}]},
    "components": [
        {"type": "library", "name": "requests", "version": "2.25.0", "purl": "pkg:pypi/requests@2.25.0", "bom-ref": "r1"},
    ],
}

CYCLONEDX_VDR = {
    **CYCLONEDX_SBOM_PLAIN,
    "vulnerabilities": [
        {
            "id": "CVE-2023-32681",
            "ratings": [{"severity": "medium", "score": 6.1}],
            "affects": [{"ref": "r1"}],
        }
    ],
}


def test_detect_and_parse_accepts_plain_cyclonedx_sbom():
    packages = detect_and_parse(CYCLONEDX_SBOM_PLAIN)

    assert [(p.name, p.version, p.ecosystem) for p in packages] == [("requests", "2.25.0", "pypi")]
    assert packages[0].vulnerabilities == []


def test_ingest_plain_cyclonedx_sbom_routes_as_sbom_inventory():
    from agent_bom.parsers.external_scanners import ingest_external_report

    imported = ingest_external_report(CYCLONEDX_SBOM_PLAIN)

    assert imported.format == "cyclonedx"
    assert imported.is_sbom is True
    assert any("--sbom" in notice for notice in imported.notices)


def test_ingest_cyclonedx_with_vulnerabilities_imports_them_labelled():
    from agent_bom.parsers.external_scanners import ingest_external_report

    imported = ingest_external_report(CYCLONEDX_VDR)

    assert imported.format == "cyclonedx"
    assert imported.is_sbom is False
    [pkg] = imported.packages
    assert (pkg.name, pkg.version) == ("requests", "2.25.0")
    assert [v.id for v in pkg.vulnerabilities] == ["CVE-2023-32681"]
    assert "external:sbom-generator" in pkg.vulnerabilities[0].advisory_sources


def test_detect_and_parse_accepts_spdx_document():
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "fixture",
        "packages": [
            {
                "SPDXID": "SPDXRef-requests",
                "name": "requests",
                "versionInfo": "2.25.0",
                "externalRefs": [
                    {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.25.0"}
                ],
            }
        ],
    }

    packages = detect_and_parse(spdx)

    assert [(p.name, p.version) for p in packages] == [("requests", "2.25.0")]


def test_detect_unknown_error_names_supported_formats():
    with pytest.raises(ValueError, match="SARIF"):
        detect_and_parse({"foo": "bar"})


# ── Folding external evidence into native inventory ──────────────────────


def _native_agent(packages):
    from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface

    server = MCPServer(name="proj", surface=ServerSurface.SBOM, packages=packages)
    return Agent(name="project:proj", agent_type=AgentType.CUSTOM, config_path="/proj", mcp_servers=[server])


def _manifest_pkg(name, version, manifest="/abs/proj/requirements.txt"):
    from agent_bom.models import Package

    return Package(
        name=name,
        version=version,
        ecosystem="pypi",
        version_evidence=[{"type": "manifest", "source_file": manifest, "line": 1}],
    )


def test_fold_external_packages_moves_vulns_onto_native_package_and_drops_duplicate():
    from agent_bom.parsers.external_import import build_external_agent, fold_external_packages
    from agent_bom.parsers.external_scanners import ingest_external_report

    native_requests = _manifest_pkg("requests", "2.25.0")
    native_flask = _manifest_pkg("flask", "2.2.0")
    native_pyyaml = _manifest_pkg("PyYAML", "5.3")
    native = _native_agent([native_requests, native_flask, native_pyyaml])
    imported = ingest_external_report(SARIF_MIXED)
    external = build_external_agent(imported, "ext.sarif")

    notices = fold_external_packages([native, external])

    assert external.mcp_servers[0].packages == []
    assert [v.id for v in native_requests.vulnerabilities] == ["CVE-2023-32681"]
    assert native_requests.vulnerabilities[0].advisory_sources == ["external:DepScanner"]
    assert [v.id for v in native_pyyaml.vulnerabilities] == ["CVE-2020-14343"]
    # Name-only result resolves against the native package from the same manifest.
    assert [v.id for v in native_flask.vulnerabilities] == ["PYSEC-2099-1"]
    assert notices == []


def test_fold_keeps_external_only_package_and_reports_unresolvable_name_only_result():
    from agent_bom.parsers.external_import import build_external_agent, fold_external_packages
    from agent_bom.finding import FindingType
    from agent_bom.parsers.external_scanners import ingest_external_report

    native = _native_agent([_manifest_pkg("requests", "2.25.0")])
    imported = ingest_external_report(SARIF_MIXED)
    external = build_external_agent(imported, "ext.sarif")

    notices = fold_external_packages([native, external], findings=imported.findings)

    remaining = {(p.name, p.version) for p in external.mcp_servers[0].packages}
    # pyyaml was only seen by the external scanner: it stays as a real package.
    assert remaining == {("pyyaml", "5.3")}
    # flask had no version and no native match: never invented, surfaced instead.
    assert any("flask" in notice and "PYSEC-2099-1" in notice for notice in notices)
    unresolved_ids = {f.cve_id for f in imported.findings if f.finding_type is FindingType.CVE}
    assert unresolved_ids == {"GHSA-j8r2-6x86-q33q", "PYSEC-2099-1"}


def test_osv_merge_prefers_native_record_but_keeps_external_label():
    from agent_bom.models import Package, Severity, Vulnerability
    from agent_bom.scanners.package_scan import merge_scanner_vulnerabilities

    pkg = Package(name="requests", version="2.25.0", ecosystem="pypi")
    pkg.vulnerabilities.append(
        Vulnerability(id="CVE-2023-32681", summary="ext", severity=Severity.MEDIUM, advisory_sources=["external:DepScanner"])
    )
    osv = Vulnerability(
        id="CVE-2023-32681",
        summary="osv",
        severity=Severity.MEDIUM,
        cvss_score=6.1,
        fixed_version="2.31.0",
        advisory_sources=["osv"],
    )
    other = Vulnerability(id="CVE-2024-35195", summary="osv", severity=Severity.MEDIUM, advisory_sources=["osv"])

    added = merge_scanner_vulnerabilities(pkg, [osv, other])

    assert [v.id for v in added] == ["CVE-2024-35195"]
    assert [v.id for v in pkg.vulnerabilities] == ["CVE-2023-32681", "CVE-2024-35195"]
    merged = pkg.vulnerabilities[0]
    assert merged.summary == "osv"
    assert merged.fixed_version == "2.31.0"
    assert set(merged.advisory_sources) == {"osv", "external:DepScanner"}


# ── Finding source labels ────────────────────────────────────────────────


def _br(servers, vuln):
    from agent_bom.models import Agent, AgentType, BlastRadius, Package

    pkg = Package(name="requests", version="2.25.0", ecosystem="pypi", vulnerabilities=[vuln])
    agent = Agent(name="a", agent_type=AgentType.CUSTOM, config_path="/p", mcp_servers=servers)
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=servers,
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )


def test_blast_radius_finding_keeps_native_source_and_both_labels():
    from agent_bom.finding import FindingSource, blast_radius_to_finding
    from agent_bom.models import MCPServer, ServerSurface, Vulnerability

    vuln = Vulnerability(id="CVE-2023-32681", summary="x", severity=Severity.MEDIUM, advisory_sources=["osv", "external:DepScanner"])
    finding = blast_radius_to_finding(_br([MCPServer(name="proj", surface=ServerSurface.SBOM)], vuln))

    assert finding.source is FindingSource.SBOM
    assert finding.sources == ["native", "external:DepScanner"]
    assert finding.to_dict()["sources"] == ["native", "external:DepScanner"]


def test_blast_radius_finding_mixed_surfaces_is_not_relabelled_external():
    from agent_bom.finding import FindingSource, blast_radius_to_finding
    from agent_bom.models import MCPServer, ServerSurface, Vulnerability

    vuln = Vulnerability(id="CVE-2023-32681", summary="x", severity=Severity.MEDIUM, advisory_sources=["osv"])
    servers = [MCPServer(name="proj", surface=ServerSurface.SBOM), MCPServer(name="ext", surface=ServerSurface.EXTERNAL_SCAN)]
    finding = blast_radius_to_finding(_br(servers, vuln))

    assert finding.source is FindingSource.SBOM
    assert finding.sources == ["native", "external"]


def test_blast_radius_finding_external_only_package_is_external():
    from agent_bom.finding import FindingSource, blast_radius_to_finding
    from agent_bom.models import MCPServer, ServerSurface, Vulnerability

    vuln = Vulnerability(id="CVE-2020-14343", summary="x", severity=Severity.HIGH, advisory_sources=["external:DepScanner"])
    server = MCPServer(name="ext", surface=ServerSurface.EXTERNAL_SCAN)
    finding = blast_radius_to_finding(_br([server], vuln))

    assert finding.source is FindingSource.EXTERNAL
    assert finding.sources == ["external:DepScanner"]


def test_blast_radius_finding_native_only_has_no_sources_field():
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.models import MCPServer, ServerSurface, Vulnerability

    vuln = Vulnerability(id="CVE-2023-32681", summary="x", severity=Severity.MEDIUM, advisory_sources=["osv"])
    finding = blast_radius_to_finding(_br([MCPServer(name="proj", surface=ServerSurface.SBOM)], vuln))

    assert finding.sources == []
    assert "sources" not in finding.to_dict()


def _report_with_native_ast_flow(line: int):
    from agent_bom.models import AIBOMReport

    report = AIBOMReport(agents=[], blast_radii=[])
    report.ai_inventory_data = {
        "ast_analysis": {
            "flow_findings": [
                {
                    "category": "tainted_command_execution",
                    "file": "app/admin.py",
                    "line": line,
                    "entrypoint": "run",
                    "sink": "subprocess.check_output",
                    "title": "Untrusted data reaches shell command execution",
                }
            ]
        }
    }
    return report


def test_external_sast_merges_with_native_sast_at_same_file_line():
    from agent_bom.finding import FindingSource, FindingType
    from agent_bom.parsers.external_scanners import ingest_external_report

    report = _report_with_native_ast_flow(11)
    report.findings.extend(ingest_external_report(SARIF_MIXED).findings)

    sast = [f for f in report.to_findings() if f.finding_type is FindingType.SAST]

    assert len(sast) == 1
    assert sast[0].source is FindingSource.SAST
    assert sast[0].sources == ["native", "external:CodeScanner"]
    assert sast[0].evidence["external_matches"][0]["rule_id"] == "python.lang.security.audit.subprocess-shell-true"


def test_sarif_output_carries_unresolved_external_advisory_and_external_sast():
    from agent_bom.models import AIBOMReport
    from agent_bom.output.sarif import to_sarif
    from agent_bom.parsers.external_scanners import ingest_external_report

    report = AIBOMReport(agents=[], blast_radii=[])
    report.findings.extend(ingest_external_report(SARIF_MIXED).findings)

    sarif = to_sarif(report)
    texts = json.dumps(sarif)

    assert "GHSA-j8r2-6x86-q33q" in texts
    assert "python.lang.security.audit.subprocess-shell-true" in texts or "subprocess shell=True" in texts
    assert "@0.0.0" not in texts


def test_external_sast_without_native_match_stays_external_sast():
    from agent_bom.finding import FindingSource, FindingType
    from agent_bom.parsers.external_scanners import ingest_external_report

    report = _report_with_native_ast_flow(42)
    report.findings.extend(ingest_external_report(SARIF_MIXED).findings)

    sast = [f for f in report.to_findings() if f.finding_type is FindingType.SAST]

    assert len(sast) == 2
    external = [f for f in sast if f.source is FindingSource.EXTERNAL]
    assert len(external) == 1
    assert external[0].sources == ["external:CodeScanner"]
