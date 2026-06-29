"""Tests for SBOM ingestion module (CycloneDX + SPDX parsing)."""

import json

import pytest

from agent_bom.sbom import (
    _ecosystem_from_purl,
    _ecosystem_from_type,
    load_sbom,
    parse_cyclonedx,
    parse_sbom_document,
    parse_spdx,
)

# ─── _ecosystem_from_purl ────────────────────────────────────────────────────


def test_ecosystem_from_purl_npm():
    assert _ecosystem_from_purl("pkg:npm/express@4.17.1") == "npm"


def test_ecosystem_from_purl_pypi():
    assert _ecosystem_from_purl("pkg:pypi/requests@2.28.0") == "pypi"


def test_ecosystem_from_purl_golang_alias():
    assert _ecosystem_from_purl("pkg:golang/github.com/x/y@v1") == "go"


def test_ecosystem_from_purl_scanner_aliases():
    assert _ecosystem_from_purl("pkg:gem/rails@7.1.3") == "rubygems"
    assert _ecosystem_from_purl("pkg:rubygems/rack@3.0.8") == "rubygems"
    assert _ecosystem_from_purl("pkg:composer/symfony/console@7.0.4") == "composer"
    assert _ecosystem_from_purl("pkg:hex/decimal@2.1.1") == "hex"
    assert _ecosystem_from_purl("pkg:pub/path@1.9.0") == "pub"


def test_ecosystem_from_purl_empty():
    assert _ecosystem_from_purl("") == "unknown"


# ─── _ecosystem_from_type ────────────────────────────────────────────────────


def test_ecosystem_from_type_npm():
    assert _ecosystem_from_type("npm") == "npm"


def test_ecosystem_from_type_gem():
    assert _ecosystem_from_type("gem") == "rubygems"


def test_ecosystem_from_type_scanner_aliases():
    assert _ecosystem_from_type("composer") == "composer"
    assert _ecosystem_from_type("hex") == "hex"
    assert _ecosystem_from_type("pub") == "pub"


# ─── parse_cyclonedx ─────────────────────────────────────────────────────────


def test_parse_cyclonedx_with_purl():
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "express",
                "version": "4.18.2",
                "purl": "pkg:npm/express@4.18.2",
            },
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
            },
        ],
    }
    packages = parse_cyclonedx(data)
    assert len(packages) == 2
    assert packages[0].name == "express"
    assert packages[0].version == "4.18.2"
    assert packages[0].ecosystem == "npm"
    assert packages[0].purl == "pkg:npm/express@4.18.2"
    assert packages[0].is_direct is True
    assert packages[0].resolved_from_registry is False
    assert packages[1].name == "requests"
    assert packages[1].ecosystem == "pypi"


def test_parse_cyclonedx_preserves_scanner_ecosystems_from_purl():
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "rails",
                "version": "7.1.3",
                "purl": "pkg:gem/rails@7.1.3",
            },
            {
                "type": "library",
                "name": "symfony/console",
                "version": "7.0.4",
                "purl": "pkg:composer/symfony/console@7.0.4",
            },
            {
                "type": "library",
                "name": "decimal",
                "version": "2.1.1",
                "purl": "pkg:hex/decimal@2.1.1",
            },
            {
                "type": "library",
                "name": "path",
                "version": "1.9.0",
                "purl": "pkg:pub/path@1.9.0",
            },
        ],
    }
    packages = parse_cyclonedx(data)
    assert [(pkg.name, pkg.ecosystem) for pkg in packages] == [
        ("rails", "rubygems"),
        ("symfony/console", "composer"),
        ("decimal", "hex"),
        ("path", "pub"),
    ]


def test_parse_cyclonedx_without_purl():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "npm",
                "name": "lodash",
                "version": "4.17.21",
            },
            {
                "type": "library",
                "name": "some-lib",
                "version": "1.0.0",
            },
        ],
    }
    packages = parse_cyclonedx(data)
    assert len(packages) == 2
    # npm type maps directly
    assert packages[0].name == "lodash"
    assert packages[0].ecosystem == "npm"
    assert packages[0].purl is None
    # "library" type falls through to "unknown"
    assert packages[1].name == "some-lib"
    assert packages[1].ecosystem == "unknown"


def test_parse_cyclonedx_skip_empty_name():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {"type": "library", "name": "", "version": "1.0.0"},
            {"type": "library", "name": "valid-pkg", "version": "2.0.0"},
        ],
    }
    packages = parse_cyclonedx(data)
    assert len(packages) == 1
    assert packages[0].name == "valid-pkg"


# ─── parse_spdx ──────────────────────────────────────────────────────────────


def test_parse_spdx_2x():
    data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "flask",
                "versionInfo": "3.0.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/flask@3.0.0",
                    }
                ],
            },
            {
                "name": "click",
                "versionInfo": "8.1.7",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/click@8.1.7",
                    }
                ],
            },
        ],
    }
    packages = parse_spdx(data)
    assert len(packages) == 2
    assert packages[0].name == "flask"
    assert packages[0].version == "3.0.0"
    assert packages[0].ecosystem == "pypi"
    assert packages[0].purl == "pkg:pypi/flask@3.0.0"
    assert packages[1].name == "click"
    assert packages[1].ecosystem == "pypi"


def test_parse_spdx_3():
    data = {
        "spdxVersion": "SPDX-3.0",
        "elements": [
            {
                "type": "software/Package",
                "name": "serde",
                "software/packageVersion": "1.0.195",
                "software/packageUrl": "pkg:cargo/serde@1.0.195",
            },
            {
                "type": "Relationship",
                "name": "depends-on",
            },
            {
                "type": "SOFTWARE_PACKAGE",
                "name": "tokio",
                "packageVersion": "1.35.0",
                "externalIdentifier": {
                    "identifier": "pkg:cargo/tokio@1.35.0",
                },
            },
        ],
    }
    packages = parse_spdx(data)
    assert len(packages) == 2
    assert packages[0].name == "serde"
    assert packages[0].version == "1.0.195"
    assert packages[0].ecosystem == "cargo"
    assert packages[0].purl == "pkg:cargo/serde@1.0.195"
    assert packages[1].name == "tokio"
    assert packages[1].version == "1.35.0"
    assert packages[1].ecosystem == "cargo"


# ─── load_sbom ────────────────────────────────────────────────────────────────


def test_load_sbom_autodetect_cyclonedx(tmp_path):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "axios",
                "version": "1.6.0",
                "purl": "pkg:npm/axios@1.6.0",
            }
        ],
    }
    path = tmp_path / "cdx.json"
    path.write_text(json.dumps(sbom))

    packages, fmt, _name = load_sbom(str(path))
    assert fmt == "cyclonedx"
    assert len(packages) == 1
    assert packages[0].name == "axios"
    assert packages[0].ecosystem == "npm"


def test_load_sbom_rejects_agent_bom_report(tmp_path):
    report = {"ai_bom_version": "0.30.0", "agents": []}
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))

    with pytest.raises(ValueError, match="agent-bom report"):
        load_sbom(str(path))


def test_parse_sbom_document_rejects_agent_bom_report():
    with pytest.raises(ValueError, match="agent-bom report"):
        parse_sbom_document({"ai_bom_version": "0.75.15", "blast_radius": []})


def test_load_sbom_unknown_format(tmp_path):
    data = {"random_key": "random_value"}
    path = tmp_path / "mystery.json"
    path.write_text(json.dumps(data))

    with pytest.raises(ValueError, match="Unrecognised SBOM format"):
        load_sbom(str(path))


def test_parse_sbom_document_autodetects_spdx_2():
    data = {
        "spdxVersion": "SPDX-2.3",
        "name": "DOCUMENT-prod-api-01",
        "packages": [
            {
                "name": "flask",
                "versionInfo": "3.0.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/flask@3.0.0",
                    }
                ],
            }
        ],
    }
    packages, fmt, resource_name = parse_sbom_document(data, source_name="memory.json")
    assert fmt == "spdx-2"
    assert resource_name == "prod-api-01"
    assert len(packages) == 1
    assert packages[0].name == "flask"


def test_load_sbom_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_sbom("/nonexistent/path/sbom.json")


# ─── SPDX 3.0 round-trip (emit → ingest) ──────────────────────────────────────


def _round_trip_report():
    from datetime import datetime, timezone

    from agent_bom.models import (
        Agent,
        AgentStatus,
        AgentType,
        AIBOMReport,
        MCPServer,
        Package,
        Severity,
        TransportType,
        Vulnerability,
    )

    pkg = Package(
        name="requests",
        version="2.28.0",
        ecosystem="pypi",
        purl="pkg:pypi/requests@2.28.0",
        license="Apache-2.0",
        supplier="PSF",
        description="HTTP for humans",
        homepage="https://requests.dev",
        is_direct=True,
    )
    pkg2 = Package(
        name="urllib3",
        version="1.26.0",
        ecosystem="pypi",
        purl="pkg:pypi/urllib3@1.26.0",
        is_direct=False,
    )
    pkg.vulnerabilities.append(
        Vulnerability(
            id="CVE-2023-1234",
            summary="boom",
            severity=Severity.HIGH,
            cvss_score=7.5,
            fixed_version="2.31.0",
            is_kev=True,
            epss_score=0.42,
            cwe_ids=["CWE-79"],
        )
    )
    server = MCPServer(name="srv1", command="x", transport=TransportType.STDIO, packages=[pkg, pkg2])
    agent = Agent(
        name="agent1",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/c.json",
        status=AgentStatus.CONFIGURED,
        mcp_servers=[server],
    )
    return AIBOMReport(
        agents=[agent],
        blast_radii=[],
        generated_at=datetime.now(timezone.utc),
        scan_id="rt",
        tool_version="0.0.0-test",
    )


def test_spdx_round_trip_preserves_packages():
    from agent_bom.output.spdx_fmt import to_spdx

    report = _round_trip_report()
    spdx = to_spdx(report)
    packages = parse_spdx(spdx)

    # Agents and MCP servers (APPLICATION purpose) must NOT be ingested as packages.
    by_name = {p.name: p for p in packages}
    assert set(by_name) == {"requests", "urllib3"}

    # name + version + purl + ecosystem survive for every package (set equality).
    emitted = {
        ("requests", "2.28.0", "pkg:pypi/requests@2.28.0", "pypi"),
        ("urllib3", "1.26.0", "pkg:pypi/urllib3@1.26.0", "pypi"),
    }
    assert {(p.name, p.version, p.purl, p.ecosystem) for p in packages} == emitted

    # Supply-chain metadata survives.
    requests_pkg = by_name["requests"]
    assert requests_pkg.license == "Apache-2.0"
    assert requests_pkg.supplier == "PSF"
    assert requests_pkg.homepage == "https://requests.dev"


def test_spdx_round_trip_preserves_vulnerability_assessments():
    from agent_bom.models import Severity
    from agent_bom.output.spdx_fmt import to_spdx

    report = _round_trip_report()
    packages = parse_spdx(to_spdx(report))
    requests_pkg = next(p for p in packages if p.name == "requests")

    assert len(requests_pkg.vulnerabilities) == 1
    vuln = requests_pkg.vulnerabilities[0]
    assert vuln.id == "CVE-2023-1234"
    assert vuln.severity == Severity.HIGH
    assert vuln.cvss_score == 7.5
    assert vuln.fixed_version == "2.31.0"
    assert vuln.is_kev is True
    assert vuln.epss_score == 0.42
    assert vuln.cwe_ids == ["CWE-79"]


def test_spdx_round_trip_via_parse_sbom_document():
    from agent_bom.output.spdx_fmt import to_spdx

    report = _round_trip_report()
    packages, fmt, _name = parse_sbom_document(to_spdx(report))
    assert fmt == "spdx-3"
    assert {p.name for p in packages} == {"requests", "urllib3"}


def test_parse_spdx3_external_identifier_list():
    """agent-bom emits externalIdentifier as a list — must not crash."""
    data = {
        "spdxVersion": "SPDX-3.0",
        "elements": [
            {
                "type": "SOFTWARE_PACKAGE",
                "spdxId": "SPDXRef-Pkg-1",
                "name": "lodash",
                "versionInfo": "4.17.21",
                "primaryPurpose": "LIBRARY",
                "externalIdentifier": [{"type": "PackageURL", "identifier": "pkg:npm/lodash@4.17.21"}],
            }
        ],
    }
    packages = parse_spdx(data)
    assert len(packages) == 1
    assert packages[0].name == "lodash"
    assert packages[0].version == "4.17.21"
    assert packages[0].purl == "pkg:npm/lodash@4.17.21"
    assert packages[0].ecosystem == "npm"


def test_parse_spdx3_minimal_external_document_no_crash():
    """A minimal hand-written third-party SPDX 3.0 doc extracts packages and does not crash."""
    data = {
        "spdxVersion": "SPDX-3.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "elements": [
            {
                "type": "software/Package",
                "spdxId": "SPDXRef-a",
                "name": "openssl",
                "software/packageVersion": "3.0.0",
                "software/packageUrl": "pkg:generic/openssl@3.0.0",
                # Fields agent-bom never emits — must be tolerated.
                "verifiedUsing": [{"algorithm": "sha256", "hashValue": "deadbeef"}],
                "builtTime": "2024-01-01T00:00:00Z",
            },
            {"type": "Person", "spdxId": "SPDXRef-author", "name": "Some Maintainer"},
        ],
    }
    packages = parse_spdx(data)
    assert len(packages) == 1
    assert packages[0].name == "openssl"
    assert packages[0].version == "3.0.0"
