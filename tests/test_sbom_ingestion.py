"""Tests for SBOM ingestion module (CycloneDX + SPDX parsing)."""

import json

import pytest

from agent_bom.sbom import (
    _ecosystem_from_purl,
    _ecosystem_from_type,
    load_sbom,
    parse_cyclonedx,
    parse_spdx,
)

# ─── _ecosystem_from_purl ────────────────────────────────────────────────────


def test_ecosystem_from_purl_npm():
    assert _ecosystem_from_purl("pkg:npm/express@4.17.1") == "npm"


def test_ecosystem_from_purl_pypi():
    assert _ecosystem_from_purl("pkg:pypi/requests@2.28.0") == "pypi"


def test_ecosystem_from_purl_golang_alias():
    assert _ecosystem_from_purl("pkg:golang/github.com/x/y@v1") == "go"


def test_ecosystem_from_purl_empty():
    assert _ecosystem_from_purl("") == "unknown"


# ─── _ecosystem_from_type ────────────────────────────────────────────────────


def test_ecosystem_from_type_npm():
    assert _ecosystem_from_type("npm") == "npm"


def test_ecosystem_from_type_gem():
    assert _ecosystem_from_type("gem") == "ruby"


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

    packages, fmt = load_sbom(str(path))
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


def test_load_sbom_unknown_format(tmp_path):
    data = {"random_key": "random_value"}
    path = tmp_path / "mystery.json"
    path.write_text(json.dumps(data))

    with pytest.raises(ValueError, match="Unrecognised SBOM format"):
        load_sbom(str(path))


def test_load_sbom_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_sbom("/nonexistent/path/sbom.json")
