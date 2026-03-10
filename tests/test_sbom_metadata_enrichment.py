"""Tests for SBOM vendor metadata + supply chain enrichment (issue #459).

Covers:
- CycloneDX ingestion: supplier, license, description, author, externalReferences, copyright
- SPDX 2.x ingestion: licenseDeclared, supplier, homepage, downloadLocation, copyrightText
- SPDX 3.0 ingestion: declaredLicense, supplier, description, copyrightText
- CycloneDX output: supplier, author, description, copyright, externalReferences
- SPDX output: supplier, description, homepage, downloadLocation, copyrightText
- JSON output: all 7 new fields
- Package model: new supply chain fields
"""

from agent_bom.models import Package
from agent_bom.sbom import parse_cyclonedx, parse_spdx

# ─── CycloneDX ingestion metadata ──────────────────────────────────────────


def test_cyclonedx_supplier_from_dict():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "express",
                "version": "4.18.2",
                "purl": "pkg:npm/express@4.18.2",
                "supplier": {"name": "OpenJS Foundation"},
            }
        ],
    }
    pkgs = parse_cyclonedx(data)
    assert pkgs[0].supplier == "OpenJS Foundation"


def test_cyclonedx_supplier_from_string():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "lodash",
                "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21",
                "supplier": "John-David Dalton",
            }
        ],
    }
    pkgs = parse_cyclonedx(data)
    assert pkgs[0].supplier == "John-David Dalton"


def test_cyclonedx_manufacturer_fallback():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "react",
                "version": "18.2.0",
                "purl": "pkg:npm/react@18.2.0",
                "manufacturer": {"name": "Meta Platforms"},
            }
        ],
    }
    pkgs = parse_cyclonedx(data)
    assert pkgs[0].supplier == "Meta Platforms"


def test_cyclonedx_author():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "flask",
                "version": "3.0.0",
                "purl": "pkg:pypi/flask@3.0.0",
                "author": "Armin Ronacher",
            }
        ],
    }
    pkgs = parse_cyclonedx(data)
    assert pkgs[0].author == "Armin Ronacher"


def test_cyclonedx_description_truncated():
    long_desc = "A" * 500
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "big-desc",
                "version": "1.0.0",
                "description": long_desc,
            }
        ],
    }
    pkgs = parse_cyclonedx(data)
    assert pkgs[0].description is not None
    assert len(pkgs[0].description) == 300


def test_cyclonedx_license_id():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "mit-pkg",
                "version": "1.0.0",
                "purl": "pkg:npm/mit-pkg@1.0.0",
                "licenses": [
                    {"license": {"id": "MIT"}},
                ],
            }
        ],
    }
    pkgs = parse_cyclonedx(data)
    assert pkgs[0].license == "MIT"
    assert pkgs[0].license_expression == "MIT"


def test_cyclonedx_license_expression():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "dual-lic",
                "version": "1.0.0",
                "licenses": [
                    {"expression": "MIT OR Apache-2.0"},
                ],
            }
        ],
    }
    pkgs = parse_cyclonedx(data)
    assert pkgs[0].license_expression == "MIT OR Apache-2.0"


def test_cyclonedx_multiple_licenses():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "multi-lic",
                "version": "1.0.0",
                "licenses": [
                    {"license": {"id": "MIT"}},
                    {"license": {"id": "ISC"}},
                ],
            }
        ],
    }
    pkgs = parse_cyclonedx(data)
    assert pkgs[0].license == "MIT"
    assert pkgs[0].license_expression == "MIT AND ISC"


def test_cyclonedx_external_references():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "rich-refs",
                "version": "1.0.0",
                "purl": "pkg:pypi/rich-refs@1.0.0",
                "externalReferences": [
                    {"type": "website", "url": "https://example.com"},
                    {"type": "vcs", "url": "https://github.com/example/rich-refs"},
                    {"type": "distribution", "url": "https://cdn.example.com/rich-refs-1.0.0.tar.gz"},
                ],
            }
        ],
    }
    pkgs = parse_cyclonedx(data)
    assert pkgs[0].homepage == "https://example.com"
    assert pkgs[0].repository_url == "https://github.com/example/rich-refs"
    assert pkgs[0].download_url == "https://cdn.example.com/rich-refs-1.0.0.tar.gz"


def test_cyclonedx_copyright():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "copyrighted",
                "version": "1.0.0",
                "copyright": "Copyright 2024 ACME Corp",
            }
        ],
    }
    pkgs = parse_cyclonedx(data)
    assert pkgs[0].copyright_text == "Copyright 2024 ACME Corp"


def test_cyclonedx_full_metadata():
    """End-to-end: component with all metadata fields populated."""
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "full-pkg",
                "version": "2.0.0",
                "purl": "pkg:npm/full-pkg@2.0.0",
                "supplier": {"name": "ACME Inc"},
                "author": "Jane Developer",
                "description": "A fully documented package",
                "copyright": "Copyright 2024 ACME Inc",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "externalReferences": [
                    {"type": "website", "url": "https://acme.com/full-pkg"},
                    {"type": "vcs", "url": "https://github.com/acme/full-pkg"},
                    {"type": "distribution", "url": "https://registry.npmjs.org/full-pkg/-/full-pkg-2.0.0.tgz"},
                ],
            }
        ],
    }
    pkgs = parse_cyclonedx(data)
    p = pkgs[0]
    assert p.name == "full-pkg"
    assert p.version == "2.0.0"
    assert p.ecosystem == "npm"
    assert p.supplier == "ACME Inc"
    assert p.author == "Jane Developer"
    assert p.description == "A fully documented package"
    assert p.copyright_text == "Copyright 2024 ACME Inc"
    assert p.license == "Apache-2.0"
    assert p.homepage == "https://acme.com/full-pkg"
    assert p.repository_url == "https://github.com/acme/full-pkg"
    assert p.download_url == "https://registry.npmjs.org/full-pkg/-/full-pkg-2.0.0.tgz"


# ─── SPDX 2.x ingestion metadata ───────────────────────────────────────────


def test_spdx2_license_declared():
    data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "flask",
                "versionInfo": "3.0.0",
                "licenseDeclared": "BSD-3-Clause",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:pypi/flask@3.0.0"},
                ],
            }
        ],
    }
    pkgs = parse_spdx(data)
    assert pkgs[0].license == "BSD-3-Clause"


def test_spdx2_noassertion_license_filtered():
    data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "unknown-lic",
                "versionInfo": "1.0.0",
                "licenseDeclared": "NOASSERTION",
            }
        ],
    }
    pkgs = parse_spdx(data)
    assert pkgs[0].license is None


def test_spdx2_supplier():
    data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "supplied-pkg",
                "versionInfo": "1.0.0",
                "supplier": "Organization: ACME Corp",
            }
        ],
    }
    pkgs = parse_spdx(data)
    assert pkgs[0].supplier == "Organization: ACME Corp"


def test_spdx2_supplier_noassertion_filtered():
    data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "no-supplier",
                "versionInfo": "1.0.0",
                "supplier": "NOASSERTION",
            }
        ],
    }
    pkgs = parse_spdx(data)
    assert pkgs[0].supplier is None


def test_spdx2_homepage_and_download():
    data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "rich-pkg",
                "versionInfo": "1.0.0",
                "homepage": "https://example.com/rich-pkg",
                "downloadLocation": "https://files.example.com/rich-pkg-1.0.0.tar.gz",
            }
        ],
    }
    pkgs = parse_spdx(data)
    assert pkgs[0].homepage == "https://example.com/rich-pkg"
    assert pkgs[0].download_url == "https://files.example.com/rich-pkg-1.0.0.tar.gz"


def test_spdx2_homepage_noassertion_filtered():
    data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "no-home",
                "versionInfo": "1.0.0",
                "homepage": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
            }
        ],
    }
    pkgs = parse_spdx(data)
    assert pkgs[0].homepage is None
    assert pkgs[0].download_url is None


def test_spdx2_description_and_copyright():
    data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "desc-pkg",
                "versionInfo": "1.0.0",
                "description": "A useful library",
                "copyrightText": "Copyright 2024 Desc Corp",
            }
        ],
    }
    pkgs = parse_spdx(data)
    assert pkgs[0].description == "A useful library"
    assert pkgs[0].copyright_text == "Copyright 2024 Desc Corp"


def test_spdx2_copyright_noassertion_filtered():
    data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "no-copyright",
                "versionInfo": "1.0.0",
                "copyrightText": "NOASSERTION",
            }
        ],
    }
    pkgs = parse_spdx(data)
    assert pkgs[0].copyright_text is None


def test_spdx2_full_metadata():
    """End-to-end: SPDX 2.x package with all metadata fields populated."""
    data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "full-spdx-pkg",
                "versionInfo": "3.0.0",
                "licenseDeclared": "MIT",
                "supplier": "Organization: Full Corp",
                "homepage": "https://fullcorp.com",
                "downloadLocation": "https://cdn.fullcorp.com/pkg-3.0.0.tar.gz",
                "description": "A fully documented SPDX package",
                "copyrightText": "Copyright 2024 Full Corp",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:pypi/full-spdx-pkg@3.0.0"},
                ],
            }
        ],
    }
    pkgs = parse_spdx(data)
    p = pkgs[0]
    assert p.name == "full-spdx-pkg"
    assert p.license == "MIT"
    assert p.supplier == "Organization: Full Corp"
    assert p.homepage == "https://fullcorp.com"
    assert p.download_url == "https://cdn.fullcorp.com/pkg-3.0.0.tar.gz"
    assert p.description == "A fully documented SPDX package"
    assert p.copyright_text == "Copyright 2024 Full Corp"


# ─── SPDX 3.0 ingestion metadata ───────────────────────────────────────────


def test_spdx3_declared_license():
    data = {
        "spdxVersion": "SPDX-3.0",
        "elements": [
            {
                "type": "software/Package",
                "name": "spdx3-pkg",
                "software/packageVersion": "1.0.0",
                "declaredLicense": "Apache-2.0",
            }
        ],
    }
    pkgs = parse_spdx(data)
    assert pkgs[0].license == "Apache-2.0"


def test_spdx3_supplier():
    data = {
        "spdxVersion": "SPDX-3.0",
        "elements": [
            {
                "type": "software/Package",
                "name": "spdx3-supplied",
                "software/packageVersion": "1.0.0",
                "supplier": {"name": "SPDX3 Corp"},
            }
        ],
    }
    pkgs = parse_spdx(data)
    assert pkgs[0].supplier == "SPDX3 Corp"


def test_spdx3_description():
    data = {
        "spdxVersion": "SPDX-3.0",
        "elements": [
            {
                "type": "software/Package",
                "name": "spdx3-desc",
                "software/packageVersion": "1.0.0",
                "description": "An SPDX 3.0 package",
            }
        ],
    }
    pkgs = parse_spdx(data)
    assert pkgs[0].description == "An SPDX 3.0 package"


def test_spdx3_copyright():
    data = {
        "spdxVersion": "SPDX-3.0",
        "elements": [
            {
                "type": "software/Package",
                "name": "spdx3-copy",
                "software/packageVersion": "1.0.0",
                "copyrightText": "Copyright 2024 SPDX3 Corp",
            }
        ],
    }
    pkgs = parse_spdx(data)
    assert pkgs[0].copyright_text == "Copyright 2024 SPDX3 Corp"


# ─── Package model fields ──────────────────────────────────────────────────


def test_package_supply_chain_fields_default_none():
    pkg = Package(name="test", version="1.0.0", ecosystem="npm")
    assert pkg.supplier is None
    assert pkg.author is None
    assert pkg.description is None
    assert pkg.homepage is None
    assert pkg.repository_url is None
    assert pkg.download_url is None
    assert pkg.copyright_text is None


def test_package_supply_chain_fields_populated():
    pkg = Package(
        name="test",
        version="1.0.0",
        ecosystem="npm",
        supplier="ACME",
        author="Jane",
        description="A test package",
        homepage="https://example.com",
        repository_url="https://github.com/acme/test",
        download_url="https://cdn.example.com/test-1.0.0.tgz",
        copyright_text="Copyright 2024 ACME",
    )
    assert pkg.supplier == "ACME"
    assert pkg.author == "Jane"
    assert pkg.description == "A test package"
    assert pkg.homepage == "https://example.com"
    assert pkg.repository_url == "https://github.com/acme/test"
    assert pkg.download_url == "https://cdn.example.com/test-1.0.0.tgz"
    assert pkg.copyright_text == "Copyright 2024 ACME"


# ─── JSON output includes metadata ─────────────────────────────────────────


def test_cyclonedx_roundtrip_metadata():
    """Metadata survives CycloneDX parse → Package → CycloneDX parse cycle."""
    original = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "roundtrip-pkg",
                "version": "1.0.0",
                "purl": "pkg:npm/roundtrip-pkg@1.0.0",
                "supplier": {"name": "RT Corp"},
                "author": "RT Author",
                "description": "Roundtrip test",
                "copyright": "Copyright RT",
                "licenses": [{"license": {"id": "MIT"}}],
                "externalReferences": [
                    {"type": "website", "url": "https://rt.com"},
                    {"type": "vcs", "url": "https://github.com/rt/pkg"},
                ],
            }
        ],
    }
    pkgs = parse_cyclonedx(original)
    p = pkgs[0]

    # Verify all fields survived ingestion
    assert p.supplier == "RT Corp"
    assert p.author == "RT Author"
    assert p.description == "Roundtrip test"
    assert p.copyright_text == "Copyright RT"
    assert p.license == "MIT"
    assert p.homepage == "https://rt.com"
    assert p.repository_url == "https://github.com/rt/pkg"
