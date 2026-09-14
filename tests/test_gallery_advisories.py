"""Published CVE and simulated workload boundaries for product screenshots."""

import json
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet

ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / "ui/fixtures/gallery-advisories.json").read_text())


@pytest.mark.parametrize("advisory", CATALOG["advisories"], ids=lambda row: row["id"])
def test_gallery_versions_are_in_the_published_affected_range(advisory):
    bounds = SpecifierSet(advisory["affected_range"])
    assert advisory["version"] in bounds
    assert advisory["fixed_version"] not in bounds
    assert advisory["reference"].startswith("https://github.com/advisories/GHSA-")
    assert advisory["id"].startswith("CVE-")
    assert advisory["precondition"]
    assert advisory["cvss_vector"].startswith(("CVSS:3.", "CVSS:4."))
    assert 0 < advisory["cvss_score"] <= 10


def test_gallery_uses_published_advisories_without_fabricated_identifiers():
    capture = (ROOT / "ui/scripts/capture-product-proof.mjs").read_text()
    assert "DEMO-VULN-" not in capture
    assert "urn:agent-bom:demo:" not in capture
    assert "checkAdvisoryFixtures();" in capture
    assert "simulated" in CATALOG["evidence"]
    assert len({row["id"] for row in CATALOG["advisories"]}) == len(CATALOG["advisories"])
