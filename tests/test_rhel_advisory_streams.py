"""Bounded RHEL stream regressions; not an ecosystem-wide accuracy estimate."""

import pytest

from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.scanners.osv import ecosystem_matches
from agent_bom.scanners.package_scan import _suppress_unfixed_os_advisories, build_vulnerabilities


def _package(version="2.9.13-3.el9_2.1"):
    return Package(name="libxml2", version=version, ecosystem="rpm", distro_name="rhel", distro_version="9.2")


def _advisory(ecosystem="Red Hat:enterprise_linux:9::baseos", fixed="0:2.9.13-10.el9_6"):
    # Package/range from https://api.osv.dev/v1/vulns/RHSA-2025:10699.
    return {
        "id": "RHSA-2025:10699",
        "summary": "libxml2 security update",
        "affected": [
            {
                "package": {"name": "libxml2", "ecosystem": ecosystem},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
            }
        ],
    }


def test_rhel_fix_is_resolved_and_survives_default_suppression():
    package = _package()
    package.vulnerabilities = build_vulnerabilities([_advisory()], package)
    assert len(package.vulnerabilities) == 1
    assert package.vulnerabilities[0].fixed_version == "0:2.9.13-10.el9_6"
    assert _suppress_unfixed_os_advisories([package]) == 0


def test_already_fixed_rhel_package_is_not_reported():
    assert build_vulnerabilities([_advisory()], _package("0:2.9.13-10.el9_6")) == []


@pytest.mark.parametrize(
    "ecosystem",
    [
        "Red Hat:enterprise_linux:8::baseos",
        "Red Hat:enterprise_linux:10.0",
        "Red Hat:enterprise_linux_eus:9.2::baseos",
        "Red Hat:enterprise_linux_ai:1.5::el9",
        "Red Hat:openshift:4.14::el9",
        "Red Hat:hummingbird:9",
        "Rocky Linux:9",
    ],
)
def test_other_product_streams_are_not_rhel_evidence(ecosystem):
    assert build_vulnerabilities([_advisory(ecosystem)], _package()) == []


def test_other_stream_fix_cannot_replace_applicable_fix():
    advisory = _advisory()
    advisory["affected"].insert(0, _advisory("Red Hat:enterprise_linux:10.0", "0:2.9.13-4.el10")["affected"][0])
    assert build_vulnerabilities([advisory], _package())[0].fixed_version == "0:2.9.13-10.el9_6"


def test_unresolved_rpm_fix_is_not_evidence_of_wont_fix(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_INCLUDE_UNFIXED", raising=False)
    package = _package()
    package.vulnerabilities = [Vulnerability(id="CVE-2026-10000", summary="Fix not resolved", severity=Severity.HIGH)]
    assert _suppress_unfixed_os_advisories([package]) == 0
    assert len(package.vulnerabilities) == 1


def test_rpm_range_comparison_accepts_distro_family_without_accepting_other_languages():
    assert ecosystem_matches("Red Hat:enterprise_linux:9::baseos", "rpm")
    assert not ecosystem_matches("Red Hat:enterprise_linux:9::baseos", "pypi")
