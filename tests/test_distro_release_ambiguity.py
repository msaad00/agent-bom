"""An unspecified distro release must not masquerade as a confident match.

``-e apk`` / ``-e deb`` with no release metadata fans the OSV query out across
every supported release branch (10 Alpine branches, 4 Debian releases). That is
deliberate — narrowing to one branch would silently drop true positives for
every other branch, and a scanner that under-reports is worse than one that
over-reports. But the union was previously indistinguishable from a confirmed
single-release match:

* no ``scan_warnings`` naming the ambiguity,
* full ``osv_range`` match confidence, and
* a ``fixed_version`` taken from whichever branch happened to match — telling a
  user on the 3.0.x branch to "upgrade to 3.5.7-r0" (the v3.23 branch).

Measured against live OSV on 2026-08-01: ``openssl@3.0.11-r0 -e apk`` reported
58 advisories where ``Alpine:v3.18`` carries 19, and recommended ``3.5.7-r0``.
"""

from __future__ import annotations

import pytest

from agent_bom.models import Package
from agent_bom.scanners.package_scan import build_vulnerabilities
from agent_bom.scanners.state import consume_scan_warnings, reset_scan_warnings

AMBIGUOUS_TIER = "ambiguous_distro_release"


@pytest.fixture(autouse=True)
def _clean_warnings():
    reset_scan_warnings()
    yield
    reset_scan_warnings()


def _alpine_openssl_advisory() -> dict:
    """Shape copied from live OSV ``ALPINE-CVE-2023-5363`` (Alpine:v3.18)."""
    return {
        "id": "ALPINE-CVE-2023-5363",
        "summary": "openssl vulnerability",
        "aliases": ["CVE-2023-5363"],
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": "Alpine:v3.18"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.4-r0"}]}],
            }
        ],
    }


def _cross_branch_advisory() -> dict:
    """A v3.23-branch fix — the wrong upgrade target for a 3.0.x user."""
    return {
        "id": "ALPINE-CVE-2026-9999",
        "summary": "openssl vulnerability",
        "aliases": ["CVE-2026-9999"],
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": "Alpine:v3.23"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.5.7-r0"}]}],
            }
        ],
    }


def _apk_package(*, distro_name: str | None = None, distro_version: str | None = None) -> Package:
    return Package(
        name="openssl",
        version="3.0.11-r0",
        ecosystem="apk",
        purl="pkg:apk/alpine/openssl@3.0.11-r0",
        distro_name=distro_name,
        distro_version=distro_version,
    )


def _deb_package(*, distro_name: str | None = None, distro_version: str | None = None) -> Package:
    return Package(
        name="openssl",
        version="3.0.11-1~deb12u2",
        ecosystem="deb",
        purl="pkg:deb/debian/openssl@3.0.11-1~deb12u2",
        distro_name=distro_name,
        distro_version=distro_version,
    )


# ── the ambiguity must be marked, not hidden ─────────────────────────────────


def test_apk_without_release_downgrades_match_confidence() -> None:
    vulns = build_vulnerabilities([_alpine_openssl_advisory()], _apk_package())
    assert vulns, "the union must still match — recall is not the thing being traded away"
    assert vulns[0].match_confidence_tier == AMBIGUOUS_TIER


def test_apk_without_release_suppresses_the_cross_branch_fix() -> None:
    """Which branch's fix applies is unknowable without the release."""
    vulns = build_vulnerabilities([_cross_branch_advisory()], _apk_package())
    assert vulns
    assert vulns[0].fixed_version is None, "a v3.23 fix must not be recommended to an unknown-release user"


def test_apk_without_release_records_a_scan_warning_naming_the_ambiguity() -> None:
    build_vulnerabilities([_alpine_openssl_advisory()], _apk_package())
    warnings = consume_scan_warnings()
    assert warnings, "an unspecified Alpine release must produce a visible warning"
    joined = " ".join(warnings)
    assert "openssl" in joined
    assert "Alpine" in joined
    assert "v3.14" in joined and "v3.23" in joined, "the warning must name the branches actually queried"
    assert "fix" in joined.lower(), "the warning must say fix recommendations are withheld"


def test_deb_without_release_downgrades_match_confidence_and_warns() -> None:
    advisory = {
        "id": "DSA-5532-1",
        "summary": "openssl security update",
        "aliases": ["CVE-2023-5363"],
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.4-2"}]}],
            }
        ],
    }
    vulns = build_vulnerabilities([advisory], _deb_package())
    assert vulns
    assert vulns[0].match_confidence_tier == AMBIGUOUS_TIER
    assert vulns[0].fixed_version is None
    joined = " ".join(consume_scan_warnings())
    assert "Debian" in joined


# ── the other direction: a known release must lose nothing ───────────────────


def test_apk_with_release_keeps_the_fix_and_full_confidence() -> None:
    pkg = _apk_package(distro_name="alpine", distro_version="3.18")
    vulns = build_vulnerabilities([_alpine_openssl_advisory()], pkg)
    assert vulns
    assert vulns[0].match_confidence_tier != AMBIGUOUS_TIER
    assert vulns[0].fixed_version == "3.1.4-r0", "a confirmed release must still get its upgrade target"
    assert not consume_scan_warnings(), "no ambiguity, no warning"


def test_deb_with_release_keeps_the_fix_and_full_confidence() -> None:
    pkg = _deb_package(distro_name="debian", distro_version="12")
    advisory = {
        "id": "DSA-5532-1",
        "summary": "openssl security update",
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": "Debian:12"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.11-1~deb12u3"}]}],
            }
        ],
    }
    vulns = build_vulnerabilities([advisory], pkg)
    assert vulns
    assert vulns[0].match_confidence_tier != AMBIGUOUS_TIER
    assert vulns[0].fixed_version == "3.0.11-1~deb12u3"
    assert not consume_scan_warnings()


def test_withheld_fix_is_not_mistaken_for_a_wont_fix_advisory() -> None:
    """"We withheld the fix" is not "the distro will not fix it".

    Distro advisories with no fixed version are suppressed by default as the
    tracker's no-dsa / won't-fix verdicts. Clearing ``fixed_version`` to stop a
    cross-branch recommendation therefore fed every ambiguous finding straight
    into that filter: ``check openssl@3.0.11-r0 -e apk`` went from 58 findings
    to 0 with a "clean" shape. The exemption is what keeps recall.
    """
    from agent_bom.scanners.package_scan import _suppress_unfixed_os_advisories

    pkg = _apk_package()
    pkg.vulnerabilities = build_vulnerabilities([_cross_branch_advisory()], pkg)
    assert len(pkg.vulnerabilities) == 1

    removed = _suppress_unfixed_os_advisories([pkg])
    assert removed == 0
    assert len(pkg.vulnerabilities) == 1


def test_a_genuinely_unfixed_distro_advisory_is_still_suppressed() -> None:
    """Non-vacuous: the exemption is scoped to the ambiguous tier only."""
    from agent_bom.scanners.package_scan import _suppress_unfixed_os_advisories

    pkg = _apk_package(distro_name="alpine", distro_version="3.18")
    advisory = {
        "id": "ALPINE-CVE-2023-0000",
        "summary": "openssl, no fix published",
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": "Alpine:v3.18"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ],
    }
    pkg.vulnerabilities = build_vulnerabilities([advisory], pkg)
    assert len(pkg.vulnerabilities) == 1
    assert pkg.vulnerabilities[0].fixed_version is None
    assert _suppress_unfixed_os_advisories([pkg]) == 1
    assert pkg.vulnerabilities == []


def test_language_ecosystems_are_untouched() -> None:
    """Non-distro packages have no release to be ambiguous about."""
    pkg = Package(name="flask", version="0.12.2", ecosystem="pypi", purl="pkg:pypi/flask@0.12.2")
    advisory = {
        "id": "CVE-2026-0001",
        "summary": "flask",
        "affected": [
            {
                "package": {"name": "flask", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.3.0"}]}],
            }
        ],
    }
    vulns = build_vulnerabilities([advisory], pkg)
    assert vulns
    assert vulns[0].match_confidence_tier != AMBIGUOUS_TIER
    assert vulns[0].fixed_version == "2.3.0"
    assert not consume_scan_warnings()


def test_wolfi_is_not_ambiguous() -> None:
    """Wolfi/Chainguard apk repos are version-less by design — one ecosystem,
    no fan-out, so nothing to downgrade."""
    pkg = Package(name="openssl", version="3.0.11-r0", ecosystem="apk", purl="pkg:apk/wolfi/openssl@3.0.11-r0", distro_name="wolfi")
    advisory = {
        "id": "CGA-0000-0000-0000",
        "summary": "openssl",
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": "Wolfi"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.4-r0"}]}],
            }
        ],
    }
    vulns = build_vulnerabilities([advisory], pkg)
    assert vulns
    assert vulns[0].match_confidence_tier != AMBIGUOUS_TIER
    assert not consume_scan_warnings()
