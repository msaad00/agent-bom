"""Regressions for OSV matching on OS package ecosystems."""

from __future__ import annotations

from agent_bom.models import Package
from agent_bom.scanners import _is_version_affected, build_vulnerabilities, parse_fixed_version


def _deb_advisory() -> dict:
    return {
        "id": "CVE-2025-NCURSES",
        "summary": "Debian ncurses issue",
        "affected": [
            {
                "package": {"ecosystem": "Debian", "name": "ncurses"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "6.5+20250216-3"},
                        ],
                    }
                ],
            }
        ],
    }


def test_osv_range_matching_uses_debian_version_order():
    advisory = _deb_advisory()
    assert _is_version_affected(advisory, "ncurses-bin", "6.5+20250216-2", "deb", source_package="ncurses") is True
    assert _is_version_affected(advisory, "ncurses-bin", "6.5+20250216-3", "deb", source_package="ncurses") is False


def test_build_vulnerabilities_filters_fixed_debian_version():
    package = Package(name="ncurses-bin", version="6.5+20250216-3", ecosystem="deb", source_package="ncurses")
    vulns = build_vulnerabilities([_deb_advisory()], package)
    assert vulns == []


def test_parse_fixed_version_preserves_higher_debian_fix():
    fixed = parse_fixed_version(
        _deb_advisory(),
        "ncurses-bin",
        "deb",
        current_version="6.5+20250216-2",
        source_package="ncurses",
    )
    assert fixed == "6.5+20250216-3"
