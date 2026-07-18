"""Honesty regressions for vulnerability-matching accuracy.

A read-only scanner must never claim a version/CVE/fix the evidence does not
support. Each test reproduces a confirmed dishonest-output defect:

1. version-range constraints scanned as exact installed pins
2. bare deps resolved from the SCANNER host env instead of the target
3. wrong ``fixed_version`` for multi-branch advisories (downgrade advice)
4. reachability over-claim on declaration-only Python manifests
5. CVSS score/vector taken from different entries (mismatched pair)
"""

from __future__ import annotations

import pytest

from agent_bom.models import BlastRadius, Package, Severity, Vulnerability
from agent_bom.parsers.python_parsers import parse_pip_packages
from agent_bom.scanners import parse_fixed_version

# --- Defect 1: version-range constraints must not become exact pins --------


def test_range_requirement_not_emitted_as_exact_pin(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask>=1.0\nDjango<2.3\nrequests==2.28.0\n")
    pkgs = {p.name.lower(): p for p in parse_pip_packages(tmp_path)}

    flask = pkgs["flask"]
    # ``flask>=1.0`` does not mean flask *is* 1.0.
    assert flask.version != "1.0"
    assert flask.purl != "pkg:pypi/flask@1.0"
    assert flask.floating_reference is True
    assert flask.version_confidence == "low"

    django = pkgs["django"]
    # ``<2.3`` DEFINITIONALLY EXCLUDES 2.3 — reporting it is a fabricated pin.
    assert django.version != "2.3"
    assert django.purl != "pkg:pypi/django@2.3"
    assert django.floating_reference is True

    # An exact ``==`` pin is still reported as an installed pin.
    req = pkgs["requests"]
    assert req.version == "2.28.0"
    assert req.floating_reference is False
    assert req.purl == "pkg:pypi/requests@2.28.0"


def test_pyproject_range_not_emitted_as_exact_pin(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["flask>=1.0", "urllib3<2"]\n'
    )
    pkgs = {p.name.lower(): p for p in parse_pip_packages(tmp_path)}
    assert pkgs["flask"].version != "1.0"
    assert pkgs["flask"].floating_reference is True
    assert pkgs["urllib3"].version != "2"
    assert pkgs["urllib3"].floating_reference is True


# --- Defect 4: declaration-only manifests must not over-claim reachability --


def test_requirements_manifest_marks_declaration_only(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\nflask>=1.0\n")
    pkgs = parse_pip_packages(tmp_path)
    assert pkgs
    assert all(p.reachability_evidence == "declaration_only" for p in pkgs)


def _blast_radius(pkg: Package) -> BlastRadius:
    vuln = Vulnerability(id="CVE-2099-1", summary="x", severity=Severity.HIGH)
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )


def test_declaration_only_downgrades_reachability_to_unknown():
    pkg = Package(
        name="requests",
        version="2.28.0",
        ecosystem="pypi",
        is_direct=True,
        reachability_evidence="declaration_only",
    )
    assert _blast_radius(pkg).reachability == "unknown"


def test_runtime_dependency_high_still_reads_likely():
    # Control: without declaration-only evidence a HIGH direct dep stays "likely".
    pkg = Package(name="requests", version="2.28.0", ecosystem="pypi", is_direct=True)
    assert _blast_radius(pkg).reachability == "likely"


# --- Defect 2: bare deps resolved against target, never the scanner host ----


@pytest.mark.asyncio
async def test_bare_pip_dep_not_resolved_from_scanner_host(tmp_path, monkeypatch):
    import agent_bom.resolvers.runtime_resolver as rr
    from agent_bom.scanners.package_scan import ScanOptions, scan_packages

    def fake_resolve_pip(python_path=None):
        # A target venv interpreter would be passed as python_path; there is
        # none here. Host ``pip`` (python_path is None) must never be consulted.
        if python_path is None:
            return {"requests": "9.9.9"}  # scanner HOST version — must not leak in
        return {}

    monkeypatch.setattr(rr, "resolve_pip_versions", fake_resolve_pip)

    pkg = Package(name="requests", version="unknown", ecosystem="pypi", is_direct=True)
    await scan_packages([pkg], options=ScanOptions(offline=True, project_dir=str(tmp_path)))

    assert pkg.version != "9.9.9"
    assert pkg.version_source != "installed"


# --- Defect 3: multi-branch advisories report the branch-correct fix --------


class _Row(dict):
    """Minimal ``sqlite3.Row``-like mapping for ``_resolve_fixed_version``."""


def test_lookup_prefers_matched_range_fix_over_rollup():
    from agent_bom.db.lookup import _resolve_fixed_version

    # form-data GHSA-fjxv-7rqg-78g4 shape: rollup=2.5.4 (2.x branch),
    # matched range fix for installed 4.0.0 = 4.0.4. Reporting 2.5.4 would
    # tell the user to DOWNGRADE.
    row = _Row(ecosystem="npm", fixed="4.0.4", fixed_version="2.5.4")
    assert _resolve_fixed_version(row) == "4.0.4"


def test_lookup_missing_range_fix_falls_back_to_rollup():
    from agent_bom.db.lookup import _resolve_fixed_version

    row = _Row(ecosystem="PyPI", fixed="", fixed_version="2.5.4")
    assert _resolve_fixed_version(row) == "2.5.4"


def test_lookup_does_not_present_invalid_sha_rollup_as_fix():
    from agent_bom.db.lookup import _resolve_fixed_version

    # No range fix and the rollup is a git SHA — that is NOT a usable fix.
    row = _Row(ecosystem="PyPI", fixed="", fixed_version="a" * 40)
    assert _resolve_fixed_version(row) is None


def test_lookup_distro_path_unchanged():
    from agent_bom.db.lookup import _resolve_fixed_version

    # Distro releases keep per-release ``fixed`` semantics, never the rollup.
    row = _Row(ecosystem="debian:11", fixed="1.2-3", fixed_version="9.9")
    assert _resolve_fixed_version(row) == "1.2-3"
    row_nofix = _Row(ecosystem="debian:11", fixed="", fixed_version="9.9")
    assert _resolve_fixed_version(row_nofix) is None


def test_osv_same_branch_fix_chosen_for_multibranch_range():
    # CVE-2023-45803 shape: one range, two branches. Installed 1.26.4 must get
    # the 1.26-branch fix (1.26.18), not the 2.x major jump (2.0.7).
    vuln = {
        "id": "CVE-2023-45803",
        "affected": [
            {
                "package": {"name": "urllib3", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.26.18"},
                            {"introduced": "2.0.0"},
                            {"fixed": "2.0.7"},
                        ],
                    }
                ],
            }
        ],
    }
    assert parse_fixed_version(vuln, "urllib3", "PyPI", current_version="1.26.4") == "1.26.18"


def test_osv_same_branch_fix_wins_regardless_of_range_order():
    # 2.x range listed FIRST; installed 1.26.4 must still resolve same-branch.
    vuln = {
        "id": "X",
        "affected": [
            {
                "package": {"name": "urllib3", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "2.0.0"}, {"fixed": "2.0.7"}]}],
            },
            {
                "package": {"name": "urllib3", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "1.26.0"}, {"fixed": "1.26.18"}]}],
            },
        ],
    }
    assert parse_fixed_version(vuln, "urllib3", "PyPI", current_version="1.26.4") == "1.26.18"


# --- Defect 5: CVSS score and vector must come from the same entry ---------


def test_cvss_score_and_vector_are_a_matched_pair():
    from agent_bom.db.sync import _parse_osv_entry

    v31_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    v40_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
    data = {
        "id": "CVE-2099-9999",
        "summary": "pair test",
        "severity": [
            {"type": "CVSS_V3_1", "score": v31_vector},
            {"type": "CVSS_V4", "score": v40_vector},
        ],
        "affected": [],
    }
    vuln_row, _ = _parse_osv_entry(data)
    # The v3.1 score must not be paired with the v4.0 vector.
    assert vuln_row["cvss_vector"] == v31_vector
    assert vuln_row["cvss_score"] is not None
