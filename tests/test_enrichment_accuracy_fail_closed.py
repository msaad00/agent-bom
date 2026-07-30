"""Accuracy + fail-closed contract for the vulnerability-matching truth layer.

Every expectation here is pinned to an authoritative external record, not to
the code's current behaviour:

* Maven ordering follows the Apache Maven POM Reference "Version Order
  Specification" (``alpha < beta < milestone < rc = cr < snapshot <
  "" = final = ga = release < sp``).
* The ``org.springframework:spring-core`` and ``jackson-databind`` verdicts are
  the ones the live OSV/GHSA records give for those versions.

The suite covers BOTH directions on every comparator change: closing a
fail-open hole must not open a fail-closed (false-negative) one.
"""

from __future__ import annotations

import sqlite3

from agent_bom.db.lookup import lookup_package, lookup_packages_batch
from agent_bom.db.schema import _DDL
from agent_bom.evidence.scan_run import ScanIssue, ScanRun
from agent_bom.models import AIBOMReport, Package
from agent_bom.posture import compute_posture_scorecard
from agent_bom.scanners.ghsa_advisory import _installed_version_is_affected
from agent_bom.scanners.package_scan import _is_version_affected
from agent_bom.version_utils import compare_version_order, version_in_range

# ---------------------------------------------------------------------------
# Finding 1 — one range engine, one (fail-closed) policy
# ---------------------------------------------------------------------------


def _osv_range_advisory(introduced: str | None, fixed: str | None, *, ecosystem: str = "PyPI", name: str = "acme") -> dict:
    events: list[dict] = [{"introduced": introduced or "0"}]
    if fixed:
        events.append({"fixed": fixed})
    return {
        "id": "CVE-2099-0001",
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": name},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
    }


def test_uncomparable_fixed_bound_fails_closed_on_the_osv_path() -> None:
    """An upper bound we cannot compare must not be silently skipped.

    ``version_utils.version_in_range`` already fails closed here. The OSV
    ``affected[].ranges[]`` walker used to skip the bound entirely
    (``if fixed_cmp is not None and fixed_cmp >= 0``), so the same package got
    opposite verdicts depending on which engine served the query.
    """
    advisory = _osv_range_advisory("0", "not-a-parseable-version")
    assert _is_version_affected(advisory, "acme", "1.2.3", "pypi") is False
    assert version_in_range("1.2.3", "0", "not-a-parseable-version", None, "pypi") is False


def test_range_engines_agree_across_a_bound_matrix() -> None:
    """The OSV walker and ``version_in_range`` must never disagree."""
    matrix = [
        ("1.2.3", "1.0.0", "2.0.0", "pypi"),
        ("2.5.0", "1.0.0", "2.0.0", "pypi"),
        ("0.9.0", "1.0.0", "2.0.0", "pypi"),
        ("1.2.3", "0", None, "pypi"),
        ("1.2.3", "0", "garbage-bound", "pypi"),
        ("1.2.3", "garbage-bound", "2.0.0", "pypi"),
        ("5.3.20", "1.1.0", "3.0.0.RELEASE", "maven"),
        ("2.5.0", "1.1.0", "3.0.0.RELEASE", "maven"),
    ]
    for version, introduced, fixed, ecosystem in matrix:
        osv_eco = {"pypi": "PyPI", "maven": "Maven"}[ecosystem]
        walker = _is_version_affected(
            _osv_range_advisory(introduced, fixed, ecosystem=osv_eco),
            "acme",
            version,
            ecosystem,
        )
        direct = version_in_range(version, introduced, fixed, None, ecosystem)
        assert walker == direct, f"engines disagree for {version} in [{introduced}, {fixed}) / {ecosystem}"


def test_open_ended_introduced_zero_range_still_matches() -> None:
    """Fail-closed must not turn ``introduced: 0`` with no fix into a miss."""
    advisory = _osv_range_advisory("0", None)
    assert _is_version_affected(advisory, "acme", "1.2.3", "pypi") is True


# ---------------------------------------------------------------------------
# Finding 2 — Maven qualifier ordering (ground truth: live OSV spring-core)
# ---------------------------------------------------------------------------


def test_maven_release_qualifier_is_equivalent_to_no_qualifier() -> None:
    """``.RELEASE`` / ``.GA`` / ``.Final`` are null qualifiers per the Maven spec."""
    assert compare_version_order("1.0.RELEASE", "1.0", "maven") == 0
    assert compare_version_order("1.0.GA", "1.0", "maven") == 0
    assert compare_version_order("1.0.Final", "1.0", "maven") == 0
    assert compare_version_order("1.0.0", "1", "maven") == 0


def test_maven_prerelease_qualifiers_sort_below_the_release() -> None:
    """alpha < beta < milestone < rc = cr < snapshot < release < sp."""
    ordered = ["1.0-alpha", "1.0-beta", "1.0-milestone", "1.0-rc", "1.0-SNAPSHOT", "1.0", "1.0-sp"]
    for lower, higher in zip(ordered, ordered[1:]):
        assert compare_version_order(lower, higher, "maven") == -1, f"{lower} should sort below {higher}"
        assert compare_version_order(higher, lower, "maven") == 1
    assert compare_version_order("1.0-rc", "1.0-cr", "maven") == 0
    assert compare_version_order("1.0-ALPHA1", "1.0-alpha1", "maven") == 0


def test_maven_qualifier_versions_are_comparable_not_none() -> None:
    """The comparator must return an ordering, never ``None`` (which fails open)."""
    assert compare_version_order("5.3.20", "5.0.6.RELEASE", "maven") == 1
    assert compare_version_order("5.3.20", "3.0.0.RELEASE", "maven") == 1
    assert compare_version_order("2.5.6.SEC03", "2.5.6", "maven") == 1
    assert compare_version_order("5.0.5.RELEASE", "5.0.6.RELEASE", "maven") == -1


def test_spring_core_5_3_20_is_outside_the_release_qualified_advisories() -> None:
    """Ground truth: live OSV reports exactly ONE advisory for spring-core 5.3.20.

    The ``.RELEASE``-bounded advisories below are the false positives the
    uncomparable-qualifier fail-open produced — CVE-2009-1190 (fixed in
    ``3.0.0.RELEASE``) against a 2022 release being the worst of them.
    """
    false_positive_ranges = [
        ("1.1.0", "3.0.0.RELEASE"),  # GHSA-wjjr-h4wh-w6vv / CVE-2009-1190
        ("5.0.5.RELEASE", "5.0.6.RELEASE"),  # GHSA-cxrj-66c5-9fmh
        ("5.0.0.RELEASE", "5.0.7.RELEASE"),  # GHSA-f26x-pr96-vw86
        ("4.3.0.RELEASE", "4.3.18.RELEASE"),  # GHSA-f26x-pr96-vw86
        ("5.1.0.RELEASE", "5.1.1.RELEASE"),  # GHSA-ffvq-7w96-97p7
        ("2.5.7.SR0", "2.5.7.SR023"),  # GHSA-wv88-pf73-x22p
        ("0", "2.5.6.SEC03"),  # GHSA-wv88-pf73-x22p
    ]
    for introduced, fixed in false_positive_ranges:
        assert version_in_range("5.3.20", introduced, fixed, None, "maven") is False, f"5.3.20 falsely matched [{introduced}, {fixed})"


def test_spring_core_true_positive_window_still_matches() -> None:
    """No false negatives: the one real advisory must still match.

    GHSA-jmp9-x22r-554x — ``introduced 5.3.0``, ``last_affected 5.3.44``.
    """
    assert version_in_range("5.3.20", "5.3.0", None, "5.3.44", "maven") is True


def test_release_qualified_bounds_still_catch_versions_inside_them() -> None:
    """The other direction: a genuinely affected qualifier version still matches."""
    assert version_in_range("5.0.5.RELEASE", "5.0.5.RELEASE", "5.0.6.RELEASE", None, "maven") is True
    assert version_in_range("2.5.0", "1.1.0", "3.0.0.RELEASE", None, "maven") is True
    assert version_in_range("1.0-SNAPSHOT", "0", "1.0", None, "maven") is True


# ---------------------------------------------------------------------------
# Finding 3 — GHSA must always honour the advisory's lower bound
# ---------------------------------------------------------------------------


def test_ghsa_range_lower_bound_is_honoured() -> None:
    """``jackson-databind@2.9.10`` is NOT in ``>= 2.13.0, < 2.18.8``."""
    assert _installed_version_is_affected("2.9.10", ">= 2.13.0, < 2.18.8", "maven") is False
    assert _installed_version_is_affected("2.14.0", ">= 2.13.0, < 2.18.8", "maven") is True


def test_ghsa_range_matching_is_ecosystem_aware() -> None:
    """npm/Go/Maven ranges must not be forced through PEP 440."""
    assert _installed_version_is_affected("13.4.20-canary.13", "< 13.4.20", "npm") is True
    assert _installed_version_is_affected("13.5.0", "< 13.4.20", "npm") is False
    assert _installed_version_is_affected("v0.16.0", "< v0.17.0", "go") is True
    assert _installed_version_is_affected("v0.18.0", "< v0.17.0", "go") is False
    assert _installed_version_is_affected("5.3.20", "< 3.0.0.RELEASE", "maven") is False


def test_ghsa_unparseable_range_fails_closed() -> None:
    """An unparseable range cannot establish a match — no blanket ``True``."""
    assert _installed_version_is_affected("1.2.3", "totally not a range", "pypi") is False
    assert _installed_version_is_affected("1.2.3", "", "pypi") is False


def test_ghsa_pep440_ranges_still_work_for_pypi() -> None:
    """No regression for the ecosystem the PEP 440 path was written for."""
    assert _installed_version_is_affected("2.30.0", ">= 2.3.0, < 2.31.0", "pypi") is True
    assert _installed_version_is_affected("2.31.0", ">= 2.3.0, < 2.31.0", "pypi") is False
    assert _installed_version_is_affected("1.6.8", "<= 1.6.8", "pypi") is True


# ---------------------------------------------------------------------------
# Finding 4 — kev_due_date survives the local-DB read path
# ---------------------------------------------------------------------------


def _seed_kev_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(_DDL)
    conn.execute(
        "INSERT INTO vulns (id, summary, severity, cvss_score, fixed_version, source) VALUES (?,?,?,?,?,?)",
        ("CVE-2021-44228", "Log4Shell", "critical", 10.0, "2.15.0", "osv"),
    )
    conn.execute(
        "INSERT INTO affected (vuln_id, ecosystem, package_name, introduced, fixed) VALUES (?,?,?,?,?)",
        ("CVE-2021-44228", "maven", "org.apache.logging.log4j:log4j-core", "2.0", "2.15.0"),
    )
    # Values as published by CISA in the BOD 22-01 catalog.
    conn.execute(
        "INSERT INTO kev_entries (cve_id, date_added, due_date) VALUES (?,?,?)",
        ("CVE-2021-44228", "2021-12-10", "2021-12-24"),
    )
    conn.commit()
    return conn


def test_lookup_package_carries_the_kev_remediation_due_date() -> None:
    """BOD 22-01 due date is in the DB and every consumer wants it."""
    conn = _seed_kev_db()
    rows = lookup_package(conn, "maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
    assert rows, "seeded KEV vulnerability was not returned"
    assert rows[0].is_kev is True
    assert rows[0].kev_date_added == "2021-12-10"
    assert rows[0].kev_due_date == "2021-12-24"


def test_batch_lookup_carries_the_kev_remediation_due_date() -> None:
    """The batch read path must not drop what the single path carries."""
    conn = _seed_kev_db()
    result = lookup_packages_batch(conn, [("maven", "org.apache.logging.log4j:log4j-core", "2.14.1")])
    rows = next(iter(result.values()))
    assert rows[0].kev_due_date == "2021-12-24"


def test_kev_due_date_reaches_the_vulnerability_model() -> None:
    """Reader → model → every exporter that already reads ``kev_due_date``."""
    from agent_bom.scanners import _local_vuln_to_vulnerability

    conn = _seed_kev_db()
    rows = lookup_package(conn, "maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
    vuln = _local_vuln_to_vulnerability(rows[0])
    assert vuln.kev_due_date == "2021-12-24"


# ---------------------------------------------------------------------------
# Finding 6 — posture must not grade a scan whose vuln coverage was incomplete
# ---------------------------------------------------------------------------


def _report_with_unavailable_vuln_db() -> AIBOMReport:
    return AIBOMReport(
        agents=[],
        blast_radii=[],
        scan_run=ScanRun(
            issues=[
                ScanIssue(
                    code="required_scanner_unavailable",
                    stage="scanning",
                    source="vulnerability-data",
                    message="Vulnerability database unavailable",
                    severity="error",
                    affects_coverage=True,
                )
            ]
        ),
        scan_performance_data={"coverage_state": "incomplete", "coverage_reason": "db unavailable"},
    )


def test_posture_is_na_when_vulnerability_coverage_is_incomplete() -> None:
    """A "no vulnerabilities found" A-grade is a lie when the vuln DB never answered."""
    report = _report_with_unavailable_vuln_db()
    report.agents = []
    scorecard = compute_posture_scorecard(report)
    assert scorecard.grade == "N/A"
    assert scorecard.no_data is True
    assert "No vulnerabilities found" not in scorecard.summary


def test_posture_is_na_even_when_packages_were_discovered() -> None:
    """Discovery is not evaluability — the old guard counted artifacts only."""
    from agent_bom.models import Agent, AgentType, MCPServer

    report = _report_with_unavailable_vuln_db()
    report.agents = [
        Agent(
            name="cursor",
            agent_type=AgentType.CUSTOM,
            config_path="/tmp/mcp.json",
            mcp_servers=[MCPServer(name="fs", packages=[Package(name="requests", version="2.31.0", ecosystem="pypi")])],
        )
    ]
    scorecard = compute_posture_scorecard(report)
    assert scorecard.grade == "N/A"
    assert scorecard.no_data is True
    assert "No vulnerabilities found" not in scorecard.summary


def test_posture_still_grades_a_complete_scan() -> None:
    """No regression: a complete scan keeps its real letter grade."""
    from agent_bom.models import Agent, AgentType, MCPServer

    report = AIBOMReport(
        agents=[
            Agent(
                name="cursor",
                agent_type=AgentType.CUSTOM,
                config_path="/tmp/mcp.json",
                mcp_servers=[MCPServer(name="fs", packages=[Package(name="requests", version="2.31.0", ecosystem="pypi")])],
            )
        ],
        blast_radii=[],
    )
    scorecard = compute_posture_scorecard(report)
    assert scorecard.grade in {"A", "B", "C", "D", "F"}
    assert scorecard.no_data is False


def test_posture_still_grades_when_only_a_non_vuln_stage_degraded() -> None:
    """A failed cloud collector must not blank the whole posture grade."""
    from agent_bom.models import Agent, AgentType, MCPServer

    report = AIBOMReport(
        agents=[
            Agent(
                name="cursor",
                agent_type=AgentType.CUSTOM,
                config_path="/tmp/mcp.json",
                mcp_servers=[MCPServer(name="fs", packages=[Package(name="requests", version="2.31.0", ecosystem="pypi")])],
            )
        ],
        blast_radii=[],
        scan_run=ScanRun(
            issues=[
                ScanIssue(
                    code="collector_failed",
                    stage="discovery",
                    source="aws",
                    message="collector failed",
                    severity="warning",
                    affects_coverage=True,
                )
            ]
        ),
    )
    scorecard = compute_posture_scorecard(report)
    assert scorecard.grade in {"A", "B", "C", "D", "F"}
    assert scorecard.no_data is False
