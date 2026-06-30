"""Tests for the CPE candidate matcher (cpe_match.match_component_cpe)."""

from __future__ import annotations

from pathlib import Path

from agent_bom.cpe_match import candidate_cpe_products, match_component_cpe
from agent_bom.db.schema import init_db


def _seed(conn) -> None:
    conn.executemany(
        "INSERT INTO cpe_matches (cve_id, criteria, vendor, product, version, "
        "version_start, version_start_op, version_end, version_end_op) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        [
            # range [1.0, 2.0)
            ("CVE-2026-1", "cpe:2.3:a:acme:widget:*", "acme", "widget", None, "1.0", "including", "2.0", "excluding"),
            # exact 3.1
            ("CVE-2026-2", "cpe:2.3:a:acme:gadget:3.1", "acme", "gadget", "3.1", None, None, None, None),
            # no bounds -> all versions
            ("CVE-2026-3", "cpe:2.3:a:acme:thing:*", "acme", "thing", None, None, None, None, None),
        ],
    )
    conn.commit()


def test_candidate_products_normalizes() -> None:
    assert candidate_cpe_products("My-Widget") == ["my_widget", "my-widget"]
    assert candidate_cpe_products("Acme Server") == ["acme_server", "acme-server", "acme server"]


def test_range_match_inclusive_start_exclusive_end() -> None:
    conn = init_db(Path(":memory:"))
    _seed(conn)
    assert [m["cve_id"] for m in match_component_cpe(conn, "widget", "1.5")] == ["CVE-2026-1"]
    assert [m["cve_id"] for m in match_component_cpe(conn, "widget", "1.0")] == ["CVE-2026-1"]  # inclusive start
    assert match_component_cpe(conn, "widget", "2.0") == []  # exclusive end
    assert match_component_cpe(conn, "widget", "0.9") == []  # below start


def test_exact_version_match() -> None:
    conn = init_db(Path(":memory:"))
    _seed(conn)
    assert [m["cve_id"] for m in match_component_cpe(conn, "gadget", "3.1")] == ["CVE-2026-2"]
    assert match_component_cpe(conn, "gadget", "3.2") == []


def test_no_bounds_matches_any_version() -> None:
    conn = init_db(Path(":memory:"))
    _seed(conn)
    assert [m["cve_id"] for m in match_component_cpe(conn, "thing", "99.9")] == ["CVE-2026-3"]


def test_unknown_product_and_empty_inputs() -> None:
    conn = init_db(Path(":memory:"))
    _seed(conn)
    assert match_component_cpe(conn, "nonexistent", "1.0") == []
    assert match_component_cpe(conn, "", "1.0") == []
    assert match_component_cpe(conn, "widget", "") == []


def test_result_carries_cpe_candidate_tier() -> None:
    conn = init_db(Path(":memory:"))
    _seed(conn)
    m = match_component_cpe(conn, "widget", "1.5")[0]
    assert m["match_confidence_tier"] == "nvd_cpe_candidate"
    assert m["cpe"].startswith("cpe:2.3:a:acme:widget")


def _seed_vuln_and_cpe(conn) -> None:
    conn.execute(
        "INSERT INTO vulns (id, summary, severity, cvss_score, cvss_vector, fixed_version, "
        "cwe_ids, aliases, published, modified, source) VALUES "
        "('CVE-2026-7', 'remote code exec in mytool', 'critical', 9.8, NULL, NULL, "
        "'CWE-77', '', '2026-01-01', '2026-01-02', 'nvd')"
    )
    conn.execute(
        "INSERT INTO cpe_matches (cve_id, criteria, vendor, product, version, "
        "version_start, version_start_op, version_end, version_end_op) VALUES "
        "('CVE-2026-7', 'cpe:2.3:a:acme:mytool:*', 'acme', 'mytool', NULL, '1.0', 'including', '2.0', 'excluding')"
    )
    conn.commit()


def test_cpe_lookup_package_hydrates_localvuln() -> None:
    from agent_bom.db.lookup import cpe_lookup_package

    conn = init_db(Path(":memory:"))
    _seed_vuln_and_cpe(conn)
    vulns = cpe_lookup_package(conn, "mytool", "1.5")
    assert len(vulns) == 1
    lv = vulns[0]
    assert lv.id == "CVE-2026-7"
    assert lv.severity == "critical"
    assert lv.source == "nvd"
    assert lv.match_confidence_tier == "nvd_cpe_candidate"
    assert "CWE-77" in lv.cwe_ids
    # out of range -> nothing
    assert cpe_lookup_package(conn, "mytool", "2.5") == []


def test_cpe_lookup_skips_cve_not_in_vulns() -> None:
    from agent_bom.db.lookup import cpe_lookup_package

    conn = init_db(Path(":memory:"))
    # CPE row exists but the CVE was never synced into vulns -> no severity, skip.
    conn.execute(
        "INSERT INTO cpe_matches (cve_id, criteria, vendor, product, version, "
        "version_start, version_start_op, version_end, version_end_op) VALUES "
        "('CVE-2026-8', 'cpe:2.3:a:acme:ghost:*', 'acme', 'ghost', NULL, NULL, NULL, NULL, NULL)"
    )
    conn.commit()
    assert cpe_lookup_package(conn, "ghost", "1.0") == []


def test_product_only_index_exists_for_vendorless_lookup() -> None:
    # match_component_cpe filters `WHERE product IN (...)` often without a vendor;
    # the (vendor, product) index can't serve that path, so a product-only index
    # must exist after init_db. Regression: idx_cpe_product_only must be present
    # and SQLite must be willing to use it for a product-only lookup.
    conn = init_db(Path(":memory:"))
    indexes = {row["name"] for row in conn.execute("PRAGMA index_list('cpe_matches')")}
    assert "idx_cpe_product_only" in indexes

    plan = conn.execute(
        "EXPLAIN QUERY PLAN SELECT * FROM cpe_matches WHERE product IN ('widget')"
    ).fetchall()
    detail = " ".join(str(row["detail"]) for row in plan)
    assert "idx_cpe_product_only" in detail
