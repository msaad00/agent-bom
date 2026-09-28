"""CVE metrics require advisory identity and a compatible finding class."""

import pytest

from agent_bom.api.overview_cve_counts import add_cve_finding, empty_cve_counts


@pytest.mark.parametrize(
    "row,expected",
    [
        ({"finding_type": "CVE", "cve_id": "CVE-2026-1234"}, 1),
        ({"finding_type": "CVE", "cve_id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1234"]}, 1),
        ({"finding_type": "CVE", "vulnerability_id": "DEBIAN-CVE-2026-1234"}, 1),
        ({"finding_type": "CVE", "cve_id": "GHSA-aaaa-bbbb-cccc"}, 0),
        ({"finding_type": "CVE", "cve_id": "CVE-invalid"}, 0),
        ({"finding_type": "CIS_FAIL", "cve_id": "CVE-2026-1234"}, 0),
        ({"finding_type": "SAST", "cve_id": "CVE-2026-1234"}, 0),
        ({"finding_type": "SECRET", "cve_id": "CVE-2026-1234"}, 0),
        ({"severity": "critical"}, 0),
    ],
)
def test_cve_count_requires_valid_identity_and_vulnerability_evidence(row, expected):
    counts = empty_cve_counts()
    add_cve_finding(counts, {"severity": "high", "is_kev": True, **row})
    assert counts["high"] == expected
    assert counts["kev"] == expected
    assert sum(counts.values()) == 2 * expected


def test_cve_histogram_counts_occurrences_and_keeps_unknown_severity():
    counts = empty_cve_counts()
    for identity in ("package-a", "package-b"):
        add_cve_finding(counts, {"id": identity, "finding_type": "CVE", "cve_id": "CVE-2026-1234", "severity": "unknown"})
    assert counts["unrated"] == 2
    assert counts["kev"] == 0


@pytest.mark.parametrize("source_status", ["partial", "unavailable"])
def test_incomplete_cve_evidence_never_reports_clean_zero(source_status):
    from agent_bom.api.overview_cve_counts import compose_cve_domain

    result = compose_cve_domain(
        empty_cve_counts(), empty_cve_counts(), scan_complete=True, hub_status=source_status, packages=0, graph_href=lambda _: "/graph"
    )
    assert result["metric"] == 0
    assert result["count_exact"] is False
    assert result["evidence_status"] == source_status
    assert result["status"] == "unknown"


def test_compacted_scan_keeps_known_hub_cves_as_lower_bound():
    from agent_bom.api.overview_cve_counts import compose_cve_domain

    hub = empty_cve_counts()
    hub.update(high=2, kev=1)
    result = compose_cve_domain(
        empty_cve_counts(), hub, scan_complete=False, hub_status="complete", packages=3, graph_href=lambda _: "/graph"
    )
    assert result["metric"] == 2
    assert result["count_exact"] is False
    assert result["evidence_status"] == "partial"
    assert result["detail"]["high"] == 2
    assert result["detail"]["kev"] == 1
    assert sum(result["detail"]["severity"].values()) == result["metric"]


def test_hub_projection_retains_only_validated_cve_aliases():
    from agent_bom.finding_scope import safe_finding_response_payload

    row = safe_finding_response_payload(
        {
            "finding_type": "CVE",
            "cve_id": "GHSA-aaaa-bbbb-cccc",
            "aliases": [
                "CVE-2026-1234",
                "cve-2026-1234",
                "CVE-invalid",
                "/private/source.py",
                "password=fixture",
                "CVE-2026-" + "1" * 1000,
                None,
            ],
        }
    )
    assert row.get("aliases") == ["CVE-2026-1234"]
    assert "aliases" not in safe_finding_response_payload({"aliases": "CVE-2026-1234"})
    assert "aliases" not in safe_finding_response_payload({"aliases": ["password=fixture"]})


def test_cve_alias_evidence_survives_sqlite_reopen_without_tenant_leakage(tmp_path):
    from datetime import datetime, timezone

    from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore

    path = str(tmp_path / "hub.db")
    store = SQLiteComplianceHubStore(path)
    rows = [{"id": "alias", "origin": "bulk_ingest", "finding_type": "CVE", "cve_id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1234"]}]
    store.add("tenant-a", rows)
    store.upsert_current_batch("tenant-a", rows, observed_at=datetime.now(timezone.utc).isoformat(), batch_id="first")
    reopened = SQLiteComplianceHubStore(path)
    persisted, _, _ = reopened.list_current_page("tenant-a", limit=10, status="open")
    counts = empty_cve_counts()
    for row in persisted:
        add_cve_finding(counts, row)
    assert counts["unrated"] == 1
    assert reopened.list_current_page("tenant-b", limit=10)[0] == []
