"""Reconcile compatibility rows by package version without merging estate assets."""

from agent_bom.api.models import ScanJob
from agent_bom.api.routes.scan import _iter_scan_findings


def report(versions=("1.0", "2.0"), *, package="demo", assets=None):
    assets = assets or ["asset-" + version for version in versions]
    return {
        "findings": [
            {
                "id": f"finding-{i}",
                "cve_id": "CVE-2026-1234",
                "title": f"CVE-2026-1234: {package}@{version}",
                "asset": {"stable_id": asset},
                "evidence": {"package_name": package, "package_version": version, "ecosystem": "npm", "symbol_reachability": "unreachable"},
            }
            for i, (version, asset) in enumerate(zip(versions, assets))
        ],
        "agents": [
            {
                "name": "project:test",
                "mcp_servers": [
                    {
                        "name": "repo",
                        "packages": [
                            {
                                "name": package,
                                "version": version,
                                "ecosystem": "npm",
                                "vulnerabilities": [{"id": "CVE-2026-1234", "severity": "high"}],
                            }
                            for version in dict.fromkeys(versions)
                        ],
                    }
                ],
            }
        ],
    }


def rows(payload):
    return _iter_scan_findings(ScanJob(job_id="scan-test", created_at="2026-09-11T00:00:00Z", request={}, result=payload))


def test_nested_versions_backfill_their_exact_authoritative_finding():
    result = rows(report())
    assert len(result) == 2
    assert {row["id"] for row in result} == {"finding-0", "finding-1"}
    for row in result:
        assert row["package_version"] == row["evidence"]["package_version"]
        assert row["evidence"]["symbol_reachability"] == "unreachable"


def test_distinct_scoped_packages_do_not_share_an_empty_name():
    payload = report(("1.0",), package="@org/a")
    other = report(("1.0",), package="@org/b", assets=["asset-b"])
    payload["findings"] += other["findings"]
    payload["agents"][0]["mcp_servers"][0]["packages"] += other["agents"][0]["mcp_servers"][0]["packages"]
    assert len(rows(payload)) == 2


def test_ambiguous_same_version_on_two_assets_remains_separate():
    assert len(rows(report(("1.0", "1.0"), assets=["image-a", "image-b"]))) == 3


def test_missing_authoritative_version_does_not_swallow_another_version():
    payload = report(("1.0",))
    payload["agents"][0]["mcp_servers"][0]["packages"][0]["version"] = "9.0"
    assert len(rows(payload)) == 2


def test_package_only_versions_are_not_collapsed():
    payload = report()
    payload["findings"] = []
    assert len(rows(payload)) == 2


def _server_scoped_report():
    """One MCP-server finding plus container findings for the same package version."""
    payload = report(("1.0", "1.0", "1.0"), assets=["server-repo", "image-a", "image-b"])
    payload["findings"][0]["asset"] = {"stable_id": "server-repo", "asset_type": "mcp_server", "name": "repo"}
    return payload


def test_nested_row_folds_onto_the_finding_for_its_own_server():
    from agent_bom.api.routes.campaigns import _canonical_finding_id

    result = rows(_server_scoped_report())
    assert len(result) == 3
    assert {row["id"] for row in result} == {"finding-0", "finding-1", "finding-2"}
    assert all(_canonical_finding_id(row) for row in result)
    merged = next(row for row in result if row["id"] == "finding-0")
    assert merged["affected_servers"] == ["repo"]


def test_nested_row_matches_a_finding_listing_its_server_as_affected():
    payload = report(("1.0", "1.0"), assets=["image-a", "image-b"])
    payload["findings"][1]["affected_servers"] = ["repo"]
    result = rows(payload)
    assert len(result) == 2
    assert {row["id"] for row in result} == {"finding-0", "finding-1"}


def test_server_name_never_merges_a_different_package_version():
    payload = _server_scoped_report()
    payload["agents"][0]["mcp_servers"][0]["packages"][0]["version"] = "9.0"
    assert len(rows(payload)) == 4


def test_unmatched_nested_row_carries_a_deterministic_occurrence_identity():
    from agent_bom.api.routes.campaigns import _canonical_finding_id

    first = rows(report(("1.0", "1.0"), assets=["image-a", "image-b"]))
    again = rows(report(("1.0", "1.0"), assets=["image-a", "image-b"]))
    nested = [row for row in first if row.get("source") == "package_vulnerability"]
    assert len(nested) == 1
    identity = _canonical_finding_id(nested[0])
    assert identity and identity != "CVE-2026-1234"
    assert identity == _canonical_finding_id(next(row for row in again if row.get("source") == "package_vulnerability"))
    assert nested[0]["id"] == "CVE-2026-1234"


def test_package_only_rows_have_distinct_identities_per_version():
    from agent_bom.api.routes.campaigns import _canonical_finding_id

    payload = report()
    payload["findings"] = []
    identities = {_canonical_finding_id(row) for row in rows(payload)}
    assert len(identities) == 2 and "" not in identities
