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
