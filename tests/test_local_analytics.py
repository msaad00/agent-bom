from __future__ import annotations

import sqlite3

from agent_bom.db.local_analytics import LocalAnalyticsStore


def _report(scan_id: str = "scan-1") -> dict:
    return {
        "scan_id": scan_id,
        "generated_at": "2026-05-10T16:00:00+00:00",
        "summary": {
            "total_agents": 1,
            "total_packages": 2,
            "total_vulnerabilities": 2,
            "critical_findings": 1,
        },
        "agents": [
            {
                "name": "desktop-agent",
                "mcp_servers": [
                    {
                        "name": "filesystem",
                        "packages": [
                            {
                                "name": "fastapi",
                                "version": "0.115.0",
                                "ecosystem": "pypi",
                                "purl": "pkg:pypi/fastapi@0.115.0",
                            },
                            {
                                "name": "uvicorn",
                                "version": "0.32.0",
                                "ecosystem": "pypi",
                            },
                        ],
                    }
                ],
            }
        ],
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2026-0001",
                "package": "fastapi@0.115.0",
                "package_name": "fastapi",
                "package_version": "0.115.0",
                "ecosystem": "pypi",
                "severity": "critical",
                "risk_score": 9.4,
                "affected_agents": ["desktop-agent"],
                "affected_servers": ["filesystem"],
            },
            {
                "vulnerability_id": "CVE-2026-0002",
                "package": "uvicorn@0.32.0",
                "ecosystem": "pypi",
                "severity": "high",
                "risk_score": 7.2,
                "affected_agents": ["desktop-agent"],
                "affected_servers": ["filesystem"],
            },
        ],
    }


def test_local_analytics_store_records_scan_summary_findings_and_packages(tmp_path):
    store = LocalAnalyticsStore(tmp_path / "local.sqlite")

    scan_id = store.record_scan_report(_report(), source="cli", artifact_path=tmp_path / "scan.json")

    assert scan_id == "scan-1"
    runs = store.list_scan_runs()
    assert runs[0]["scan_id"] == "scan-1"
    assert runs[0]["total_packages"] == 2
    assert runs[0]["critical_findings"] == 1
    assert runs[0]["high_findings"] == 1

    severity_rows = store.query("SELECT severity, COUNT(*) AS count FROM scan_findings GROUP BY severity ORDER BY severity")
    assert severity_rows == [{"severity": "critical", "count": 1}, {"severity": "high", "count": 1}]

    package_rows = store.query("SELECT package_name FROM scan_packages ORDER BY package_name")
    assert package_rows == [{"package_name": "fastapi"}, {"package_name": "uvicorn"}]


def test_local_analytics_store_upserts_scan_without_changing_existing_json_artifact(tmp_path):
    report = _report()
    store = LocalAnalyticsStore(tmp_path / "local.sqlite")

    store.record_scan_report(report, source="cli")
    report["summary"]["total_vulnerabilities"] = 3
    report["blast_radius"].append(
        {
            "vulnerability_id": "CVE-2026-0003",
            "package": "fastapi@0.115.0",
            "ecosystem": "pypi",
            "severity": "medium",
        }
    )
    store.record_scan_report(report, source="cli")

    assert store.query("SELECT total_vulnerabilities FROM scan_runs WHERE scan_id = ?", ("scan-1",)) == [{"total_vulnerabilities": 3}]
    assert store.query("SELECT COUNT(*) AS count FROM scan_findings WHERE scan_id = ?", ("scan-1",)) == [{"count": 3}]


def test_history_save_dual_writes_local_analytics(monkeypatch, tmp_path):
    import agent_bom.db.local_analytics as local_analytics
    import agent_bom.history as history

    analytics_path = tmp_path / "analytics.sqlite"
    monkeypatch.setattr(history, "HISTORY_DIR", tmp_path / "history")
    monkeypatch.setattr(local_analytics, "LOCAL_ANALYTICS_DB", str(analytics_path))

    saved_path = history.save_report(_report("saved-scan"))

    assert saved_path.exists()
    with sqlite3.connect(analytics_path) as conn:
        rows = conn.execute("SELECT scan_id, source, artifact_path FROM scan_runs").fetchall()
    assert rows == [("saved-scan", "cli", str(saved_path))]
