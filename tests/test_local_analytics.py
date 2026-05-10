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
    assert runs[0]["run_id"].startswith("local-run-")
    assert runs[0]["scan_id"] == "scan-1"
    assert runs[0]["total_packages"] == 2
    assert runs[0]["critical_findings"] == 1
    assert runs[0]["high_findings"] == 1

    severity_rows = store.query("SELECT severity, COUNT(*) AS count FROM scan_findings GROUP BY severity ORDER BY severity")
    assert severity_rows == [{"severity": "critical", "count": 1}, {"severity": "high", "count": 1}]

    package_rows = store.query("SELECT package_name FROM scan_packages ORDER BY package_name")
    assert package_rows == [{"package_name": "fastapi"}, {"package_name": "uvicorn"}]


def test_local_analytics_store_records_repeated_artifact_as_distinct_runs(tmp_path):
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

    runs = store.query("SELECT run_id, total_vulnerabilities FROM scan_runs WHERE scan_id = ? ORDER BY rowid", ("scan-1",))
    assert [row["total_vulnerabilities"] for row in runs] == [2, 3]
    assert len({row["run_id"] for row in runs}) == 2
    assert store.query("SELECT COUNT(*) AS count FROM scan_findings WHERE scan_id = ?", ("scan-1",)) == [{"count": 5}]


def test_local_analytics_store_records_unified_non_cve_findings(tmp_path):
    store = LocalAnalyticsStore(tmp_path / "local.sqlite")
    report = _report()
    report.pop("blast_radius")
    report["findings"] = [
        {
            "schema_version": "1",
            "id": "prompt-risk-1",
            "finding_type": "PROMPT_SECURITY",
            "source": "PROMPT_SCAN",
            "asset": {
                "name": "system.prompt",
                "asset_type": "prompt_template",
                "identifier": "prompts/system.prompt",
            },
            "severity": "high",
            "title": "Prompt injection pattern",
            "description": "Prompt contains override language.",
        }
    ]

    store.record_scan_report(report, source="cli")

    rows = store.query(
        """
        SELECT finding_key, vulnerability_id, finding_type, source, schema_version, title, asset_json
        FROM scan_findings
        """
    )
    assert rows[0]["finding_key"] == "prompt-risk-1"
    assert rows[0]["vulnerability_id"] == ""
    assert rows[0]["finding_type"] == "PROMPT_SECURITY"
    assert rows[0]["source"] == "PROMPT_SCAN"
    assert rows[0]["schema_version"] == "1"
    assert rows[0]["title"] == "Prompt injection pattern"
    assert '"asset_type": "prompt_template"' in rows[0]["asset_json"]


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


def test_local_analytics_store_migrates_initial_scan_id_keyed_schema(tmp_path):
    db_path = tmp_path / "local.sqlite"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE scan_runs (
                scan_id TEXT PRIMARY KEY,
                generated_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                source TEXT NOT NULL,
                artifact_path TEXT,
                total_agents INTEGER NOT NULL DEFAULT 0,
                total_packages INTEGER NOT NULL DEFAULT 0,
                total_vulnerabilities INTEGER NOT NULL DEFAULT 0,
                critical_findings INTEGER NOT NULL DEFAULT 0,
                high_findings INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE scan_findings (
                scan_id TEXT NOT NULL,
                finding_key TEXT NOT NULL,
                vulnerability_id TEXT NOT NULL,
                package_name TEXT NOT NULL,
                package_version TEXT NOT NULL,
                package_ref TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score REAL NOT NULL DEFAULT 0,
                affected_agents_json TEXT NOT NULL DEFAULT '[]',
                affected_servers_json TEXT NOT NULL DEFAULT '[]',
                PRIMARY KEY (scan_id, finding_key)
            );
            CREATE TABLE scan_packages (
                scan_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                server_name TEXT NOT NULL,
                package_name TEXT NOT NULL,
                package_version TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                purl TEXT,
                PRIMARY KEY (scan_id, agent_name, server_name, package_name, package_version, ecosystem)
            );
            INSERT INTO scan_runs(scan_id, generated_at, recorded_at, source)
            VALUES ('legacy-scan', '2026-05-10T16:00:00+00:00', '2026-05-10T16:01:00+00:00', 'cli');
            INSERT INTO scan_findings(
                scan_id, finding_key, vulnerability_id, package_name, package_version,
                package_ref, ecosystem, severity, risk_score
            )
            VALUES ('legacy-scan', 'CVE-2026-0001|pkg|pypi', 'CVE-2026-0001', 'pkg', '1.0', 'pkg@1.0', 'pypi', 'high', 7.1);
            INSERT INTO scan_packages(scan_id, agent_name, server_name, package_name, package_version, ecosystem)
            VALUES ('legacy-scan', 'agent', 'server', 'pkg', '1.0', 'pypi');
            """
        )

    store = LocalAnalyticsStore(db_path)

    assert store.list_scan_runs()[0]["run_id"] == "legacy-scan"
    assert store.query("SELECT run_id, scan_id, source FROM scan_findings") == [
        {"run_id": "legacy-scan", "scan_id": "legacy-scan", "source": ""}
    ]
    assert store.query("SELECT run_id, scan_id, package_name FROM scan_packages") == [
        {"run_id": "legacy-scan", "scan_id": "legacy-scan", "package_name": "pkg"}
    ]
