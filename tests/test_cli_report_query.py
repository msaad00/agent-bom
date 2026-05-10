from __future__ import annotations

import json

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.db.local_analytics import LocalAnalyticsStore


def _scan_report() -> dict:
    return {
        "scan_id": "query-scan",
        "generated_at": "2026-05-10T16:00:00+00:00",
        "findings": [
            {
                "id": "finding-1",
                "vulnerability_id": "CVE-2026-0001",
                "package_name": "fastapi",
                "package_version": "0.115.0",
                "ecosystem": "pypi",
                "severity": "high",
                "risk_score": 8.1,
            }
        ],
    }


def test_report_query_outputs_local_analytics_rows_as_json(tmp_path):
    db_path = tmp_path / "local.sqlite"
    LocalAnalyticsStore(db_path).record_scan_report(_scan_report(), source="cli")

    result = CliRunner().invoke(
        main,
        [
            "report",
            "query",
            "SELECT severity, COUNT(*) AS count FROM scan_findings GROUP BY severity",
            "--db",
            str(db_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["count"] == 1
    assert payload["rows"] == [{"severity": "high", "count": 1}]


def test_report_query_outputs_local_analytics_rows_as_table(tmp_path):
    db_path = tmp_path / "local.sqlite"
    LocalAnalyticsStore(db_path).record_scan_report(_scan_report(), source="cli")

    result = CliRunner().invoke(
        main,
        [
            "report",
            "query",
            "SELECT package_name, severity FROM scan_findings ORDER BY package_name",
            "--db",
            str(db_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "package_name  severity" in result.output
    assert "fastapi       high" in result.output


def test_report_query_rejects_write_sql(tmp_path):
    db_path = tmp_path / "local.sqlite"
    LocalAnalyticsStore(db_path).record_scan_report(_scan_report(), source="cli")

    result = CliRunner().invoke(
        main,
        ["report", "query", "DELETE FROM scan_findings", "--db", str(db_path)],
    )

    assert result.exit_code != 0
    assert "read-only" in result.output
