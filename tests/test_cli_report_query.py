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


def test_report_storage_reports_counts_and_configured_caps(tmp_path, monkeypatch):
    db_path = tmp_path / "local.sqlite"
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_EVENTS", "9")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_PACKAGES", "99")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_FINDINGS", "19")
    LocalAnalyticsStore(db_path).record_scan_report(_scan_report(), source="cli")

    result = CliRunner().invoke(
        main,
        ["report", "storage", "--db", str(db_path), "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["scan_runs"] == 1
    assert payload["findings"] == 1
    assert payload["packages"] == 0
    assert payload["limits"] == {"scan_runs": 9, "findings": 19, "packages": 99}
    assert payload["bytes"] > 0


def test_report_prune_is_dry_run_until_apply(tmp_path, monkeypatch):
    db_path = tmp_path / "local.sqlite"
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_EVENTS", "100")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_PACKAGES", "100")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_FINDINGS", "100")
    store = LocalAnalyticsStore(db_path)
    for index in range(3):
        report = _scan_report()
        report["scan_id"] = f"scan-{index}"
        report["generated_at"] = f"2026-05-1{index}T16:00:00+00:00"
        store.record_scan_report(report, source="cli")

    dry_run = CliRunner().invoke(
        main,
        ["report", "prune", "--db", str(db_path), "--max-runs", "1", "--format", "json"],
    )
    assert dry_run.exit_code == 0, dry_run.output
    dry_payload = json.loads(dry_run.output)
    assert dry_payload["applied"] is False
    assert dry_payload["deleted_runs"] == 2
    assert len(store.list_scan_runs(limit=10)) == 3

    applied = CliRunner().invoke(
        main,
        [
            "report",
            "prune",
            "--db",
            str(db_path),
            "--max-runs",
            "1",
            "--apply",
            "--format",
            "json",
        ],
    )
    assert applied.exit_code == 0, applied.output
    applied_payload = json.loads(applied.output)
    assert applied_payload["applied"] is True
    assert applied_payload["deleted_runs"] == 2
    assert len(store.list_scan_runs(limit=10)) == 1


def test_report_prune_requires_apply_for_compaction(tmp_path):
    result = CliRunner().invoke(
        main,
        ["report", "prune", "--db", str(tmp_path / "local.sqlite"), "--compact"],
    )

    assert result.exit_code != 0
    assert "--compact requires --apply" in result.output
