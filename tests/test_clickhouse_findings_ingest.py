"""Tests for the best-effort ClickHouse findings-ingest tail of #3499.

The CLI scan-completion history hook (``history.save_report``) mirrors the
scan's findings/summary into ClickHouse when a URL is configured, alongside
the local SQLite analytics store. All tests use a fake in-memory store — no
real ClickHouse instance is required.
"""

from __future__ import annotations

import sqlite3

import pytest

from agent_bom.api.clickhouse_store import (
    build_scan_ingest_rows,
    ingest_scan_report_best_effort,
)

CLICKHOUSE_ENV = "AGENT_BOM_CLICKHOUSE_URL"


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
        "posture_scorecard": {"grade": "B"},
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2026-0001",
                "package": "fastapi@0.115.0",
                "package_name": "fastapi",
                "package_version": "0.115.0",
                "ecosystem": "pypi",
                "severity": "critical",
                "cvss_score": 9.4,
                "epss_score": 0.42,
                "primary_advisory_source": "ghsa",
                "affected_agents": ["desktop-agent"],
            },
            {
                "vulnerability_id": "CVE-2026-0002",
                "package": "uvicorn@0.32.0",
                "ecosystem": "pypi",
                "severity": "high",
                "affected_agents": ["desktop-agent"],
            },
        ],
    }


class FakeStore:
    """Captures record_scan / record_scan_metadata calls."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.scans: list[tuple] = []
        self.metadata: list[tuple] = []
        self.closed = False

    def record_scan(self, scan_id, agent_name, vulns, *, tenant_id="default"):
        if self.fail:
            raise RuntimeError("simulated ClickHouse outage")
        self.scans.append((scan_id, agent_name, list(vulns), tenant_id))

    def record_scan_metadata(self, metadata, *, tenant_id="default"):
        if self.fail:
            raise RuntimeError("simulated ClickHouse outage")
        self.metadata.append((dict(metadata), tenant_id))

    def close(self):
        self.closed = True


# ─── Row construction ───────────────────────────────────────────────────────


def test_build_scan_ingest_rows_maps_findings_and_metadata():
    scan_id, findings_by_agent, metadata = build_scan_ingest_rows(_report("scan-xyz"))

    assert scan_id == "scan-xyz"
    assert set(findings_by_agent) == {"desktop-agent"}
    findings = findings_by_agent["desktop-agent"]
    assert len(findings) == 2

    first = findings[0]
    # Columns must line up with vulnerability_scans / record_scan expectations.
    assert first["package_name"] == "fastapi"
    assert first["package_version"] == "0.115.0"
    assert first["ecosystem"] == "pypi"
    assert first["cve_id"] == "CVE-2026-0001"
    assert first["cvss_score"] == pytest.approx(9.4)
    assert first["epss_score"] == pytest.approx(0.42)
    assert first["severity"] == "critical"
    assert first["source"] == "ghsa"

    assert metadata["scan_id"] == "scan-xyz"
    assert metadata["agent_count"] == 1
    assert metadata["package_count"] == 2
    assert metadata["vuln_count"] == 2
    assert metadata["critical_count"] == 1
    assert metadata["high_count"] == 1  # one "high" blast entry
    assert metadata["posture_grade"] == "B"
    assert metadata["source"] == "cli"


def test_build_scan_ingest_rows_derives_stable_scan_id_when_absent():
    report = _report()
    report.pop("scan_id")
    scan_id_a, _, _ = build_scan_ingest_rows(report)
    scan_id_b, _, _ = build_scan_ingest_rows(report)
    # Deterministic from generated_at so re-saves dedup instead of double count.
    assert scan_id_a == scan_id_b
    assert scan_id_a.startswith("local-")


def test_build_scan_ingest_rows_keeps_unattributed_findings():
    report = _report()
    report["blast_radius"][0].pop("affected_agents")
    _, findings_by_agent, _ = build_scan_ingest_rows(report)
    # Finding with no affected agent is recorded under an empty agent name, not
    # silently dropped.
    assert "" in findings_by_agent
    assert findings_by_agent[""][0]["cve_id"] == "CVE-2026-0001"


def test_build_scan_ingest_rows_handles_empty_report():
    scan_id, findings_by_agent, metadata = build_scan_ingest_rows({})
    assert scan_id  # falls back to a generated uuid
    assert findings_by_agent == {}
    assert metadata["vuln_count"] == 0


# ─── Best-effort ingest gating ──────────────────────────────────────────────


def test_ingest_noop_when_unconfigured(monkeypatch):
    monkeypatch.delenv(CLICKHOUSE_ENV, raising=False)

    # No url, no env, no store → clean no-op, and it must never construct a store.
    def _boom(*_a, **_k):  # pragma: no cover - must not be called
        raise AssertionError("ClickHouseAnalyticsStore constructed while unconfigured")

    monkeypatch.setattr("agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore", _boom)
    assert ingest_scan_report_best_effort(_report()) is None


def test_ingest_records_when_store_supplied():
    store = FakeStore()
    scan_id = ingest_scan_report_best_effort(_report("scan-live"), store=store, tenant_id="acme")

    assert scan_id == "scan-live"
    assert len(store.scans) == 1
    recorded_scan_id, agent_name, vulns, tenant_id = store.scans[0]
    assert recorded_scan_id == "scan-live"
    assert agent_name == "desktop-agent"
    assert len(vulns) == 2
    assert tenant_id == "acme"
    assert len(store.metadata) == 1
    assert store.metadata[0][1] == "acme"


def test_ingest_constructs_store_from_url(monkeypatch):
    created = {}

    def _fake_store_cls(*, url):
        created["url"] = url
        return FakeStore()

    monkeypatch.setattr("agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore", _fake_store_cls)
    scan_id = ingest_scan_report_best_effort(_report(), url="http://clickhouse:8123")
    assert scan_id == "scan-1"
    assert created["url"] == "http://clickhouse:8123"


def test_ingest_is_best_effort_on_store_error():
    store = FakeStore(fail=True)
    # Client error must be swallowed, returning None rather than raising.
    assert ingest_scan_report_best_effort(_report(), store=store) is None


def test_ingest_reads_url_from_env(monkeypatch):
    monkeypatch.setenv(CLICKHOUSE_ENV, "http://ch-env:8123")
    store = FakeStore()

    def _fake_store_cls(*, url):
        assert url == "http://ch-env:8123"
        return store

    monkeypatch.setattr("agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore", _fake_store_cls)
    assert ingest_scan_report_best_effort(_report()) == "scan-1"
    assert len(store.scans) == 1


# ─── history.save_report integration ────────────────────────────────────────


def _isolate_history(monkeypatch, tmp_path):
    import agent_bom.db.local_analytics as local_analytics
    import agent_bom.history as history

    monkeypatch.setattr(history, "HISTORY_DIR", tmp_path / "history")
    monkeypatch.setattr(local_analytics, "LOCAL_ANALYTICS_DB", str(tmp_path / "analytics.sqlite"))
    return history


def test_save_report_noop_without_clickhouse_url(monkeypatch, tmp_path):
    monkeypatch.delenv(CLICKHOUSE_ENV, raising=False)
    history = _isolate_history(monkeypatch, tmp_path)

    def _boom(*_a, **_k):  # pragma: no cover - must not be called
        raise AssertionError("ClickHouse ingest attempted while unconfigured")

    monkeypatch.setattr("agent_bom.api.clickhouse_store.ingest_scan_report_best_effort", _boom)
    saved = history.save_report(_report("no-ch"))
    assert saved.exists()
    # Local analytics still written.
    with sqlite3.connect(tmp_path / "analytics.sqlite") as conn:
        assert conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 1


def test_save_report_ingests_clickhouse_when_configured(monkeypatch, tmp_path):
    monkeypatch.setenv(CLICKHOUSE_ENV, "http://ch:8123")
    history = _isolate_history(monkeypatch, tmp_path)

    store = FakeStore()
    monkeypatch.setattr(
        "agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore",
        lambda *, url: store,
    )
    saved = history.save_report(_report("with-ch"))
    assert saved.exists()
    assert len(store.scans) == 1
    assert store.scans[0][0] == "with-ch"
    assert len(store.metadata) == 1


def test_save_report_survives_clickhouse_failure(monkeypatch, tmp_path):
    monkeypatch.setenv(CLICKHOUSE_ENV, "http://ch:8123")
    history = _isolate_history(monkeypatch, tmp_path)

    def _raise(*, url):
        raise RuntimeError("simulated ClickHouse connect failure")

    monkeypatch.setattr("agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore", _raise)
    # Scan save must still succeed even though ClickHouse is unreachable.
    saved = history.save_report(_report("ch-down"))
    assert saved.exists()
    with sqlite3.connect(tmp_path / "analytics.sqlite") as conn:
        assert conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 1
