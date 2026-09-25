"""Comparable history must not turn partial collections into remediation claims."""

from __future__ import annotations

import sqlite3

import pytest

from agent_bom.api.models import ScanRequest
from agent_bom.api.trend_comparison import public_trend_point, retain_open_interval, scan_scope_id
from agent_bom.api.trend_recording import trend_point_from_scan_result
from agent_bom.baseline import SQLiteTrendStore


def point(scan="one", timestamp="2026-09-01T00:00:00Z", ids=("CVE-1",), *, scope="repo:a", outcome="complete", tenant="a"):
    result = {
        "scan_id": scan,
        "generated_at": timestamp,
        "posture_scorecard": {"grade": "A", "score": 90},
        "scan_run": {"outcome": outcome, "scopes": [{"name": "packages", "status": outcome}]},
        "scan_sources": ["repo"],
        "findings": [
            {
                "canonical_id": "finding:" + id,
                "asset": {"canonical_id": "asset:p"},
                "cve_id": id,
                "first_seen": timestamp,
                "observed_at": "2026-08-31T00:00:00Z",
            }
            for id in ids
        ],
    }
    value = trend_point_from_scan_result(result, tenant_id=tenant, scope_id=scope)
    assert value is not None
    return value


def test_alias_matching_dedup_and_absence_is_not_verified_remediation():
    old = point(ids=("GHSA-1", "GHSA-1", "CVE-2"))
    current = point("two", "2026-09-02T00:00:00Z", ("CVE-1", "CVE-3"))
    old.comparison_metadata["observations"][0]["keys"].extend(current.comparison_metadata["observations"][0]["keys"])
    payload = public_trend_point(current, old)
    assert payload["comparison"] == {
        "status": "comparable",
        "reason": None,
        "previous_scan_id": "one",
        "new_findings": 1,
        "still_open": 1,
        "no_longer_detected": 1,
    }
    assert payload["verified_remediations"] is None
    assert payload["verified_remediation_duration_days"] is None


@pytest.mark.parametrize("kind", ["partial", "scope", "tenant", "coverage", "version", "legacy", "identities"])
def test_noncomparable_snapshots_never_report_removed_findings(kind):
    old = point()
    current = point("two", "2026-09-02T00:00:00Z", ())
    if kind == "partial":
        old.comparison_metadata["collection_coverage"] = "partial"
    elif kind == "scope":
        current.comparison_metadata["scope_id"] = "repo:b"
    elif kind == "tenant":
        current.tenant_id = "b"
    elif kind == "coverage":
        current.comparison_metadata["coverage_key"] = "other"
    elif kind == "version":
        current.comparison_metadata["measurement_version"] = 2
    elif kind == "legacy":
        current.comparison_metadata = {}
    else:
        current.comparison_metadata["identities_complete"] = False
    comparison = public_trend_point(current, old)["comparison"]
    assert comparison["status"] == "unavailable"
    assert comparison["new_findings"] is None
    assert comparison["no_longer_detected"] is None


def test_open_interval_carries_forward_but_reopened_finding_has_new_interval():
    old = point()
    current = point("two", "2026-09-03T00:00:00Z")
    retain_open_interval(current, [old])
    rendered = public_trend_point(current, old)
    assert rendered["open_finding_age_days"] == 2
    assert rendered["evidence_age_days"] == 3
    absent = point("three", "2026-09-04T00:00:00Z", ())
    reopened = point("four", "2026-09-05T00:00:00Z")
    retain_open_interval(reopened, [old, current, absent])
    assert public_trend_point(reopened, absent)["open_finding_age_days"] == 0
    assert public_trend_point(reopened, absent)["comparison"]["new_findings"] == 1


def test_missing_or_future_observation_timestamps_are_not_replaced_by_page_time():
    current = point()
    row = current.comparison_metadata["observations"][0]
    row["first_seen"] = None
    row["observed_at"] = "2999-01-01T00:00:00Z"
    rendered = public_trend_point(current, None)
    assert rendered["open_finding_age_days"] is None
    assert rendered["evidence_age_days"] is None
    assert rendered["age_sample_count"] == rendered["evidence_sample_count"] == 0


def test_sqlite_migrates_legacy_rows_and_idempotently_persists_metadata(tmp_path):
    path = tmp_path / "trends.db"
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE trend_history (id INTEGER PRIMARY KEY, timestamp TEXT, total_vulns INTEGER,
                 critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, posture_score REAL, posture_grade TEXT)""")
    conn.execute("INSERT INTO trend_history VALUES (1,'2026-01-01T00:00:00Z',1,0,1,0,0,90,'A')")
    conn.commit()
    conn.close()
    store = SQLiteTrendStore(str(path))
    assert store.get_history()[0].comparison_metadata == {}
    current = point()
    store.record(current)
    store.record(current)
    assert len(store.get_history(tenant_id="a")) == 1
    assert store.get_history(tenant_id="a")[0].comparison_metadata == current.comparison_metadata
    assert store.get_history(tenant_id="b") == []


def test_explicit_target_scope_is_stable_and_ambient_target_is_unknown():
    assert scan_scope_id(ScanRequest()) is None
    assert scan_scope_id(ScanRequest(k8s=True)) is None
    a = ScanRequest(repo_url="https://example.com/a.git")
    assert scan_scope_id(a) == scan_scope_id(a.model_copy(update={"format": "html"}))
    assert scan_scope_id(a) != scan_scope_id(ScanRequest(repo_url="https://example.com/b.git"))
    assert scan_scope_id(a.model_copy(update={"discover_host": True})) is None


def test_serialized_finding_contract_preserves_advisory_alias_match():
    from agent_bom.api.trend_comparison import comparison_metadata
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType

    asset = Asset(name="pillow", asset_type="package", identifier="pkg:pypi/pillow@9.0.0")
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=asset,
        severity="HIGH",
        cve_id="CVE-2023-4863",
        evidence={"advisory_aliases": ["GHSA-j7hp-h8jx-5ppr"]},
    )
    report = {"findings": [finding.to_dict()], "scan_run": {"outcome": "complete"}}
    metadata = comparison_metadata(report, "repo:a")
    assert metadata["identities_complete"] is True
    assert len(metadata["observations"][0]["keys"]) == 2


@pytest.mark.asyncio
async def test_api_selects_scope_and_preserves_legacy_history(monkeypatch):
    from starlette.requests import Request

    from agent_bom.api.routes import enterprise
    from agent_bom.baseline import InMemoryTrendStore

    store = InMemoryTrendStore()
    for row in [point(), point("two", "2026-09-02T00:00:00Z"), point("other", scope="repo:b"), point("foreign", tenant="b")]:
        store.record(row)
    monkeypatch.setattr(enterprise, "_get_trend_store", lambda: store)
    monkeypatch.setattr(enterprise, "require_request_tenant_id", lambda request: "a")
    request = Request({"type": "http", "headers": []})
    payload = await enterprise.get_trends(request, scope_id="repo:a")
    assert payload["count"] == 2
    assert payload["data_points"][0]["comparison"]["still_open"] == 1
    assert payload["available_scopes"] == ["repo:a", "repo:b"]
    assert payload["age_statistic"] == "median"
    assert payload["freshness_reference"] == "scan_completion"
    assert "observations" not in str(payload)


def test_inmemory_retention_does_not_evict_other_tenants():
    from agent_bom.baseline import InMemoryTrendStore

    store = InMemoryTrendStore()
    store.record(point("original", tenant="b"))
    for index in range(370):
        store.record(point(str(index)))
    assert len(store.get_history(limit=1000, tenant_id="a")) == 365
    assert len(store.get_history(tenant_id="b")) == 1


@pytest.mark.parametrize("limit", ["MAX_COMPARISON_OBSERVATIONS", "MAX_COMPARISON_METADATA_BYTES"])
def test_oversized_comparison_preserves_basic_metrics_and_honest_timestamp_samples(monkeypatch, limit):
    from agent_bom.api import trend_comparison

    monkeypatch.setattr(trend_comparison, limit, 1)
    current = point(ids=("CVE-1", "CVE-2", "CVE-3"))
    assert current.comparison_metadata["observations"] == []
    rendered = public_trend_point(current, None)
    assert rendered["comparison"]["reason"] == "comparison_limit_exceeded"
    assert rendered["comparison"]["no_longer_detected"] is None
    assert rendered["age_sample_count"] == 3
    assert rendered["evidence_sample_count"] == 3
    assert rendered["evidence_age_days"] == 1


def test_sqlite_history_metadata_is_budgeted_before_transfer(tmp_path):
    store = SQLiteTrendStore(str(tmp_path / "budget.db"))
    for index in range(9):
        row = point(str(index), f"2026-09-{index + 1:02d}T00:00:00Z")
        row.comparison_metadata = {"padding": "x" * (2 * 1024 * 1024)}
        store.record(row)
    rows = store.get_history(tenant_id="a")
    assert rows[-1].comparison_metadata == {"history_processing_limit": True}
    assert sum(len(str(row.comparison_metadata)) for row in rows) < 16 * 1024 * 1024
    assert all(row.timestamp for row in rows)


def test_real_finding_serialization_carries_observed_runtime_source_time():
    from agent_bom.api.trend_comparison import finding_observed_at
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType

    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="worker", asset_type="container"),
        severity="HIGH",
        workload_runtime_evidence={"latest_observed_at": "2026-09-01T00:00:00Z", "signal_count": 1},
    )
    row = finding.to_dict()
    assert "observed_at" not in row
    assert finding_observed_at(row) == "2026-09-01T00:00:00+00:00"
    finding.workload_runtime_evidence = None
    assert finding_observed_at(finding.to_dict()) is None


def test_connection_scope_changes_on_target_edit_not_credential_rotation():
    from dataclasses import replace

    from agent_bom.api.connection_store import CloudConnectionRecord
    from agent_bom.api.trend_comparison import connection_scope_id

    record = CloudConnectionRecord(
        id="connection",
        tenant_id="a",
        provider="aws",
        display_name="account",
        role_ref="arn:aws:iam::111111111111:role/read",
        external_id_encrypted="ciphertext",
    )
    assert connection_scope_id(record) == connection_scope_id(replace(record, external_id_encrypted="rotated"))
    assert connection_scope_id(record) != connection_scope_id(replace(record, regions=["us-east-1"]))
    assert connection_scope_id(record) != connection_scope_id(replace(record, role_ref="arn:aws:iam::222222222222:role/read"))
