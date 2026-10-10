"""Fast reads must actually skip rebuilding, without changing evidence semantics."""

from unittest.mock import Mock

import pytest

from agent_bom.api.routes import scan
from tests.test_scan_snapshot import _job
from tests.test_scan_snapshot_reads import put
from tests.test_scan_snapshot_reads import snapshots as snapshots  # noqa: F401


def test_fast_path_skips_legacy_collection_and_graph(snapshots, monkeypatch):
    from tests.api.test_api_scan_findings_wiring import _report_with_known_vuln

    job = _job(result=_report_with_known_vuln())
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
    expected = scan._iter_scan_findings(job)
    put(snapshots, job)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "1")
    collector = Mock(wraps=scan.collect_scan_findings)
    reach = Mock(wraps=scan._effective_reach_lookup)
    monkeypatch.setattr(scan, "collect_scan_findings", collector)
    monkeypatch.setattr(scan, "_effective_reach_lookup", reach)
    assert scan._iter_scan_findings(job) == expected
    collector.assert_not_called()
    reach.assert_not_called()


def test_fast_duplicate_representations_enrich_before_merge(snapshots, monkeypatch):
    job = _job()
    base = {"id": "one", "canonical_id": "one", "source": "secret_scan"}
    job.result["findings"] = [base, {**base, "affected_servers": ["server-a"]}]
    monkeypatch.setattr(
        scan,
        "attach_runtime_evidence_to_finding",
        lambda row, *a, **kw: row.update(runtime_evidence={"seen": list(row.get("affected_servers", []))}),
    )
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
    expected = scan._iter_scan_findings(job)
    put(snapshots, job)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "1")
    collector = Mock(wraps=scan.collect_scan_findings)
    monkeypatch.setattr(scan, "collect_scan_findings", collector)
    assert scan._iter_scan_findings(job) == expected
    assert expected[0]["runtime_evidence"] == {"seen": []}
    collector.assert_not_called()


@pytest.mark.parametrize("change", ["title", "type", "timestamp", "tenant"])
def test_fast_falls_back_on_changed_source(snapshots, monkeypatch, change):
    job = _job()
    put(snapshots, job)
    if change == "title":
        job.result["findings"][0]["title"] = "changed"
    elif change == "type":
        job.result["findings"][0]["confidence"] = True
    elif change == "timestamp":
        job.completed_at = "2026-10-10T00:00:00Z"
    else:
        job.tenant_id = "other"
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
    expected = scan._iter_scan_findings(job)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "1")
    assert scan._iter_scan_findings(job) == expected


@pytest.mark.parametrize("damage", ["payload", "reach", "missing", "old_version", "count"])
def test_fast_corrupt_or_stale_snapshot_rebuilds(snapshots, monkeypatch, damage):
    job = _job()
    meta, rows = put(snapshots, job)
    if damage == "payload":
        rows[1]["payload"]["title"] = "corrupted"
    elif damage == "reach":
        rows[0]["payload"]["reach"] = {"CVE": {"composite": True}}
    elif damage == "missing":
        rows.pop()
    elif damage == "old_version":
        meta["row_schema_version"] = 1
    else:
        meta["row_count"] = True
    snapshots.put_snapshot(job.tenant_id, job.job_id, meta, rows)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
    expected = scan._iter_scan_findings(job)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "1")
    collector = Mock(wraps=scan.collect_scan_findings)
    monkeypatch.setattr(scan, "collect_scan_findings", collector)
    assert scan._iter_scan_findings(job) == expected
    collector.assert_called_once()


def test_qualification_takes_precedence_over_fast(snapshots, monkeypatch):
    job = _job()
    put(snapshots, job)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "1")
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "1")
    collector = Mock(wraps=scan.collect_scan_findings)
    monkeypatch.setattr(scan, "collect_scan_findings", collector)
    scan._iter_scan_findings(job)
    collector.assert_called_once()
