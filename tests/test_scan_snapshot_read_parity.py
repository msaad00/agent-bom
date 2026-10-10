"""Differential qualification of snapshot reads against retained finding folds."""

from copy import deepcopy
from unittest.mock import Mock

import pytest

from agent_bom.api.findings_current import current_scan_findings
from agent_bom.api.routes import scan
from tests.api.test_partial_rescan_findings import attempted
from tests.api.test_scan_job_sla_history import job
from tests.test_scan_snapshot_reads import put
from tests.test_scan_snapshot_reads import snapshots as snapshots  # noqa: F401


def fold(jobs, *, since=None, scan_id=None, require_authoritative_evidence=False):
    return current_scan_findings(
        jobs,
        since=since,
        scan_id=scan_id,
        iter_findings=scan._iter_scan_findings,
        require_authoritative_evidence=require_authoritative_evidence,
    )


@pytest.mark.parametrize("scenario", ["history", "partial", "empty", "parent", "window", "scan_id", "failed", "alias", "scope"])
@pytest.mark.parametrize("authoritative", [False, True])
@pytest.mark.parametrize("mode", ["qualify", "fast"])
def test_snapshot_fold_matches_current_selection_lifecycle_and_history(snapshots, monkeypatch, scenario, authoritative, mode):
    old, new = job(8), job(9)
    old.result["findings"][0].update(sla_due_at="2026-12-01T00:00:00+00:00", sla_due_at_source="explicit")
    kwargs = {"require_authoritative_evidence": authoritative}
    if scenario == "partial":
        new = attempted()
    elif scenario == "empty":
        new.result["findings"] = []
    elif scenario == "parent":
        new.child_job_ids = [old.job_id]
    elif scenario == "window":
        kwargs["since"] = "2026-08-31T00:00:00+00:00"
    elif scenario == "scan_id":
        kwargs["scan_id"] = old.job_id
    elif scenario == "failed":
        new.result["scan_run"] = {"outcome": "failed"}
    elif scenario == "alias":
        new.result["scan_id"] = "public-scan-alias"
        kwargs["scan_id"] = "public-scan-alias"
    elif scenario == "scope":
        new.target = {"path": "another-repository"}
    jobs = [new, old]
    for row in jobs:
        put(snapshots, row)
    before = deepcopy([row.model_dump(mode="json") for row in jobs])
    spy = Mock(wraps=snapshots.get_rows)
    monkeypatch.setattr(snapshots, "get_rows", spy)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
    expected = fold(jobs, **kwargs)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "1" if mode == "qualify" else "0")
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "1" if mode == "fast" else "0")
    assert fold(jobs, **kwargs) == expected
    assert spy.called
    assert [row.model_dump(mode="json") for row in jobs] == before


def test_mixed_representations_preserve_enrichment_order_without_fallback(snapshots, monkeypatch, caplog):
    row = job(9)
    base = {"id": "one", "canonical_id": "one", "title": "one", "source": "secret_scan"}
    row.result["findings"] = [base, {**base, "affected_servers": ["server-a"]}]
    put(snapshots, row)

    def attach(finding, *_args, **_kwargs):
        finding["runtime_evidence"] = {"servers_seen": list(finding.get("affected_servers", []))}

    monkeypatch.setattr(scan, "attach_runtime_evidence_to_finding", attach)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
    expected = scan._iter_scan_findings(row)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "1")
    assert scan._iter_scan_findings(row) == expected
    assert expected[0]["affected_servers"] == ["server-a"]
    assert expected[0]["runtime_evidence"] == {"servers_seen": []}
    assert "outcome=mismatch" not in caplog.text


def test_real_report_keeps_nested_packages_blast_radius_and_reach(snapshots, monkeypatch):
    from tests.api.test_api_scan_findings_wiring import _report_with_known_vuln

    row = job(9)
    row.result = _report_with_known_vuln()
    put(snapshots, row)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
    expected = scan._iter_scan_findings(row)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "1")
    assert scan._iter_scan_findings(row) == expected
    assert any(finding.get("effective_reach") for finding in expected)


def test_live_enrichment_is_not_frozen_at_snapshot_time(snapshots, monkeypatch):
    row = job(9)
    put(snapshots, row)
    live = {"signal": "first"}

    def attach(finding, *_args, **_kwargs):
        finding["runtime_evidence"] = dict(live)

    monkeypatch.setattr(scan, "attach_runtime_evidence_to_finding", attach)
    for signal in ("first", "changed"):
        live["signal"] = signal
        monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
        expected = scan._iter_scan_findings(row)
        monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "1")
        actual = scan._iter_scan_findings(row)
        assert actual == expected
        assert actual[0]["runtime_evidence"]["signal"] == signal
    assert "runtime_evidence" not in snapshots.get_rows(row.tenant_id, row.job_id)[0]["payload"]


def test_snapshot_reads_preserve_http_findings_and_export_contracts(snapshots, monkeypatch):
    from agent_bom.api import stores
    from agent_bom.api.store import InMemoryJobStore
    from tests.api.test_scan_job_sla_history import get_rows
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env

    jobs = InMemoryJobStore()
    monkeypatch.setattr(stores, "_store", jobs)
    row = job(9)
    jobs.put(row)
    put(snapshots, row)
    spy = Mock(wraps=snapshots.get_rows)
    monkeypatch.setattr(snapshots, "get_rows", spy)
    enable_trusted_proxy_env()
    try:
        monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
        expected_http = get_rows()
        expected_export = scan.iter_tenant_scan_spine_findings(row.tenant_id)
        monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "1")
        assert get_rows() == expected_http
        assert scan.iter_tenant_scan_spine_findings(row.tenant_id) == expected_export
        assert spy.call_count >= 2
        assert expected_http and expected_export
    finally:
        disable_trusted_proxy_env()


def test_owner_and_suppression_are_projected_after_snapshot_verification(snapshots, monkeypatch):
    from agent_bom.api.routes import enterprise

    row = job(9)
    put(snapshots, row)
    live = {"owner": "first", "suppressed": False}
    monkeypatch.setattr(enterprise, "build_tenant_triage_owner_index", lambda _: {"present": True})
    monkeypatch.setattr(enterprise, "triage_owner_for", lambda *_args, **_kwargs: live["owner"])
    monkeypatch.setattr(scan, "project_current_suppressions", lambda rows, _: [{**r, "suppressed": live["suppressed"]} for r in rows])
    for owner, suppressed in [("first", False), ("changed", True)]:
        live.update(owner=owner, suppressed=suppressed)
        monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
        expected = scan._iter_scan_findings(row)
        monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "1")
        actual = scan._iter_scan_findings(row)
        assert actual == expected
        assert actual[0]["owner"] == owner and actual[0]["suppressed"] is suppressed
