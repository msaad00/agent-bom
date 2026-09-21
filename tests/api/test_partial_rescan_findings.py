"""Incomplete collections cannot erase or refresh earlier finding evidence."""

from copy import deepcopy

import pytest

from agent_bom.api.findings_current import current_scan_findings
from agent_bom.api.routes.scan import iter_tenant_scan_spine_findings
from tests.api.test_scan_job_sla_history import get_rows, job
from tests.api.test_scan_job_sla_history import scan_store as history_store  # noqa: F401


@pytest.fixture
def scan_store(history_store):  # noqa: F811 - imported parametrized fixture
    return history_store


def attempted(month=9, *, status="permission_denied", findings=None):
    row = job(month, findings=[] if findings is None else findings)
    row.result["scan_run"] = {
        "outcome": "complete" if status == "complete" else "partial",
        "scopes": [{"name": "permissions", "requested": True, "status": status}],
    }
    return row


@pytest.mark.parametrize("status", ["permission_denied", "partial", "unavailable", "unsupported", "skipped"])
def test_incomplete_rescan_retains_original_evidence_as_unreconfirmed(scan_store, status):
    baseline, candidate = job(8), attempted(status=status)
    baseline.result["findings"][0]["provenance"] = {"source": "mcp-scan", "scan_id": baseline.job_id}
    before = deepcopy(baseline.result)
    scan_store.put(baseline)
    scan_store.put(candidate)

    rows = get_rows()
    assert len(rows) == 1
    assert rows[0]["scan_id"] == baseline.job_id
    assert rows[0]["last_observed"] == "2026-08-01T00:00:00+00:00"
    assert rows[0]["observation_status"] == "unreconfirmed"
    assert rows[0]["reconfirmation"] == {
        "scan_id": candidate.job_id,
        "attempted_at": "2026-09-01T00:00:00+00:00",
        "reason_codes": ["scan_partial", f"scope_{status}"],
    }
    assert rows[0]["provenance"]["scan_id"] == baseline.job_id
    assert scan_store.get(baseline.job_id, tenant_id=baseline.tenant_id).result == before
    assert get_rows(scan_id=candidate.job_id) == []
    exported = iter_tenant_scan_spine_findings(baseline.tenant_id)
    assert exported[0]["observation_status"] == "unreconfirmed"
    assert exported[0]["reconfirmation"] == rows[0]["reconfirmation"]


def test_partial_positive_observation_does_not_refresh_other_findings(scan_store):
    baseline, candidate = job(8), attempted()
    observed = deepcopy(baseline.result["findings"][0])
    observed.update(id="new-finding", canonical_id="new-finding", last_observed="2026-09-01T00:00:00+00:00")
    candidate.result["findings"] = [observed]
    scan_store.put(baseline)
    scan_store.put(candidate)
    rows = {row["id"]: row for row in get_rows()}
    assert len(rows) == 2
    assert rows["new-finding"]["observation_status"] == "observed"
    assert "reconfirmation" not in rows["new-finding"]
    assert rows[baseline.result["findings"][0]["id"]]["observation_status"] == "unreconfirmed"


def test_reobserved_finding_uses_candidate_provenance(scan_store):
    baseline, candidate = job(8), job(9)
    candidate.result["scan_run"] = attempted().result["scan_run"]
    candidate.result["findings"][0].update(observation_status="unreconfirmed", reconfirmation={"scan_id": "forged"})
    scan_store.put(baseline)
    scan_store.put(candidate)
    rows = get_rows()
    assert len(rows) == 1 and rows[0]["scan_id"] == candidate.job_id
    assert rows[0]["observation_status"] == "observed"
    assert "reconfirmation" not in rows[0]
    assert rows[0]["last_observed"] == "2026-09-01T00:00:00+00:00"


@pytest.mark.parametrize("status", ["complete", "legacy"])
def test_complete_or_legacy_replacement_remains_current_view_only(scan_store, status):
    baseline, partial, candidate = job(7), attempted(8), attempted(9, status="complete")
    if status == "legacy":
        candidate.result.pop("scan_run")
    for row in (partial, candidate, baseline):
        scan_store.put(row)
    assert get_rows() == []
    assert len(get_rows(scan_id=baseline.job_id)) == 1


@pytest.mark.parametrize("boundary", ["tenant", "target", "source"])
def test_unrelated_partial_attempt_cannot_qualify_other_scope(scan_store, boundary):
    baseline, candidate = job(8), attempted()
    if boundary == "tenant":
        candidate.tenant_id = "other-tenant"
    elif boundary == "target":
        candidate.target = {"path": "other-repo"}
    else:
        candidate.source_id = "other-source"
    scan_store.put(baseline)
    scan_store.put(candidate)
    rows = get_rows()
    assert len(rows) == 1 and rows[0]["observation_status"] == "observed"
    assert "reconfirmation" not in rows[0]


@pytest.mark.parametrize(
    "receipt",
    [
        {"outcome": "partial"},
        {"outcome": "complete", "issues": [{"affects_coverage": True}]},
        {"outcome": "complete", "incomplete_scope_count": 1},
        {"outcome": "complete", "scopes": [{"requested": True, "status": "permission_denied"}]},
    ],
)
def test_explicit_coverage_markers_preserve_findings(receipt):
    baseline, candidate = job(8), attempted()
    candidate.result["scan_run"] = receipt
    rows = current_scan_findings([candidate, baseline], since=None, scan_id=None, iter_findings=lambda row: row.result["findings"])
    assert len(rows) == 1 and rows[0]["observation_status"] == "unreconfirmed"


@pytest.mark.parametrize("receipt", [{}, {"issues": [{}]}, {"scopes": [{"requested": False, "status": "permission_denied"}]}])
def test_missing_or_unrequested_coverage_keeps_legacy_selection_without_inventing_proof(receipt):
    baseline, candidate = job(8), attempted()
    candidate.result["scan_run"] = receipt
    rows = current_scan_findings([baseline, candidate], since=None, scan_id=None, iter_findings=lambda row: row.result["findings"])
    assert rows == []


def test_time_window_does_not_resurrect_unloaded_prior_observations():
    baseline, candidate = job(8), attempted()
    rows = current_scan_findings(
        [baseline, candidate], since="2026-08-31T00:00:00Z", scan_id=None, iter_findings=lambda row: row.result["findings"]
    )
    assert rows == []


def test_group_counts_include_unreconfirmed_members_even_when_representative_is_fresh(scan_store):
    baseline, candidate = job(8), attempted()
    observed = deepcopy(baseline.result["findings"][0])
    observed.update(id="fresh-occurrence", canonical_id="fresh-occurrence", last_observed="2026-09-01T00:00:00+00:00", cvss_score=9.8)
    candidate.result["findings"] = [observed]
    scan_store.put(baseline)
    scan_store.put(candidate)
    groups = get_rows(group_occurrences=True)
    assert len(groups) == 1
    assert groups[0]["observation_status"] == "observed"
    assert groups[0]["occurrence_count"] == 2
    assert groups[0]["unreconfirmed_occurrence_count"] == 1
    assert {row["observation_status"] for row in groups[0]["occurrences"]} == {"observed", "unreconfirmed"}
    retained = next(row for row in groups[0]["occurrences"] if row["observation_status"] == "unreconfirmed")
    assert retained["reconfirmation"]["scan_id"] == candidate.job_id


@pytest.mark.asyncio
async def test_persisted_mcp_blast_radius_keeps_unreconfirmed_receipt(scan_store, monkeypatch):
    import json

    from agent_bom.api.routes.scan import persisted_finding_evidence
    from agent_bom.mcp_tools.analysis import blast_radius_impl

    scan_store.put(job(8))
    scan_store.put(attempted())
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "history-tenant")

    async def no_local_scan():
        raise AssertionError("Persisted findings must not fall back to local scanning")

    payload = json.loads(
        await blast_radius_impl(
            cve_id="CVE-2026-4242",
            tenant_id="history-tenant",
            _validate_cve_id=lambda value: value,
            _run_scan_pipeline=no_local_scan,
            _truncate_response=lambda value: value,
            _get_persisted_evidence=persisted_finding_evidence,
        )
    )
    assert payload["completeness"]["status"] == "partial"
    assert payload["completeness"]["basis"] == "persisted_row_enumeration"
    finding = payload["blast_radii"][0]
    assert finding["observation_status"] == "unreconfirmed"
    assert finding["scan_id"] == job(8).job_id
    assert finding["last_observed"] == "2026-08-01T00:00:00+00:00"
    assert finding["reconfirmation"]["scan_id"] == attempted().job_id
