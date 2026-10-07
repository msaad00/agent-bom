"""List-row projection and per-read reuse for findings and posture reads."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.models import JobStatus
from agent_bom.api.server import ScanJob, ScanRequest, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH = proxy_headers(tenant="default")

_CONTROLS = [
    {"framework": "soc2", "control": "CC6.1", "version": "2017", "source": "vendor-asserted:agent-bom", "confidence": 0.75},
    {"framework": "iso_27001", "control": "A.8.8", "version": "2022", "source": "vendor-asserted:agent-bom", "confidence": 0.75},
]


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())


def _seed() -> None:
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    observed_at = datetime.now(timezone.utc).isoformat()
    job = ScanJob(job_id="projection-job", tenant_id="default", created_at=observed_at, request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = observed_at
    job.result = {
        "agents": [],
        "scan_sources": ["cloud"],
        "summary": {"total_findings": 2, "total_packages": 1},
        "posture_scorecard": {"grade": "C", "score": 70, "summary": "seeded"},
        "findings": [
            {
                "id": "f-mapped",
                "severity": "high",
                "title": "mapped finding",
                "soc2_tags": ["CC6.1"],
                "iso_27001_tags": ["A.8.8"],
                "controls": _CONTROLS,
            },
            {"id": "f-unmapped", "severity": "low", "title": "unmapped finding"},
        ],
    }
    _get_store().put(job)


def _by_id(body: dict) -> dict[str, dict]:
    return {row["id"]: row for row in body["findings"]}


def test_list_rows_carry_control_counts_not_full_mappings_by_default() -> None:
    _seed()
    resp = TestClient(app).get("/v1/findings", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    rows = _by_id(body)
    mapped = rows["f-mapped"]
    assert "controls" not in mapped
    assert mapped["controls_count"] == 2
    assert set(mapped["framework_tags"]) >= {"soc2:CC6.1", "iso_27001:A.8.8"}
    assert "controls" not in rows["f-unmapped"]
    assert body["include"] == []


def test_include_controls_restores_full_control_mappings() -> None:
    _seed()
    resp = TestClient(app).get("/v1/findings?include=controls", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    mapped = _by_id(body)["f-mapped"]
    assert {(c["framework"], c["control"]) for c in mapped["controls"]} == {("soc2", "CC6.1"), ("iso_27001", "A.8.8")}
    assert mapped["controls"][0]["source"] == "vendor-asserted:agent-bom"
    assert mapped["controls_count"] == 2
    assert body["include"] == ["controls"]


def test_unknown_include_value_is_rejected() -> None:
    _seed()
    resp = TestClient(app).get("/v1/findings?include=everything", headers=_AUTH)
    assert resp.status_code == 422
    assert "controls" in resp.text


def test_grouped_list_honours_the_same_projection() -> None:
    _seed()
    client = TestClient(app)
    compact = client.get("/v1/findings?group_occurrences=true", headers=_AUTH).json()
    full = client.get("/v1/findings?group_occurrences=true&include=controls", headers=_AUTH).json()
    assert all("controls" not in row for row in compact["findings"])
    assert any(row.get("controls") for row in full["findings"])


def test_posture_materializes_each_scan_job_once_per_read(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.routes import overview as overview_route
    from agent_bom.api.routes import scan as scan_route

    _seed()
    monkeypatch.setattr(overview_route, "_overview_cache_get", lambda *_args, **_kwargs: None)
    calls: list[str] = []
    original = scan_route._iter_scan_findings

    def counting(job):  # type: ignore[no-untyped-def]
        calls.append(job.job_id)
        return original(job)

    monkeypatch.setattr(scan_route, "_iter_scan_findings", counting)
    resp = TestClient(app).get("/v1/posture", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    assert resp.json()["no_data"] is False
    assert calls == ["projection-job"]
