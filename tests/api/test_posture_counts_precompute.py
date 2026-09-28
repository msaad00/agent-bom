"""Posture issue counts are precomputed when scan evidence is written.

The write-time value is stored under the same evidence fingerprint the read
path computes, so a read after a scan or hub ingest serves it without a
grouped findings walk. It must equal what the read path computes, and one
tenant's precompute must never answer another tenant's read.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore
from agent_bom.api.stores import _get_store
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers
from tests.test_demo_estate_bootstrap import demo_estate_client  # noqa: F401

TENANT_A = "precompute-tenant-a"
TENANT_B = "precompute-tenant-b"


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())


@pytest.fixture(autouse=True)
def _fresh_caches(monkeypatch: pytest.MonkeyPatch):
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.api.posture_counts_cache import clear_posture_counts_cache, wait_for_posture_precompute
    from agent_bom.api.routes import overview

    monkeypatch.setenv("AGENT_BOM_POSTURE_PRECOMPUTE", "1")
    set_job_store(InMemoryJobStore())
    for tenant in (TENANT_A, TENANT_B):
        get_compliance_hub_store().clear(tenant)
    assert wait_for_posture_precompute(30)
    clear_posture_counts_cache()
    overview._reset_overview_cache()
    yield
    assert wait_for_posture_precompute(30)
    clear_posture_counts_cache()


def _stamp(hours: float = 0.0) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _job(tenant_id: str, job_id: str, blast: list[dict[str, Any]]) -> ScanJob:
    job = ScanJob(job_id=job_id, tenant_id=tenant_id, created_at=_stamp(1), request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = _stamp()
    job.result = {
        "summary": {"total_packages": len(blast), "total_findings": len(blast)},
        "agents": [],
        "blast_radius": blast,
    }
    return job


def _blast(vid: str, severity: str, package: str, **extra: Any) -> dict[str, Any]:
    return {"vulnerability_id": vid, "package": package, "severity": severity, **extra}


_TENANT_A_BLAST = [
    _blast("CVE-2026-7001", "critical", "a@1", is_kev=True, exposed_credentials=["TOKEN"]),
    _blast("CVE-2026-7001", "critical", "a@1", affected_agents=["second-agent"]),
    _blast("CVE-2026-7002", "high", "b@1", epss_score=0.5, cvss_score=8.1),
    _blast("CVE-2026-7003", "medium", "c@1"),
    _blast("GHSA-aaaa-bbbb-cccc", "unknown", "d@1"),
]
_TENANT_B_BLAST = [_blast("CVE-2026-8001", "low", "z@9")]


class _ComputeProbe:
    """Counts read-time recomputation of the precomputed evidence blocks."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from agent_bom.api import exec_posture
        from agent_bom.api.routes import overview as overview_routes
        from agent_bom.api.routes import scan as scan_routes

        self.calls: dict[str, list[str]] = {"issues": [], "exec": [], "compound": []}
        real_issues = scan_routes.issue_severity_counts
        real_exec = overview_routes.exec_severity_counts
        real_compound = exec_posture.compound_issue_count

        def issues(request, *args, **kwargs):
            self.calls["issues"].append(request.state.tenant_id)
            return real_issues(request, *args, **kwargs)

        def exec_counts(request, *args, **kwargs):
            self.calls["exec"].append(request.state.tenant_id)
            return real_exec(request, *args, **kwargs)

        def compound(tenant_jobs, *args, **kwargs):
            self.calls["compound"].append(",".join(sorted({job.tenant_id for job in tenant_jobs})))
            return real_compound(tenant_jobs, *args, **kwargs)

        monkeypatch.setattr(scan_routes, "issue_severity_counts", issues)
        monkeypatch.setattr(overview_routes, "exec_severity_counts", exec_counts)
        monkeypatch.setattr(exec_posture, "compound_issue_count", compound)

    def total(self) -> int:
        return sum(len(values) for values in self.calls.values())


def _read(client: TestClient, tenant_id: str) -> dict[str, Any]:
    response = client.get("/v1/posture/counts", headers=proxy_headers(role="analyst", tenant=tenant_id))
    assert response.status_code == 200, response.text
    return response.json()


def _comparable(body: dict[str, Any]) -> dict[str, Any]:
    """The read-window cutoff is stamped at compute time; every count must match."""
    out = dict(body)
    issues = dict(out.get("issues") or {})
    window = dict(issues.get("window") or {})
    window.pop("since", None)
    issues["window"] = window
    out["issues"] = issues
    return out


def _recomputed(client: TestClient, tenant_id: str) -> dict[str, Any]:
    from agent_bom.api.posture_counts_cache import clear_posture_counts_cache

    clear_posture_counts_cache()
    return _read(client, tenant_id)


def test_a_completed_scan_write_precomputes_the_blocks_the_read_serves(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.posture_counts_cache import wait_for_posture_precompute

    _get_store().put(_job(TENANT_A, "precompute-a-1", _TENANT_A_BLAST))
    assert wait_for_posture_precompute(60)

    probe = _ComputeProbe(monkeypatch)
    client = TestClient(app)
    precomputed = _read(client, TENANT_A)
    assert probe.total() == 0, probe.calls

    assert precomputed["issues"]["basis"] == "issue_groups"
    assert precomputed["issues"]["critical"] == 1
    assert precomputed["compound_issues"] == 2
    assert _comparable(precomputed) == _comparable(_recomputed(client, TENANT_A))


def test_a_hub_ingest_precomputes_the_new_evidence_revision(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.api.posture_counts_cache import issue_counts_fingerprint, wait_for_posture_precompute
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType

    _get_store().put(_job(TENANT_A, "precompute-a-hub", _TENANT_A_BLAST))
    assert wait_for_posture_precompute(60)
    before = issue_counts_fingerprint(TENANT_A, _get_store().list_all(tenant_id=TENANT_A))
    client = TestClient(app)

    hub_finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.SBOM,
        asset=Asset(name="hub-pkg", asset_type="package", identifier="pkg:pypi/hub-pkg@1.0.0"),
        severity="critical",
        cve_id="CVE-2026-7100",
    ).to_dict()
    get_compliance_hub_store().add(TENANT_A, [hub_finding])
    assert wait_for_posture_precompute(60)

    probe = _ComputeProbe(monkeypatch)
    after = _read(client, TENANT_A)
    assert probe.total() == 0, probe.calls
    assert issue_counts_fingerprint(TENANT_A, _get_store().list_all(tenant_id=TENANT_A)) != before
    assert _comparable(after) == _comparable(_recomputed(client, TENANT_A))


def test_one_tenants_precompute_never_answers_another_tenants_read(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api import posture_counts_cache
    from agent_bom.api.posture_counts_cache import wait_for_posture_precompute

    monkeypatch.setenv("AGENT_BOM_POSTURE_PRECOMPUTE", "0")
    _get_store().put(_job(TENANT_B, "precompute-b-1", _TENANT_B_BLAST))
    monkeypatch.setenv("AGENT_BOM_POSTURE_PRECOMPUTE", "1")
    _get_store().put(_job(TENANT_A, "precompute-a-2", _TENANT_A_BLAST))
    assert wait_for_posture_precompute(60)

    cached_tenants = {key[0] for key in posture_counts_cache.POSTURE_COUNTS_CACHE}
    assert cached_tenants == {TENANT_A}

    probe = _ComputeProbe(monkeypatch)
    client = TestClient(app)
    tenant_b = _read(client, TENANT_B)
    assert probe.calls["issues"] == [TENANT_B]
    assert probe.calls["exec"] == [TENANT_B]
    assert probe.calls["compound"] == [TENANT_B]
    assert tenant_b["issues"]["total"] == 1
    assert tenant_b["issues"]["low"] == 1
    assert tenant_b["issues"]["critical"] == 0
    assert tenant_b["compound_issues"] == 0

    tenant_a = _read(client, TENANT_A)
    assert probe.calls["issues"] == [TENANT_B]
    assert tenant_a["issues"]["critical"] == 1
    assert _comparable(tenant_a) == _comparable(_recomputed(client, TENANT_A))
    assert _comparable(tenant_b) == _comparable(_recomputed(client, TENANT_B))


def test_precompute_is_off_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api import posture_counts_cache
    from agent_bom.api.posture_counts_cache import wait_for_posture_precompute

    monkeypatch.setenv("AGENT_BOM_POSTURE_PRECOMPUTE", "0")
    _get_store().put(_job(TENANT_A, "precompute-off", _TENANT_A_BLAST))
    assert wait_for_posture_precompute(10)
    assert not posture_counts_cache.POSTURE_COUNTS_CACHE


def test_an_in_place_result_refresh_moves_the_fingerprint(tmp_path) -> None:
    from agent_bom.api.posture_counts_cache import issue_counts_fingerprint

    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    set_job_store(store)
    job = _job(TENANT_A, "refresh-in-place", _TENANT_A_BLAST)
    store.put(job)
    before = issue_counts_fingerprint(TENANT_A, store.list_all(tenant_id=TENANT_A))
    job.result = dict(job.result or {}, blast_radius=_TENANT_B_BLAST)
    store.put(job)
    after = issue_counts_fingerprint(TENANT_A, store.list_all(tenant_id=TENANT_A))
    assert before != after


def test_a_block_that_computes_longer_than_the_ttl_is_still_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    from starlette.requests import Request

    from agent_bom.api import posture_counts_cache

    monkeypatch.setattr(posture_counts_cache, "POSTURE_COUNTS_TTL_SECONDS", 0.2)
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b"", "state": {}})
    request.state.tenant_id = TENANT_A
    calls = []

    def slow() -> dict[str, Any]:
        calls.append(1)
        time.sleep(0.3)
        return {"count": 1}

    posture_counts_cache.cached_posture_block(request, [], "slow", slow)
    posture_counts_cache.cached_posture_block(request, [], "slow", slow)
    assert len(calls) == 1


def test_demo_estate_precompute_equals_the_read_path(demo_estate_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    from agent_bom.api.posture_counts_cache import wait_for_posture_precompute
    from agent_bom.demo_estate.bootstrap import SHOWCASE_TENANT

    # Readiness already waited for the seed's precompute.
    assert wait_for_posture_precompute(0)
    probe = _ComputeProbe(monkeypatch)
    precomputed = _read(demo_estate_client, SHOWCASE_TENANT)
    assert probe.total() == 0, probe.calls
    assert precomputed["issues"]["total"] > 0
    assert _comparable(precomputed) == _comparable(_recomputed(demo_estate_client, SHOWCASE_TENANT))
