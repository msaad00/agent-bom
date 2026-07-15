"""Per-tenant overview cache (pre-release scale hardening, #3963 follow-up).

``_build_overview`` folds every finding of every completed scan. These tests pin
the TTL + fingerprint cache: a re-read with unchanged job metadata skips the
fold, new scan data invalidates it, and the numbers never change.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_bom.api.routes import overview


class _FakeStore:
    def __init__(self, jobs):
        self._jobs = jobs

    def list_all(self, tenant_id):
        return list(self._jobs)


def _job(job_id: str, status: str = "done", completed_at: str = "2026-07-15T00:00:00Z"):
    return SimpleNamespace(job_id=job_id, status=status, completed_at=completed_at)


@pytest.fixture(autouse=True)
def _clean_cache(monkeypatch):
    overview._reset_overview_cache()
    monkeypatch.setattr(overview, "_tenant_id", lambda request: "acme")
    monkeypatch.delenv("AGENT_BOM_OVERVIEW_CACHE_TTL_SECONDS", raising=False)
    yield
    overview._reset_overview_cache()


def _install(monkeypatch, jobs, hub_severity=None):
    store = _FakeStore(jobs)
    monkeypatch.setattr(overview, "_get_store", lambda: store)
    hub_state = dict(hub_severity or {"critical": 0, "high": 0})
    monkeypatch.setattr(overview, "_hub_severity_snapshot", lambda request: dict(hub_state))
    calls = {"n": 0}

    def _fake_compose(request, tenant_id, jobs_arg, hub_severity):
        calls["n"] += 1
        return {"schema_version": "overview.v1", "tenant_id": tenant_id, "job_count": len(jobs_arg)}

    monkeypatch.setattr(overview, "_compose_overview", _fake_compose)
    return calls


def test_hub_ingest_invalidates_cache(monkeypatch):
    jobs = [_job("j1")]
    hub = {"critical": 0, "high": 0}
    store = _FakeStore(jobs)
    monkeypatch.setattr(overview, "_get_store", lambda: store)
    monkeypatch.setattr(overview, "_hub_severity_snapshot", lambda request: dict(hub))
    calls = {"n": 0}

    def _fake_compose(request, tenant_id, jobs_arg, hub_severity):
        calls["n"] += 1
        return {"hub_critical": hub_severity.get("critical", 0)}

    monkeypatch.setattr(overview, "_compose_overview", _fake_compose)
    req = object()

    overview._build_overview(req)
    assert calls["n"] == 1

    # Bulk-ingested findings change hub current-state (not any scan job) — the
    # cache must still invalidate so the headline reflects them.
    hub["critical"] = 3
    result = overview._build_overview(req)
    assert calls["n"] == 2
    assert result["hub_critical"] == 3


def test_second_read_within_ttl_skips_fold(monkeypatch):
    calls = _install(monkeypatch, [_job("j1")])
    req = object()

    first = overview._build_overview(req)
    second = overview._build_overview(req)

    assert calls["n"] == 1  # folded once, second served from cache
    assert first == second


def test_new_scan_invalidates_cache(monkeypatch):
    jobs = [_job("j1")]
    calls = _install(monkeypatch, jobs)
    req = object()

    overview._build_overview(req)
    assert calls["n"] == 1

    # A new completed scan lands -> fingerprint changes -> refold.
    jobs.append(_job("j2"))
    result = overview._build_overview(req)

    assert calls["n"] == 2
    assert result["job_count"] == 2


def test_status_transition_invalidates_cache(monkeypatch):
    job = _job("j1", status="running", completed_at="")
    calls = _install(monkeypatch, [job])
    req = object()

    overview._build_overview(req)
    assert calls["n"] == 1

    # Same job id, but it completes -> fingerprint must change.
    job.status = "done"
    job.completed_at = "2026-07-15T01:00:00Z"
    overview._build_overview(req)
    assert calls["n"] == 2


def test_ttl_zero_disables_cache(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_OVERVIEW_CACHE_TTL_SECONDS", "0")
    calls = _install(monkeypatch, [_job("j1")])
    req = object()

    overview._build_overview(req)
    overview._build_overview(req)

    assert calls["n"] == 2  # caching disabled -> always refolds
