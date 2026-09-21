"""Durable revision cache keeps warm overview reads independent of job payload size."""

from __future__ import annotations

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from fastapi import HTTPException

from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.api.routes import overview
from agent_bom.api.store import SQLiteJobStore


def job(tenant="acme", value=1):
    return ScanJob(job_id="j1", tenant_id=tenant, created_at="2026-09-21T00:00:00Z", request=ScanRequest(), result={"value": value})


@pytest.fixture
def setup(tmp_path, monkeypatch):
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    store.put(job())
    overview._reset_overview_cache()
    monkeypatch.setattr(overview, "_tenant_id", lambda request: "acme")
    monkeypatch.setattr(overview, "_get_store", lambda: store)
    hub = {"revision": 1}
    monkeypatch.setattr(
        overview,
        "_capture_hub_overview_snapshot",
        lambda *a, **k: overview._HubOverviewSnapshot({}, set(), 0, [], hub["revision"], ({}, "complete")),
    )
    monkeypatch.setattr(
        overview, "_compose_overview", lambda request, tenant, jobs, *a, **k: {"value": jobs[0].result["value"] if jobs else 0}
    )
    yield store, hub
    overview._reset_overview_cache()


def test_warm_cache_skips_full_job_deserialization(setup, monkeypatch):
    store, _ = setup
    assert overview._build_overview(object()) == {"value": 1}
    monkeypatch.setattr(store, "list_all", lambda **kwargs: pytest.fail("warm cache loaded full job data"))
    assert overview._build_overview(object()) == {"value": 1}


def test_cross_process_in_place_evidence_invalidates_cache(setup):
    store, _ = setup
    assert overview._build_overview(object()) == {"value": 1}
    script = """import sqlite3,json,sys
c=sqlite3.connect(sys.argv[1])
d=json.loads(c.execute('SELECT data FROM jobs').fetchone()[0])
d['result']['value']=9
c.execute('UPDATE jobs SET data=?',(json.dumps(d),))
c.commit()
"""
    subprocess.run([sys.executable, "-c", script, store._db_path], check=True)
    assert overview._build_overview(object()) == {"value": 9}


def test_revision_is_tenant_scoped_and_survives_reopen(setup):
    store, _ = setup
    initial = store.overview_evidence_revision("acme")
    store.put(ScanJob(job_id="other", tenant_id="other", created_at="2026-09-21T00:00:00Z", request=ScanRequest()))
    assert store.overview_evidence_revision("acme") == initial
    assert SQLiteJobStore(store._db_path).overview_evidence_revision("acme") == initial
    store.put(job(value=2))
    assert store.overview_evidence_revision("acme") != initial
    before_move = store.overview_evidence_revision("acme")
    store.put(job(tenant="other"))
    assert store.overview_evidence_revision("acme") != before_move
    before_delete = store.overview_evidence_revision("other")
    store.delete("j1", tenant_id="other")
    assert store.overview_evidence_revision("other") != before_delete


def test_hub_revision_still_invalidates_warm_cache(setup, monkeypatch):
    store, hub = setup
    overview._build_overview(object())
    reads = []
    original = store.list_all
    monkeypatch.setattr(store, "list_all", lambda **kw: (reads.append(1), original(**kw))[1])
    hub["revision"] += 1
    overview._build_overview(object())
    assert len(reads) == 1


def test_singleflight_loads_full_payload_once(setup, monkeypatch):
    store, _ = setup
    entered, release = Event(), Event()
    original = store.list_all
    reads = []

    def blocked(**kwargs):
        reads.append(1)
        entered.set()
        assert release.wait(5)
        return original(**kwargs)

    monkeypatch.setattr(store, "list_all", blocked)
    with ThreadPoolExecutor(max_workers=4) as pool:
        leader = pool.submit(overview._build_overview, object())
        assert entered.wait(5)
        followers = [pool.submit(overview._build_overview, object()) for _ in range(3)]
        release.set()
        assert all(f.result() == {"value": 1} for f in [leader, *followers])
    assert reads == [1]


def test_mutation_during_fold_retries_without_caching_stale_result(setup, monkeypatch):
    store, _ = setup
    calls = []

    def compose(request, tenant, jobs, *args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            store.put(job(value=2))
        return {"value": jobs[0].result["value"]}

    monkeypatch.setattr(overview, "_compose_overview", compose)
    assert overview._build_overview(object()) == {"value": 2}
    assert len(calls) == 2
    assert overview._build_overview(object()) == {"value": 2}
    assert len(calls) == 2


def test_continuous_mutation_fails_bounded_without_cache_write(setup, monkeypatch):
    store, _ = setup

    def compose(request, tenant, jobs, *args, **kwargs):
        store.put(job(value=jobs[0].result["value"] + 1))
        return {"value": jobs[0].result["value"]}

    monkeypatch.setattr(overview, "_compose_overview", compose)
    with pytest.raises(HTTPException, match="503"):
        overview._build_overview(object())
    assert not overview._overview_cache


def test_disabled_ttl_still_materializes_each_read(setup, monkeypatch):
    store, _ = setup
    monkeypatch.setenv("AGENT_BOM_OVERVIEW_CACHE_TTL_SECONDS", "0")
    reads = []
    original = store.list_all
    monkeypatch.setattr(store, "list_all", lambda **kw: (reads.append(1), original(**kw))[1])
    overview._build_overview(object())
    overview._build_overview(object())
    assert reads == [1, 1]


def test_database_identity_prevents_revision_collision(setup, tmp_path, monkeypatch):
    original, _ = setup
    assert overview._build_overview(object()) == {"value": 1}
    replacement = SQLiteJobStore(str(tmp_path / "replacement.db"))
    replacement.put(job(value=7))
    assert original.overview_evidence_revision("acme") != replacement.overview_evidence_revision("acme")
    monkeypatch.setattr(overview, "_get_store", lambda: replacement)
    assert overview._build_overview(object()) == {"value": 7}


def test_rolled_back_write_does_not_change_revision(setup):
    import sqlite3

    store, _ = setup
    before = store.overview_evidence_revision("acme")
    with sqlite3.connect(store._db_path) as connection:
        connection.execute("DELETE FROM jobs")
        connection.rollback()
    assert store.overview_evidence_revision("acme") == before


def test_revision_read_failure_does_not_serve_cached_payload(setup, monkeypatch):
    store, _ = setup
    overview._build_overview(object())

    def unavailable(tenant_id):
        raise OSError("sensitive local detail")

    monkeypatch.setattr(store, "overview_evidence_revision", unavailable)
    with pytest.raises(HTTPException) as exc:
        overview._build_overview(object())
    assert exc.value.status_code == 503
    assert "sensitive" not in exc.value.detail


def test_direct_tenant_update_invalidates_both_tenant_revisions(setup):
    import sqlite3

    store, _ = setup
    before = {tenant: store.overview_evidence_revision(tenant) for tenant in ("acme", "other")}
    with sqlite3.connect(store._db_path) as connection:
        connection.execute("UPDATE jobs SET tenant_id='other' WHERE job_id='j1'")
    assert all(store.overview_evidence_revision(tenant) != before[tenant] for tenant in before)


def test_other_tenant_write_keeps_warm_payload_without_materializing(setup, monkeypatch):
    store, _ = setup
    assert overview._build_overview(object()) == {"value": 1}
    store.put(ScanJob(job_id="other", tenant_id="other", created_at="2026-09-21T00:00:00Z", request=ScanRequest()))
    monkeypatch.setattr(store, "list_all", lambda **kwargs: pytest.fail("unrelated tenant invalidated cached payload"))
    assert overview._build_overview(object()) == {"value": 1}
