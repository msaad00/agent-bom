from __future__ import annotations

import sqlite3

import pytest


def test_sqlite_campaign_queue_is_atomic_and_survives_replica_restart(tmp_path):
    from agent_bom.api.storage.campaign_revisions import SQLiteCampaignEvidenceState, initialize_sqlite_campaign_evidence

    path = tmp_path / "estate.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE job_overview_revisions(tenant_id TEXT PRIMARY KEY, revision INTEGER NOT NULL)")
    initialize_sqlite_campaign_evidence(conn)
    conn.commit()
    conn.execute("INSERT INTO job_overview_revisions VALUES ('alpha',1)")
    conn.commit()
    replica = sqlite3.connect(path)
    state = SQLiteCampaignEvidenceState(lambda: replica)
    assert state.pending_tenants() == ["alpha"]
    assert state.revision("alpha") == 1
    conn.execute("UPDATE job_overview_revisions SET revision=2 WHERE tenant_id='alpha'")
    conn.rollback()
    assert state.revision("alpha") == 1
    assert state.revision("beta") == 0


def test_stale_campaign_reconciliation_cannot_retire_newer_membership(tmp_path):
    from agent_bom.api.campaign_store import SQLiteCampaignStore
    from agent_bom.api.storage.campaign_revisions import CampaignEvidenceChangedError

    store = SQLiteCampaignStore(str(tmp_path / "estate.db"))
    store._conn.execute("INSERT INTO campaign_evidence_state VALUES ('alpha',2,0)")
    store._conn.commit()
    store.reconcile_memberships("alpha", {"campaign": ("current", ("finding",))}, evidence_revision=2)
    with pytest.raises(CampaignEvidenceChangedError):
        store.reconcile_memberships("alpha", {}, evidence_revision=1)
    assert store.get("alpha", "campaign").active
    assert store.evidence_state.pending_tenants() == []
    store._conn.execute("UPDATE campaign_evidence_state SET revision=3 WHERE tenant_id='alpha'")
    store._conn.commit()
    with pytest.raises(CampaignEvidenceChangedError):
        store.patch("alpha", "campaign", expected_version=1, fields={"owner": "stale"}, evidence_revision=2)
    assert store.get("alpha", "campaign").owner is None


def test_worker_reconciles_without_a_get_and_retires_on_empty_evidence(monkeypatch):
    from agent_bom.api.campaign_reconciliation import notify_campaign_evidence, reconcile_pending_campaigns
    from agent_bom.api.campaign_store import InMemoryCampaignStore, set_campaign_store
    from agent_bom.api.routes import campaigns

    store = InMemoryCampaignStore()
    set_campaign_store(store)
    findings = [{"id": "finding", "package": "acme", "fixed_version": "2", "severity": "high"}]
    walks = []
    monkeypatch.setattr(
        campaigns,
        "_load_findings",
        lambda request, **kwargs: {
            "_deadline": walks.append(kwargs.get("deadline_seconds")),
            "findings": findings,
            "total": len(findings),
            "has_more": False,
            "_evidence_revision": store.evidence_state.revision(request.state.tenant_id),
        },
    )
    monkeypatch.setattr(campaigns, "_audit", lambda *args, **kwargs: None)
    monkeypatch.setattr("agent_bom.api.campaign_reconciliation._cursor", "")
    try:
        notify_campaign_evidence("alpha")
        assert reconcile_pending_campaigns() == 1
        assert len(store.list("alpha")) == 1
        assert store.evidence_state.pending_tenants() == []
        findings.clear()
        notify_campaign_evidence("alpha")
        assert reconcile_pending_campaigns() == 1
        assert store.list("alpha")[0].active is False
        assert store.evidence_state.checkpoints["alpha"] == 2
        # Unchanged evidence is not walked again; the background walk is not request-bounded.
        assert reconcile_pending_campaigns() == 0
        assert len(walks) == 2 and all(bound > 10.0 for bound in walks)
    finally:
        set_campaign_store(None)


def test_worker_incomplete_source_keeps_prior_membership_and_pending_checkpoint(monkeypatch):
    from agent_bom.api.campaign_reconciliation import reconcile_pending_campaigns
    from agent_bom.api.campaign_store import InMemoryCampaignStore, set_campaign_store

    store = InMemoryCampaignStore()
    set_campaign_store(store)
    before = store.reconcile_memberships("alpha", {"campaign": ("v1", ("finding",))})[0]
    store.evidence_state.changed("alpha")
    monkeypatch.setattr(
        "agent_bom.api.routes.campaigns._load_findings", lambda request, **_: {"findings": [], "total": 1, "has_more": True}
    )
    monkeypatch.setattr("agent_bom.api.campaign_reconciliation._cursor", "")
    try:
        assert reconcile_pending_campaigns() == 0
        assert store.get("alpha", "campaign") == before
        assert store.evidence_state.pending_tenants() == ["alpha"]
    finally:
        set_campaign_store(None)


def test_postgres_campaign_source_fences_cross_replica_writes():
    import os
    from uuid import uuid4

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires restricted-role Postgres")
    from psycopg.errors import InsufficientPrivilege

    from agent_bom.api.postgres_campaign import PostgresCampaignStore
    from agent_bom.api.postgres_common import _new_application_pool, _tenant_connection
    from agent_bom.api.storage.campaign_revisions import CampaignEvidenceChangedError
    from tests.test_postgres_job_evidence_revision import tenant_scope

    tenant, other = "campaign-" + uuid4().hex, "campaign-" + uuid4().hex
    pools = [_new_application_pool(min_size=1, max_size=2) for _ in range(2)]
    try:
        a, b = (PostgresCampaignStore(pool=p) for p in pools)
        with tenant_scope(tenant):
            with _tenant_connection(pools[0]) as conn:
                conn.execute("INSERT INTO hub_overview_revisions(tenant_id,revision) VALUES (%s,1)", (tenant,))
            revision = a.evidence_state.revision(tenant)
            assert revision == 1
            a.reconcile_memberships(tenant, {"campaign": ("one", ("finding",))}, evidence_revision=revision)
            assert b.get(tenant, "campaign").active
            with _tenant_connection(pools[1]) as conn:
                conn.execute("UPDATE hub_overview_revisions SET revision=revision+1 WHERE tenant_id=%s", (tenant,))
            assert b.evidence_state.revision(tenant) == revision + 1
            with pytest.raises(CampaignEvidenceChangedError):
                a.reconcile_memberships(tenant, {}, evidence_revision=revision)
            with pytest.raises(CampaignEvidenceChangedError):
                a.patch(tenant, "campaign", expected_version=1, fields={"owner": "stale"}, evidence_revision=revision)
            assert b.get(tenant, "campaign").owner is None
            assert b.get(tenant, "campaign").active
            b.reconcile_memberships(tenant, {}, evidence_revision=revision + 1)
            assert a.get(tenant, "campaign").active is False
            with _tenant_connection(pools[0]) as conn:
                assert conn.execute(
                    "SELECT revision,reconciled_revision FROM campaign_evidence_state WHERE tenant_id=%s", (tenant,)
                ).fetchone() == (2, 2)
        with tenant_scope(other):
            assert b.get(tenant, "campaign") is None
            assert b.evidence_state.revision(tenant) == 0
            with pytest.raises(InsufficientPrivilege):
                b.reconcile_memberships(tenant, {}, evidence_revision=2)
    finally:
        for p in pools:
            p.close()


def test_campaign_mutation_rejects_changed_source_before_writing(monkeypatch):
    from types import SimpleNamespace

    from fastapi import HTTPException

    from agent_bom.api.campaign_store import InMemoryCampaignStore, set_campaign_store
    from agent_bom.api.routes import campaigns

    store = InMemoryCampaignStore()
    set_campaign_store(store)
    monkeypatch.setattr(campaigns, "_campaign_source_revision", lambda request: ("new", 2))
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="alpha"), headers={})
    source = {"findings": [], "total": 0, "has_more": False, "_source_revision": ("old", 1), "_evidence_revision": 0}
    try:
        with pytest.raises(HTTPException) as rejected:
            campaigns.update_campaign_workflow(
                request=request, campaign_id="campaign", body=campaigns.CampaignUpdate(version=1, owner="alice"), source=source
            )
        assert rejected.value.status_code == 409
        assert store.list("alpha") == []
    finally:
        set_campaign_store(None)


def test_postgres_campaign_fence_blocks_concurrent_source_commit():
    import os
    from uuid import uuid4

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires restricted-role Postgres")
    from psycopg.errors import QueryCanceled

    from agent_bom.api.postgres_common import _new_application_pool, _tenant_connection
    from agent_bom.api.storage.campaign_revisions import PostgresCampaignEvidenceState
    from tests.test_postgres_job_evidence_revision import tenant_scope

    tenant = "campaign-fence-" + uuid4().hex
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        state = PostgresCampaignEvidenceState(pool)
        with tenant_scope(tenant):
            with _tenant_connection(pool) as conn:
                conn.execute("INSERT INTO job_overview_revisions(tenant_id,revision) VALUES (%s,1)", (tenant,))
            assert state.revision(tenant) == 1
            with _tenant_connection(pool) as reader:
                state.guard(tenant, 1, reader)
                with pytest.raises(QueryCanceled):
                    with _tenant_connection(pool) as writer:
                        writer.execute("SET LOCAL statement_timeout='150ms'")
                        writer.execute("UPDATE job_overview_revisions SET revision=revision+1 WHERE tenant_id=%s", (tenant,))
                state.checkpoint(tenant, 1, reader)
            with _tenant_connection(pool) as writer:
                writer.execute("UPDATE job_overview_revisions SET revision=revision+1 WHERE tenant_id=%s", (tenant,))
            assert state.revision(tenant) == 2
    finally:
        pool.close()


def test_repeated_generation_does_not_duplicate_membership_audit(monkeypatch):
    from types import SimpleNamespace

    from agent_bom.api.campaign_store import InMemoryCampaignStore, set_campaign_store
    from agent_bom.api.routes import campaigns

    store = InMemoryCampaignStore()
    set_campaign_store(store)
    store.evidence_state.changed("alpha")
    audits = []
    monkeypatch.setattr(campaigns, "_audit", lambda *args, **kwargs: audits.append(args))
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="alpha", api_key_name="worker"))
    source = {"findings": [{"id": "finding", "severity": "high"}], "total": 1, "has_more": False, "_evidence_revision": 1}
    try:
        campaigns._reconcile_campaigns(request, source)
        campaigns._reconcile_campaigns(request, source)
        assert len(audits) == 1
        assert store.list("alpha")[0].generation == 1
    finally:
        set_campaign_store(None)


def test_startup_requires_campaign_checkpoint_migration(monkeypatch):
    from contextlib import contextmanager

    from agent_bom.api.storage import registry_stores

    checked = []

    class Connection:
        def execute(self, *args):
            return None

    class Pool:
        @contextmanager
        def connection(self):
            yield Connection()

    def validate(conn, component):
        checked.append(component)
        if component == "campaign_evidence_state":
            raise RuntimeError("required campaign migration missing")

    monkeypatch.setattr(registry_stores.postgres_common, "_get_pool", lambda: Pool())
    monkeypatch.setattr(registry_stores, "ensure_postgres_schema_version", validate)
    with pytest.raises(RuntimeError, match="campaign migration missing"):
        registry_stores.validate_postgres_registries()
    assert "campaign_evidence_state" in checked


def _paged_source(monkeypatch, pages):
    from types import SimpleNamespace

    from agent_bom.api.campaign_store import InMemoryCampaignStore, set_campaign_store
    from agent_bom.api.routes import campaigns, scan

    store = InMemoryCampaignStore()
    set_campaign_store(store)
    monkeypatch.setattr(campaigns, "_campaign_source_revision", lambda request: ("jobs", 1))
    by_cursor = {None: pages[0], **{f"c{i}": page for i, page in enumerate(pages[1:], start=1)}}
    monkeypatch.setattr(scan, "_list_findings_impl", lambda request, **kwargs: by_cursor[kwargs["cursor"]])
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="alpha", api_key_name="worker"))
    try:
        return campaigns._load_findings(request)
    finally:
        set_campaign_store(None)


def _rows(*ids):
    return [{"id": value, "canonical_id": value, "severity": "high"} for value in ids]


def test_merged_resume_pages_without_a_recount_still_complete(monkeypatch):
    from agent_bom.api.routes.campaigns import _source_incomplete

    source = _paged_source(
        monkeypatch,
        [
            {"findings": _rows("a", "b"), "total": 3, "total_approximate": False, "has_more": True, "next_cursor": "c1"},
            {"findings": _rows("c"), "total": None, "total_approximate": True, "has_more": False, "next_cursor": None},
        ],
    )
    assert [row["id"] for row in source["findings"]] == ["a", "b", "c"]
    assert not _source_incomplete(source)
    assert source["_evidence_revision"] == 0


def test_one_campaign_walk_reuses_retained_scan_work_across_pages(monkeypatch):
    from agent_bom.api.finding_read_context import read_once
    from agent_bom.api.routes import campaigns, scan

    loads = []
    pages = {
        None: {"findings": _rows("a"), "total": 2, "total_approximate": False, "has_more": True, "next_cursor": "c1"},
        "c1": {"findings": _rows("b"), "total": None, "total_approximate": True, "has_more": False, "next_cursor": None},
    }

    def page(request, **kwargs):
        read_once(("rows", "job"), lambda: loads.append(1))
        return pages[kwargs["cursor"]]

    _paged_source(monkeypatch, [pages[None], pages["c1"]])
    monkeypatch.setattr(scan, "_list_findings_impl", page)
    from types import SimpleNamespace

    from agent_bom.api.campaign_store import InMemoryCampaignStore, set_campaign_store

    set_campaign_store(InMemoryCampaignStore())
    try:
        campaigns._load_findings(SimpleNamespace(state=SimpleNamespace(tenant_id="alpha", api_key_name="worker")))
    finally:
        set_campaign_store(None)
    assert loads == [1]


def test_resume_page_contradicting_the_first_total_stays_incomplete(monkeypatch):
    from agent_bom.api.routes.campaigns import _source_incomplete

    source = _paged_source(
        monkeypatch,
        [
            {"findings": _rows("a", "b"), "total": 3, "total_approximate": False, "has_more": True, "next_cursor": "c1"},
            {"findings": _rows("c"), "total": 4, "total_approximate": False, "has_more": False, "next_cursor": None},
        ],
    )
    assert _source_incomplete(source)


def test_walk_shorter_than_the_exact_first_total_stays_incomplete(monkeypatch):
    from agent_bom.api.routes.campaigns import _source_incomplete

    source = _paged_source(
        monkeypatch,
        [
            {"findings": _rows("a", "b"), "total": 4, "total_approximate": False, "has_more": True, "next_cursor": "c1"},
            {"findings": _rows("c"), "total": None, "total_approximate": True, "has_more": False, "next_cursor": None},
        ],
    )
    assert _source_incomplete(source)


def test_approximate_first_page_total_never_completes(monkeypatch):
    from agent_bom.api.routes.campaigns import _source_incomplete

    source = _paged_source(
        monkeypatch,
        [
            {"findings": _rows("a"), "total": 2, "total_approximate": True, "has_more": True, "next_cursor": "c1"},
            {"findings": _rows("b"), "total": None, "total_approximate": True, "has_more": False, "next_cursor": None},
        ],
    )
    assert _source_incomplete(source)


def test_identity_less_row_keeps_the_collection_incomplete(monkeypatch):
    from agent_bom.api.routes.campaigns import _source_incomplete

    rows = _rows("a") + [{"id": "CVE-2026-1", "vulnerability_id": "CVE-2026-1", "severity": "high"}]
    source = _paged_source(
        monkeypatch, [{"findings": rows, "total": 2, "total_approximate": False, "has_more": False, "next_cursor": None}]
    )
    assert _source_incomplete(source)
