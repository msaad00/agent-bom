from __future__ import annotations

import os
import sys
import types
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from inspect import getsource
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.campaign_store import InMemoryCampaignStore, SQLiteCampaignStore, get_campaign_store, set_campaign_store
from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.risk_campaigns import derive_campaigns
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from agent_bom.ticketing.connection_store import InMemoryTicketingStore, TicketLink, get_ticketing_store, set_ticketing_store

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"


def _headers(role: str = "admin", tenant: str = "tenant-alpha") -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


@pytest.fixture(autouse=True)
def _stores() -> Iterator[None]:
    prior = {
        "AGENT_BOM_TRUST_PROXY_AUTH": os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH"),
        "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH_SECRET"),
    }
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    set_campaign_store(InMemoryCampaignStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    set_ticketing_store(InMemoryTicketingStore())
    set_job_store(InMemoryJobStore())
    try:
        yield
    finally:
        set_campaign_store(None)
        set_compliance_hub_store(None)
        set_ticketing_store(None)
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _findings() -> list[dict[str, Any]]:
    return [
        {
            "id": "finding-a",
            "vulnerability_id": "CVE-2026-1",
            "package": "acme-lib",
            "fixed_version": "2.0",
            "severity": "critical",
            "risk_score": 9.4,
            "is_kev": True,
            "is_reachable": True,
            "asset": {"name": "payments-api", "owner": "payments", "business_context": "checkout"},
        },
        {
            "id": "finding-b",
            "vulnerability_id": "CVE-2026-2",
            "package": "acme-lib",
            "fixed_version": "2.0",
            "severity": "high",
            "risk_score": 7.2,
            "epss_score": 0.63,
            "asset": {"name": "payments-worker", "owner": "payments", "business_context": "checkout"},
        },
        {"id": "finding-c", "severity": "medium", "risk_score": 4.0},
    ]


def test_derivation_groups_only_shared_remediation_and_explains_score() -> None:
    campaigns = derive_campaigns(_findings(), tenant_id="tenant-alpha", workflow_by_id={})

    assert len(campaigns) == 2
    campaign = next(item for item in campaigns if item["finding_count"] == 2)
    assert campaign["finding_ids"] == ["finding-a", "finding-b"]
    assert campaign["priority_score"] == 9.4
    assert campaign["score_factors"]["severity"]["value"] == "critical"
    assert campaign["score_factors"]["exploitability"]["status"] == "observed"
    assert campaign["score_factors"]["reachability"]["status"] == "observed"
    assert campaign["score_factors"]["business_context"]["value"] == "checkout"
    assert campaign["owner"] == "payments"
    assert campaign["expected_risk_reduction"]["assumption"] == "all campaign findings are remediated and verified"
    assert campaign["expected_risk_reduction"]["modeled_window_percent"] == pytest.approx(80.6, abs=0.1)
    assert campaign["priority_score_method"] == "maximum finding risk; context factors do not modify the score"


def test_derivation_does_not_fabricate_missing_context() -> None:
    campaign = next(
        item for item in derive_campaigns(_findings(), tenant_id="tenant-alpha", workflow_by_id={}) if item["finding_count"] == 1
    )

    assert campaign["score_factors"]["exploitability"]["status"] == "unknown"
    assert campaign["score_factors"]["reachability"]["status"] == "unknown"
    assert campaign["score_factors"]["business_context"]["status"] == "unknown"
    assert campaign["owner"] is None
    assert campaign["verification_status"] == "unverified"


def test_derivation_rejects_non_finite_risk_signals_as_unknown() -> None:
    finding = {
        "id": "finding-nan",
        "severity": "high",
        "risk_score": float("nan"),
        "epss_score": float("inf"),
    }
    campaign = derive_campaigns([finding], tenant_id="tenant-alpha", workflow_by_id={})[0]

    assert campaign["priority_score"] == 7.0
    assert campaign["score_factors"]["exploitability"]["status"] == "unknown"


def test_campaign_ids_are_deterministic_across_derivations() -> None:
    first = derive_campaigns(_findings(), tenant_id="tenant-alpha", workflow_by_id={})
    second = derive_campaigns(list(reversed(_findings())), tenant_id="tenant-alpha", workflow_by_id={})

    assert [item["id"] for item in first] == [item["id"] for item in second]


def test_grouping_uses_ecosystem_and_dedupes_canonical_ids() -> None:
    rows = [
        {"id": "same", "ecosystem": "npm", "package": "shared", "fixed_version": "2", "severity": "high"},
        {"id": "same", "ecosystem": "npm", "package": "shared", "fixed_version": "2", "severity": "critical"},
        {"id": "python", "ecosystem": "pypi", "package": "shared", "fixed_version": "2", "severity": "high"},
    ]
    campaigns = derive_campaigns(rows, tenant_id="t", workflow_by_id={})
    assert len(campaigns) == 2
    assert sum(item["finding_count"] for item in campaigns) == 2


def test_purl_grouping_ignores_installed_version_and_qualifiers() -> None:
    rows = [
        {"id": "a", "purl": "pkg:npm/%40scope/lib@1.0?repository_url=x", "fixed_version": "2", "severity": "high"},
        {"id": "b", "purl": "pkg:npm/%40scope/lib@1.5?download_url=y", "fixed_version": "2", "severity": "high"},
    ]
    campaigns = derive_campaigns(rows, tenant_id="t", workflow_by_id={})
    assert len(campaigns) == 1 and campaigns[0]["finding_count"] == 2


def test_campaign_workflow_store_is_tenant_isolated() -> None:
    store = InMemoryCampaignStore()
    store.upsert("tenant-alpha", "campaign-1", owner="alice", state="in_progress")

    assert store.get("tenant-alpha", "campaign-1") is not None
    assert store.get("tenant-beta", "campaign-1") is None


def test_membership_change_and_reentry_reset_done_verification() -> None:
    store = InMemoryCampaignStore()
    row = store.reconcile_memberships("t", {"c": "one"})[0]
    store.patch("t", "c", expected_version=row.version, fields={"state": "done", "verification_status": "verified"})
    changed = store.reconcile_memberships("t", {"c": "two"})[0]
    assert changed.state == "open" and changed.verification_status == "unverified"
    assert changed.generation == 2
    store.reconcile_memberships("t", {})
    reentered = store.reconcile_memberships("t", {"c": "two"})[0]
    assert reentered.generation == 3 and reentered.state == "open"


def test_incomplete_membership_page_does_not_retire_unseen_campaigns() -> None:
    store = InMemoryCampaignStore()
    store.reconcile_memberships("t", {"a": "one", "b": "two"})
    store.reconcile_memberships("t", {"a": "one"}, complete=False)
    assert store.get("t", "b").active is True


def test_incomplete_api_snapshot_never_reconciles_or_reactivates(monkeypatch) -> None:
    from agent_bom.api.server import app

    store = InMemoryCampaignStore()
    set_campaign_store(store)
    full = _findings()
    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: full)
    client = TestClient(app)
    campaign = client.get("/v1/campaigns", headers=_headers()).json()["campaigns"][0]
    store.patch(
        "tenant-alpha",
        campaign["id"],
        expected_version=campaign["version"],
        fields={"state": "done", "verification_status": "verified"},
    )
    store.reconcile_memberships("tenant-alpha", {})
    before = store.get("tenant-alpha", campaign["id"])
    partial = [dict(full[0], id="changed-member")]
    monkeypatch.setattr(
        "agent_bom.api.routes.campaigns._load_findings",
        lambda request: {"findings": partial, "total": 99, "has_more": True, "total_approximate": False},
    )
    body = client.get("/v1/campaigns", headers=_headers()).json()
    after = store.get("tenant-alpha", campaign["id"])
    assert after == before
    assert body["membership_complete"] is False
    assert all(item["membership_provisional"] is True for item in body["campaigns"])


def test_sqlite_patch_cas_rejects_stale_writer(tmp_path) -> None:
    store = SQLiteCampaignStore(str(tmp_path / "cas.db"))
    row = store.reconcile_memberships("t", {"c": "one"})[0]
    assert store.patch("t", "c", expected_version=row.version, fields={"owner": "alice"}) is not None
    assert store.patch("t", "c", expected_version=row.version, fields={"owner": "bob"}) is None
    assert store.get("t", "c").owner == "alice"


def test_sqlite_patch_cas_allows_only_one_concurrent_writer(tmp_path) -> None:
    path = str(tmp_path / "concurrent.db")
    seed = SQLiteCampaignStore(path)
    row = seed.reconcile_memberships("t", {"c": "one"})[0]

    def write(owner: str) -> bool:
        return SQLiteCampaignStore(path).patch("t", "c", expected_version=row.version, fields={"owner": owner}) is not None

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(write, ("alice", "bob")))
    assert sorted(outcomes) == [False, True]


def test_default_store_is_durable_unless_ephemeral(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("AGENT_BOM_EPHEMERAL_STORE", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    set_campaign_store(None)
    assert isinstance(get_campaign_store(), SQLiteCampaignStore)
    get_campaign_store().reconcile_memberships("t", {"c": "one"})
    set_campaign_store(None)
    assert get_campaign_store().get("t", "c") is not None
    set_campaign_store(None)
    monkeypatch.setenv("AGENT_BOM_EPHEMERAL_STORE", "1")
    assert isinstance(get_campaign_store(), InMemoryCampaignStore)


def test_campaign_store_is_in_storage_schema_manifest() -> None:
    from agent_bom.api.storage_schema import describe_control_plane_storage_schema

    components = {item["component"]: item for item in describe_control_plane_storage_schema()["components"]}
    assert components["risk_campaign_workflows"]["tables"] == ["risk_campaign_workflows"]


def test_campaign_openapi_has_typed_responses_and_partial_status() -> None:
    from agent_bom.api.server import app

    schema = app.openapi()
    assert "CampaignListResponse" in schema["components"]["schemas"]
    expected = {
        "/v1/campaigns/{campaign_id}/tickets": "CampaignTicketCreateResponse",
        "/v1/campaigns/{campaign_id}/tickets/sync": "CampaignTicketSyncResponse",
    }
    for path, model in expected.items():
        responses = schema["paths"][path]["post"]["responses"]
        assert "200" in responses and "207" in responses
        for status in ("200", "207"):
            assert responses[status]["content"]["application/json"]["schema"]["$ref"].endswith(model)
    assert "created" in schema["components"]["schemas"]["CampaignTicketCreateResponse"]["properties"]
    assert "synced" in schema["components"]["schemas"]["CampaignTicketSyncResponse"]["properties"]


def test_sqlite_campaign_store_persists_same_logical_id_per_tenant(tmp_path) -> None:
    store = SQLiteCampaignStore(str(tmp_path / "campaigns.db"))
    store.upsert(
        "tenant-alpha",
        "campaign-1",
        owner="alice",
        sla_due_at="2026-08-01T00:00:00+00:00",
        state="in_progress",
        verification_status="pending",
    )
    store.upsert("tenant-beta", "campaign-1", owner="bob")

    reopened = SQLiteCampaignStore(str(tmp_path / "campaigns.db"))
    alpha = reopened.get("tenant-alpha", "campaign-1")
    assert alpha.owner == "alice"
    assert alpha.sla_due_at == "2026-08-01T00:00:00+00:00"
    assert alpha.state == "in_progress"
    assert alpha.verification_status == "pending"
    assert reopened.get("tenant-beta", "campaign-1").owner == "bob"


def test_campaign_store_selects_postgres_for_multi_replica(monkeypatch) -> None:
    sentinel = object()
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://db/agent_bom")
    monkeypatch.setitem(
        sys.modules,
        "agent_bom.api.postgres_campaign",
        types.SimpleNamespace(PostgresCampaignStore=lambda: sentinel),
    )
    set_campaign_store(None)

    assert get_campaign_store() is sentinel
    set_campaign_store(None)


def test_postgres_campaign_store_uses_tenant_key_rls_and_scoped_upsert(monkeypatch) -> None:
    import agent_bom.api.postgres_campaign as module

    executed: list[tuple[str, tuple[Any, ...] | None]] = []
    rls: list[tuple[str, str]] = []
    stored = ("tenant-alpha", "campaign-1", "alice", None, "in_progress", "pending", "2026-07-17T00:00:00Z")

    class _Cursor:
        def fetchone(self):
            return stored

        def fetchall(self):
            return [stored]

    class _Conn:
        def execute(self, sql, params=None):
            executed.append((str(sql), params))
            return _Cursor()

        def commit(self):
            return None

    class _Pool:
        @contextmanager
        def connection(self):
            yield _Conn()

    @contextmanager
    def _tenant_connection(pool):
        yield _Conn()

    monkeypatch.setattr(module, "ensure_postgres_schema_version", lambda *args: None)
    monkeypatch.setattr(module, "_ensure_tenant_rls", lambda conn, table, column: rls.append((table, column)))
    monkeypatch.setattr(module, "_tenant_connection", _tenant_connection)
    store = module.PostgresCampaignStore(pool=_Pool())
    row = store.upsert("tenant-alpha", "campaign-1", owner="alice", state="in_progress", verification_status="pending")

    schema_sql = "\n".join(sql for sql, _ in executed)
    assert "PRIMARY KEY (tenant_id, campaign_id)" in schema_sql
    assert rls == [("risk_campaign_workflows", "tenant_id")]
    upsert = next(params for sql, params in executed if "ON CONFLICT (tenant_id, campaign_id)" in sql)
    assert upsert[:2] == ("tenant-alpha", "campaign-1")
    assert row.tenant_id == "tenant-alpha"


def test_postgres_campaign_reconcile_locks_tenant_before_read(monkeypatch) -> None:
    import agent_bom.api.postgres_campaign as module

    executed: list[str] = []

    class _Cursor:
        def fetchall(self):
            return []

    class _Conn:
        def execute(self, sql, params=None):
            executed.append(str(sql))
            return _Cursor()

        def commit(self):
            return None

    class _Pool:
        @contextmanager
        def connection(self):
            yield _Conn()

    @contextmanager
    def _tenant_connection(pool):
        yield _Conn()

    monkeypatch.setattr(module, "ensure_postgres_schema_version", lambda *args: None)
    monkeypatch.setattr(module, "_ensure_tenant_rls", lambda *args: None)
    monkeypatch.setattr(module, "_tenant_connection", _tenant_connection)
    store = module.PostgresCampaignStore(pool=_Pool())
    store.reconcile_memberships("tenant-alpha", {})
    lock_index = next(index for index, sql in enumerate(executed) if "pg_advisory_xact_lock" in sql)
    read_index = next(index for index, sql in enumerate(executed) if "FOR UPDATE" in sql)
    assert lock_index < read_index


def test_campaign_api_requires_auth_and_rejects_viewer_writes(monkeypatch) -> None:
    from agent_bom.api.server import app

    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: _findings())
    client = TestClient(app)

    assert client.get("/v1/campaigns").status_code == 401
    assert client.patch("/v1/campaigns/campaign-1", json={"owner": "alice"}, headers=_headers(role="viewer")).status_code == 403


def test_campaign_api_derives_from_bulk_findings_spine() -> None:
    from agent_bom.api.server import app

    client = TestClient(app)
    ingested = client.post(
        "/v1/findings/bulk",
        json={"source": "contract-test", "findings": _findings()},
        headers=_headers(tenant="default"),
    )
    assert ingested.status_code == 201, ingested.text

    response = client.get("/v1/campaigns", headers=_headers(tenant="default"))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["count"] == 2
    assert {campaign["source"] for campaign in body["campaigns"]} == {"canonical_findings_spine"}


def test_findings_window_excludes_old_completed_scan_but_keeps_recent_bulk() -> None:
    from agent_bom.api.server import app

    job = ScanJob(
        job_id="old",
        tenant_id="default",
        created_at="2025-01-01T00:00:00Z",
        completed_at="2025-01-01T01:00:00Z",
        status=JobStatus.DONE,
        request=ScanRequest(),
        result={"findings": [{"id": "old-finding", "severity": "critical"}]},
    )
    from agent_bom.api.stores import _get_store

    _get_store().put(job)
    client = TestClient(app)
    client.post(
        "/v1/findings/bulk",
        json={"source": "recent", "findings": [{"id": "recent-finding", "severity": "high"}]},
        headers=_headers(tenant="default"),
    )
    findings = client.get("/v1/findings?window_days=90", headers=_headers(tenant="default")).json()["findings"]
    assert {row["id"] for row in findings} == {"recent-finding"}


def test_campaign_api_labels_bounded_source_as_truncated(monkeypatch) -> None:
    from agent_bom.api.server import app

    findings = [{"id": f"finding-{idx}", "severity": "low"} for idx in range(1000)]
    monkeypatch.setattr(
        "agent_bom.api.routes.campaigns._load_findings",
        lambda request: {"findings": findings, "total": 1001, "total_approximate": False, "has_more": True},
    )
    response = TestClient(app).get("/v1/campaigns", headers=_headers())

    assert response.status_code == 200
    assert response.json()["finding_limit"] == 1000
    assert response.json()["finding_window_days"] == 90
    assert response.json()["truncated"] is True
    expected = response.json()["campaigns"][0]["expected_risk_reduction"]
    assert expected["portfolio_complete"] is False
    assert expected["scope"] == "last 90 days, first 1000 findings"


def test_campaign_api_persists_workflow_without_cross_tenant_leak(monkeypatch) -> None:
    from agent_bom.api.server import app

    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: _findings())
    client = TestClient(app)
    first = client.get("/v1/campaigns", headers=_headers()).json()["campaigns"][0]

    updated = client.patch(
        f"/v1/campaigns/{first['id']}",
        json={
            "version": first["version"],
            "owner": "security-platform",
            "sla_due_at": "2026-08-01T00:00:00Z",
            "state": "in_progress",
            "verification_status": "pending",
        },
        headers=_headers(),
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["owner"] == "security-platform"
    assert updated.json()["state"] == "in_progress"

    other = client.get("/v1/campaigns", headers=_headers(tenant="tenant-beta"))
    assert other.status_code == 200
    assert other.json()["campaigns"][0]["owner"] == "payments"


def test_campaign_patch_preserves_omitted_workflow_fields(monkeypatch) -> None:
    from agent_bom.api.server import app

    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: _findings())
    client = TestClient(app)
    campaign = client.get("/v1/campaigns", headers=_headers()).json()["campaigns"][0]
    campaign_id = campaign["id"]
    first = client.patch(
        f"/v1/campaigns/{campaign_id}",
        json={"version": campaign["version"], "owner": "alice", "state": "in_progress", "verification_status": "pending"},
        headers=_headers(),
    )

    second = client.patch(f"/v1/campaigns/{campaign_id}", json={"version": first.json()["version"], "owner": "bob"}, headers=_headers())
    assert second.status_code == 200
    assert second.json()["owner"] == "bob"
    assert second.json()["state"] == "in_progress"
    assert second.json()["verification_status"] == "pending"
    stale = client.patch(f"/v1/campaigns/{campaign_id}", json={"version": campaign["version"], "owner": "lost"}, headers=_headers())
    assert stale.status_code == 409


def test_campaign_patch_rejects_invalid_sla_timestamp(monkeypatch) -> None:
    from agent_bom.api.server import app

    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: _findings())
    client = TestClient(app)
    campaign = client.get("/v1/campaigns", headers=_headers()).json()["campaigns"][0]
    campaign_id = campaign["id"]

    response = client.patch(
        f"/v1/campaigns/{campaign_id}",
        json={"version": campaign["version"], "sla_due_at": "not-a-timestamp"},
        headers=_headers(),
    )
    assert response.status_code == 422


def test_campaign_ticket_action_forbids_credentials_and_reports_partial_result(monkeypatch) -> None:
    from agent_bom.api.server import app

    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: _findings())

    async def _create(**kwargs):
        if kwargs["finding_id"] == "finding-b":
            raise RuntimeError("transport secret-token failed")
        return {"ticket": {"id": "ticket-a", "status": "open"}}

    monkeypatch.setattr("agent_bom.api.routes.campaigns.create_ticket_for_finding", _create)
    client = TestClient(app)
    campaign = next(item for item in client.get("/v1/campaigns", headers=_headers()).json()["campaigns"] if item["finding_count"] == 2)

    forbidden = client.post(
        f"/v1/campaigns/{campaign['id']}/tickets",
        json={"connection_id": "conn", "token": "nope"},
        headers=_headers(),
    )
    assert forbidden.status_code == 422
    missing_connection = client.post(f"/v1/campaigns/{campaign['id']}/tickets", json={}, headers=_headers())
    assert missing_connection.status_code == 422

    result = client.post(
        f"/v1/campaigns/{campaign['id']}/tickets",
        json={"connection_id": "conn"},
        headers=_headers(),
    )
    assert result.status_code == 207
    assert result.json()["created"] == 1
    assert result.json()["failed"] == 1
    assert "secret-token" not in result.text


def test_ticket_action_is_bounded_and_resumable_before_side_effects(monkeypatch) -> None:
    from agent_bom.api.server import app

    findings = [{"id": f"f-{i}", "purl": "pkg:npm/shared", "fixed_version": "2", "severity": "high"} for i in range(30)]
    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: findings)
    called: list[str] = []

    async def _create(**kwargs):
        called.append(kwargs["finding_id"])
        return {"ticket": {"id": kwargs["finding_id"]}}

    monkeypatch.setattr("agent_bom.api.routes.campaigns.create_ticket_for_finding", _create)
    client = TestClient(app)
    campaign = client.get("/v1/campaigns", headers=_headers()).json()["campaigns"][0]
    first = client.post(f"/v1/campaigns/{campaign['id']}/tickets", json={"connection_id": "c"}, headers=_headers()).json()
    assert first["processed"] == 25 and first["has_more"] is True and len(called) == 25
    invalid = client.post(f"/v1/campaigns/{campaign['id']}/tickets", json={"connection_id": "c", "cursor": "bad"}, headers=_headers())
    assert invalid.status_code == 400 and len(called) == 25
    second = client.post(
        f"/v1/campaigns/{campaign['id']}/tickets", json={"connection_id": "c", "cursor": first["next_cursor"]}, headers=_headers()
    ).json()
    assert second["processed"] == 5 and second["next_cursor"] is None


def test_action_cursor_binds_action_membership_items_and_connection(monkeypatch) -> None:
    from agent_bom.api.server import app

    findings = [{"id": f"f-{i}", "purl": "pkg:npm/shared@1", "fixed_version": "2", "severity": "high"} for i in range(30)]
    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: findings)
    called: list[str] = []

    async def _create(**kwargs):
        called.append(kwargs["finding_id"])
        return {"ticket": {"id": kwargs["finding_id"]}}

    monkeypatch.setattr("agent_bom.api.routes.campaigns.create_ticket_for_finding", _create)
    client = TestClient(app)
    campaign = client.get("/v1/campaigns", headers=_headers()).json()["campaigns"][0]
    first = client.post(f"/v1/campaigns/{campaign['id']}/tickets", json={"connection_id": "one"}, headers=_headers()).json()
    cursor = first["next_cursor"]
    findings.reverse()
    replay_start = len(called)
    resumed = client.post(f"/v1/campaigns/{campaign['id']}/tickets", json={"connection_id": "one", "cursor": cursor}, headers=_headers())
    assert resumed.status_code == 200
    resumed_ids = called[replay_start:]
    retry_start = len(called)
    retried = client.post(f"/v1/campaigns/{campaign['id']}/tickets", json={"connection_id": "one", "cursor": cursor}, headers=_headers())
    assert retried.status_code == 200 and called[retry_start:] == resumed_ids
    baseline = len(called)
    changed = client.post(f"/v1/campaigns/{campaign['id']}/tickets", json={"connection_id": "two", "cursor": cursor}, headers=_headers())
    assert changed.status_code == 409 and len(called) == baseline
    cross = client.post(f"/v1/campaigns/{campaign['id']}/tickets/sync?cursor={cursor}", headers=_headers())
    assert cross.status_code == 409 and len(called) == baseline
    findings.append({"id": "inserted", "purl": "pkg:npm/shared@1", "fixed_version": "2", "severity": "high"})
    stale = client.post(f"/v1/campaigns/{campaign['id']}/tickets", json={"connection_id": "one", "cursor": cursor}, headers=_headers())
    assert stale.status_code == 409 and len(called) == baseline
    findings.pop()
    findings.pop()
    deleted = client.post(f"/v1/campaigns/{campaign['id']}/tickets", json={"connection_id": "one", "cursor": cursor}, headers=_headers())
    assert deleted.status_code == 409 and len(called) == baseline


def test_malformed_cursor_has_zero_workflow_audit_or_transport_side_effects(monkeypatch) -> None:
    from agent_bom.api.server import app

    store = InMemoryCampaignStore()
    set_campaign_store(store)
    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: _findings())
    audits: list[str] = []
    calls: list[str] = []
    monkeypatch.setattr("agent_bom.api.routes.campaigns._audit", lambda action, *args, **kwargs: audits.append(action))

    async def _create(**kwargs):
        calls.append("called")
        return {}

    monkeypatch.setattr("agent_bom.api.routes.campaigns.create_ticket_for_finding", _create)
    response = TestClient(app).post("/v1/campaigns/any/tickets", json={"connection_id": "c", "cursor": "malformed"}, headers=_headers())
    assert response.status_code == 400
    assert store.list("tenant-alpha") == [] and audits == [] and calls == []


def test_campaign_audit_failure_does_not_log_raw_exception() -> None:
    from agent_bom.api.routes.campaigns import _audit

    assert "exc_info=True" not in getsource(_audit)


def test_campaign_ticket_sync_is_tenant_and_finding_scoped(monkeypatch) -> None:
    from agent_bom.api.server import app

    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: _findings())
    store = get_ticketing_store()
    for ticket_id, tenant, dedupe in (
        ("ticket-a", "tenant-alpha", "finding-a"),
        ("ticket-unrelated", "tenant-alpha", "finding-c"),
        ("ticket-other-tenant", "tenant-beta", "finding-b"),
    ):
        store.claim_ticket_link(
            TicketLink(
                id=ticket_id,
                tenant_id=tenant,
                connection_id="conn",
                dedupe_key=dedupe,
                provider="generic",
            )
        )

    called: list[str] = []

    async def _sync(**kwargs):
        called.append(kwargs["ticket_id"])
        return {"ticket": {"id": kwargs["ticket_id"], "status": "done"}}

    monkeypatch.setattr("agent_bom.api.routes.campaigns.sync_ticket_status", _sync)
    client = TestClient(app)
    campaign = next(item for item in client.get("/v1/campaigns", headers=_headers()).json()["campaigns"] if item["finding_count"] == 2)
    result = client.post(f"/v1/campaigns/{campaign['id']}/tickets/sync", headers=_headers())

    assert result.status_code == 200
    assert result.json()["synced"] == 1
    assert result.json()["per_action_credential"] is False
    assert called == ["ticket-a"]


def test_campaign_ticket_sync_returns_207_and_sanitizes_partial_failure(monkeypatch) -> None:
    from agent_bom.api.server import app

    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: _findings())
    store = get_ticketing_store()
    for ticket_id, dedupe in (("ticket-a", "finding-a"), ("ticket-b", "finding-b")):
        store.claim_ticket_link(
            TicketLink(
                id=ticket_id,
                tenant_id="tenant-alpha",
                connection_id="conn",
                dedupe_key=dedupe,
                provider="generic",
            )
        )

    async def _sync(**kwargs):
        if kwargs["ticket_id"] == "ticket-b":
            raise RuntimeError("sync leaked-secret-value")
        return {"ticket": {"id": kwargs["ticket_id"], "status": "done"}}

    monkeypatch.setattr("agent_bom.api.routes.campaigns.sync_ticket_status", _sync)
    client = TestClient(app)
    campaign = next(item for item in client.get("/v1/campaigns", headers=_headers()).json()["campaigns"] if item["finding_count"] == 2)
    result = client.post(f"/v1/campaigns/{campaign['id']}/tickets/sync", headers=_headers())

    assert result.status_code == 207
    assert result.json()["synced"] == 1
    assert result.json()["failed"] == 1
    assert "leaked-secret-value" not in result.text
