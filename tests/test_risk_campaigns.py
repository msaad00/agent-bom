from __future__ import annotations

import os
import sys
import types
from collections.abc import Iterator
from contextlib import contextmanager
from inspect import getsource
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.campaign_store import InMemoryCampaignStore, SQLiteCampaignStore, get_campaign_store, set_campaign_store
from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.risk_campaigns import derive_campaigns
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


def test_campaign_workflow_store_is_tenant_isolated() -> None:
    store = InMemoryCampaignStore()
    store.upsert("tenant-alpha", "campaign-1", owner="alice", state="in_progress")

    assert store.get("tenant-alpha", "campaign-1") is not None
    assert store.get("tenant-beta", "campaign-1") is None


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


def test_campaign_api_labels_bounded_source_as_truncated(monkeypatch) -> None:
    from agent_bom.api.server import app

    findings = [{"id": f"finding-{idx}", "severity": "low"} for idx in range(1000)]
    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: findings)
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
    campaign_id = client.get("/v1/campaigns", headers=_headers()).json()["campaigns"][0]["id"]
    client.patch(
        f"/v1/campaigns/{campaign_id}",
        json={"owner": "alice", "state": "in_progress", "verification_status": "pending"},
        headers=_headers(),
    )

    second = client.patch(f"/v1/campaigns/{campaign_id}", json={"owner": "bob"}, headers=_headers())
    assert second.status_code == 200
    assert second.json()["owner"] == "bob"
    assert second.json()["state"] == "in_progress"
    assert second.json()["verification_status"] == "pending"


def test_campaign_patch_rejects_invalid_sla_timestamp(monkeypatch) -> None:
    from agent_bom.api.server import app

    monkeypatch.setattr("agent_bom.api.routes.campaigns._load_findings", lambda request: _findings())
    client = TestClient(app)
    campaign_id = client.get("/v1/campaigns", headers=_headers()).json()["campaigns"][0]["id"]

    response = client.patch(
        f"/v1/campaigns/{campaign_id}",
        json={"sla_due_at": "not-a-timestamp"},
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
