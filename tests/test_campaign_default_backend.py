"""Default single-node evidence must reach campaign workflows without GET writes."""

import asyncio
import json
import secrets

import pytest
from starlette.testclient import TestClient

_PROXY_SECRET = secrets.token_urlsafe(32)


@pytest.fixture
def default_stores(monkeypatch, tmp_path):
    from agent_bom.api.campaign_store import SQLiteCampaignStore, get_campaign_store, set_campaign_store
    from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, get_compliance_hub_store, set_compliance_hub_store
    from agent_bom.api.store import InMemoryJobStore
    from agent_bom.api.stores import _get_store, set_job_store

    for key in ("AGENT_BOM_DB", "AGENT_BOM_POSTGRES_URL", "AGENT_BOM_EPHEMERAL_STORE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_POSTURE_PRECOMPUTE", "0")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", _PROXY_SECRET)
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-alpha")
    set_campaign_store(None)
    set_compliance_hub_store(None)
    set_job_store(None)
    campaigns, hub, jobs = get_campaign_store(), get_compliance_hub_store(), _get_store()
    assert isinstance(campaigns, SQLiteCampaignStore)
    assert isinstance(hub, InMemoryComplianceHubStore)
    assert isinstance(jobs, InMemoryJobStore)
    try:
        yield campaigns, hub, jobs
    finally:
        set_campaign_store(None)
        set_compliance_hub_store(None)
        set_job_store(None)


def _headers():
    return {
        "X-Agent-Bom-Role": "admin",
        "X-Agent-Bom-Tenant-ID": "tenant-alpha",
        "X-Agent-Bom-Proxy-Secret": _PROXY_SECRET,
    }


def _findings():
    return [{"id": "finding-a", "severity": "high", "package": "acme-lib", "fixed_version": "2.0"}]


def _ingest_findings():
    from agent_bom.api.server import app

    response = TestClient(app).post("/v1/findings/bulk", headers=_headers(), json={"source": "default-test", "findings": _findings()})
    assert response.status_code in (200, 201, 202), response.text


@pytest.mark.parametrize("source", ["hub", "job"])
def test_default_evidence_writes_enqueue_durable_campaigns(default_stores, source):
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest

    campaigns, hub, jobs = default_stores
    if source == "hub":
        _ingest_findings()
    else:
        jobs.put(
            ScanJob(
                job_id="default-scan",
                tenant_id="tenant-alpha",
                status=JobStatus.DONE,
                created_at="2026-10-07T00:00:00Z",
                request=ScanRequest(),
            )
        )
    assert campaigns.evidence_state.pending_tenants() == ["tenant-alpha"]
    assert campaigns.evidence_state.revision("tenant-alpha") == 1
    assert campaigns.evidence_state.revision("tenant-beta") == 0


@pytest.mark.parametrize("surface", ["rest", "mcp"])
def test_default_campaign_verify_before_worker_tick(default_stores, surface):
    from agent_bom.api.server import app
    from agent_bom.mcp_tools.risk_campaigns import risk_campaign_workflow_impl

    campaigns, hub, _ = default_stores
    _ingest_findings()
    client = TestClient(app)
    listed = client.get("/v1/campaigns", headers=_headers())
    assert listed.status_code == 200, listed.text
    campaign = listed.json()["campaigns"][0]
    assert campaigns.list("tenant-alpha") == []  # GET stays read-only.
    if surface == "rest":
        response = client.post(f"/v1/campaigns/{campaign['id']}/verify", headers=_headers(), json={"version": campaign["version"]})
        assert response.status_code == 200, response.text
        result = response.json()
    else:
        result = json.loads(
            asyncio.run(
                risk_campaign_workflow_impl(
                    action="verify",
                    campaign_id=campaign["id"],
                    version=campaign["version"],
                    tenant_id="tenant-alpha",
                    _authenticated_actor="test-admin",
                    _truncate_response=lambda value: value,
                )
            )
        )
    assert result["outcome"] == "still_affected", result
    assert campaigns.get("tenant-alpha", campaign["id"]).verification_status == "failed"
    assert campaigns.list("tenant-beta") == []


def test_default_background_maintenance_observes_campaigns(default_stores, monkeypatch):
    from agent_bom.api import foreground_activity
    from agent_bom.api.server import _cleanup_loop

    # Maintenance yields to the ingest request for one quiet window first.
    monkeypatch.setattr(foreground_activity, "QUIET_SECONDS", 0.05)
    campaigns, hub, _ = default_stores
    _ingest_findings()

    async def run_worker():
        task = asyncio.create_task(_cleanup_loop())
        try:
            for _ in range(100):
                if campaigns.list("tenant-alpha"):
                    return
                await asyncio.sleep(0.02)
            pytest.fail("Default background maintenance never observed campaign membership")
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(run_worker())
    assert campaigns.evidence_state.pending_tenants() == []
