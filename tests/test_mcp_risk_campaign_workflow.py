from __future__ import annotations

import asyncio
import json

from agent_bom.api.campaign_store import InMemoryCampaignStore, set_campaign_store
from agent_bom.api.idempotency_store import InMemoryIdempotencyStore
from agent_bom.api.risk_campaigns import derive_campaigns
from agent_bom.api.stores import set_idempotency_store
from agent_bom.mcp_tools.risk_campaigns import risk_campaign_workflow_impl


def _truncate(value: str) -> str:
    return value


def test_mcp_risk_campaign_verification_uses_shared_outcome_and_tenant(monkeypatch) -> None:
    findings = [{"id": "finding-a", "severity": "high", "package": "acme-lib", "fixed_version": "2.0"}]
    campaign = derive_campaigns(findings, tenant_id="tenant-alpha", workflow_by_id={})[0]
    campaign_id = campaign["id"]
    store = InMemoryCampaignStore()
    store.reconcile_memberships(
        "tenant-alpha",
        {campaign_id: (campaign["membership_fingerprint"], ("finding-a",), campaign["title"])},
    )
    set_campaign_store(store)
    set_idempotency_store(InMemoryIdempotencyStore())
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-alpha")
    monkeypatch.setattr(
        "agent_bom.mcp_tools.risk_campaigns._load_source",
        lambda tenant_id: {"findings": [{**findings[0], "fixed_version": "2.1"}], "total": 1, "has_more": False},
    )
    try:
        result = json.loads(
            asyncio.run(
                risk_campaign_workflow_impl(
                    action="verify",
                    campaign_id=campaign_id,
                    version=1,
                    idempotency_key="mcp-verify-once",
                    tenant_id="tenant-alpha",
                    _authenticated_actor="mcp-admin",
                    _truncate_response=_truncate,
                )
            )
        )
    finally:
        set_campaign_store(None)
        set_idempotency_store(None)

    assert result["outcome"] == "still_affected"
    assert result["remaining_finding_ids"] == ["finding-a"]
    assert result["campaign_id"] == campaign_id
    assert store.get("tenant-alpha", campaign_id).verification_status == "failed"
    assert store.get("default", campaign_id) is None


def test_risk_campaign_workflow_is_advertised_and_write_gated() -> None:
    from agent_bom.mcp_server_metadata import _TOOL_CAPABILITY_CLASSES, registered_mcp_tool_decorator_names, server_card_tool_names

    assert "risk_campaign_workflow" in server_card_tool_names()
    assert "risk_campaign_workflow" in registered_mcp_tool_decorator_names()
    assert "WRITE" in _TOOL_CAPABILITY_CLASSES["risk_campaign_workflow"]


def test_mcp_campaign_absence_returns_unavailable_and_keeps_workflow(monkeypatch):
    findings = [{"id": "finding-a", "severity": "high"}]
    campaign = derive_campaigns(findings, tenant_id="tenant-alpha", workflow_by_id={})[0]
    store = InMemoryCampaignStore()
    baseline = store.reconcile_memberships(
        "tenant-alpha", {campaign["id"]: (campaign["membership_fingerprint"], ("finding-a",), campaign["title"])}
    )[0]
    set_campaign_store(store)
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-alpha")
    monkeypatch.setattr(
        "agent_bom.mcp_tools.risk_campaigns._load_source", lambda tenant_id: {"findings": [], "total": 0, "has_more": False}
    )
    try:
        result = json.loads(
            asyncio.run(
                risk_campaign_workflow_impl(
                    action="verify",
                    campaign_id=campaign["id"],
                    version=baseline.version,
                    tenant_id="tenant-alpha",
                    _truncate_response=_truncate,
                )
            )
        )
        assert store.get("tenant-alpha", campaign["id"]) == baseline
    finally:
        set_campaign_store(None)
    assert result["status"] == "rejected"
    assert result["http_status"] == 409
    assert result["outcome"] == "unavailable_evidence"
    assert result["retry_state"] == "awaiting_fresh_scope_evidence"
    assert "alternate graph paths have not been verified" in result["reason"]


def test_mcp_verification_preserves_unreconfirmed_evidence_rejection(monkeypatch):
    findings = [{"id": "finding-a", "severity": "high", "observation_status": "unreconfirmed"}]
    campaign = derive_campaigns(findings, tenant_id="tenant-alpha", workflow_by_id={})[0]
    store = InMemoryCampaignStore()
    store.reconcile_memberships("tenant-alpha", {campaign["id"]: (campaign["membership_fingerprint"], ("finding-a",), campaign["title"])})
    before = store.get("tenant-alpha", campaign["id"])
    set_campaign_store(store)
    set_idempotency_store(InMemoryIdempotencyStore())
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-alpha")
    monkeypatch.setattr(
        "agent_bom.mcp_tools.risk_campaigns._load_source", lambda tenant_id: {"findings": findings, "total": 1, "has_more": False}
    )
    try:
        result = json.loads(
            asyncio.run(
                risk_campaign_workflow_impl(
                    action="verify",
                    campaign_id=campaign["id"],
                    version=1,
                    tenant_id="tenant-alpha",
                    _authenticated_actor="mcp-admin",
                    _truncate_response=_truncate,
                )
            )
        )
    finally:
        set_campaign_store(None)
        set_idempotency_store(None)
    assert result["http_status"] == 409
    assert result["outcome"] == "unavailable_evidence"
    assert result["retry_state"] == "awaiting_fresh_scope_evidence"
    assert store.get("tenant-alpha", campaign["id"]) == before
