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
    findings = [{"id": "finding-a", "severity": "high"}]
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
        lambda tenant_id: {"findings": findings, "total": 1, "has_more": False},
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
    assert result["campaign_id"] == campaign_id
    assert store.get("tenant-alpha", campaign_id).verification_status == "failed"
    assert store.get("default", campaign_id) is None


def test_risk_campaign_workflow_is_advertised_and_write_gated() -> None:
    from agent_bom.mcp_server_metadata import _TOOL_CAPABILITY_CLASSES, registered_mcp_tool_decorator_names, server_card_tool_names

    assert "risk_campaign_workflow" in server_card_tool_names()
    assert "risk_campaign_workflow" in registered_mcp_tool_decorator_names()
    assert "WRITE" in _TOOL_CAPABILITY_CLASSES["risk_campaign_workflow"]
