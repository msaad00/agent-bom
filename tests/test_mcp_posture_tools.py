"""Tests for the posture-query MCP tools (mcp_tools/posture.py).

Covers the six capability tools that expose recently shipped FinOps / NHI /
cloud-inventory / access-review features to headless agents:
cost_forecast, cost_allocation, credential_expiry, nhi_discover,
cloud_inventory, access_review.

Each tool must: return a JSON string that round-trips to a dict, leak no stack
trace, and — when its capability is gated off / unconfigured — return a clean
status rather than an error or secret material.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from agent_bom.mcp_tenant import MCP_TENANT_ENV_VAR
from agent_bom.mcp_tools.posture import (
    access_review_impl,
    cloud_inventory_impl,
    cost_allocation_impl,
    cost_forecast_impl,
    credential_expiry_impl,
    nhi_discover_impl,
)


def _trunc(s: str) -> str:
    return s


def _run(coro) -> dict:
    raw = asyncio.run(coro)
    assert isinstance(raw, str), f"impl returned non-string: {type(raw)}"
    assert "Traceback (most recent call last)" not in raw, "stack trace leaked into payload"
    data = json.loads(raw)  # well-formed + JSON-serializable
    json.dumps(data)
    assert isinstance(data, dict)
    return data


def _bind_mcp_tenant(monkeypatch: pytest.MonkeyPatch, tenant_id: str) -> None:
    monkeypatch.setenv(MCP_TENANT_ENV_VAR, tenant_id)


# ---------------------------------------------------------------------------
# cost_forecast
# ---------------------------------------------------------------------------


def test_cost_forecast_returns_forecast_envelope(monkeypatch):
    _bind_mcp_tenant(monkeypatch, "t-cf")
    data = _run(cost_forecast_impl(tenant_id="t-cf", _truncate_response=_trunc))
    assert data.get("schema_version") == "observability.cost_forecast.v1"
    assert data.get("tenant_id") == "t-cf"
    # Empty history => a clear status, never an error.
    assert "error" not in data


def test_cost_forecast_agent_scoped(monkeypatch):
    _bind_mcp_tenant(monkeypatch, "t-cf2")
    data = _run(cost_forecast_impl(agent="builder", tenant_id="t-cf2", _truncate_response=_trunc))
    assert "error" not in data
    assert data.get("tenant_id") == "t-cf2"


# ---------------------------------------------------------------------------
# cost_allocation
# ---------------------------------------------------------------------------


def test_cost_allocation_returns_rollups(monkeypatch):
    _bind_mcp_tenant(monkeypatch, "t-ca")
    data = _run(cost_allocation_impl(tenant_id="t-ca", _truncate_response=_trunc))
    assert "error" not in data
    # summarize() always emits the chargeback rollup keys.
    assert "by_cost_center" in data
    assert "budget" in data
    assert "forecast" in data


def test_cost_allocation_cost_center_scoped(monkeypatch):
    _bind_mcp_tenant(monkeypatch, "t-ca2")
    data = _run(cost_allocation_impl(cost_center="platform", tag="team", tenant_id="t-ca2", _truncate_response=_trunc))
    assert "error" not in data
    assert data.get("tenant_id") == "t-ca2"


# ---------------------------------------------------------------------------
# credential_expiry
# ---------------------------------------------------------------------------


def test_credential_expiry_posture_no_secrets():
    data = _run(credential_expiry_impl(_truncate_response=_trunc))
    assert "error" not in data
    assert data.get("secret_values_included") is False
    assert "counts" in data


# ---------------------------------------------------------------------------
# nhi_discover  (gated off by default — providers unconfigured)
# ---------------------------------------------------------------------------


def test_nhi_discover_gated_off_clean_status(monkeypatch):
    _bind_mcp_tenant(monkeypatch, "t-nhi")
    # Ensure discovery flags are off so providers self-report disabled.
    for var in (
        "AGENT_BOM_OKTA_DISCOVERY",
        "AGENT_BOM_ENTRA_DISCOVERY",
        "OKTA_DISCOVERY",
        "ENTRA_DISCOVERY",
    ):
        monkeypatch.delenv(var, raising=False)
    data = _run(nhi_discover_impl(tenant_id="t-nhi", _truncate_response=_trunc))
    assert "error" not in data
    assert data.get("schema_version") == "identity.nhi.discovery.v1"
    # No provider enabled => empty, no identities, both providers reported.
    assert data.get("status") in {"empty", "ok"}
    assert data.get("count") == 0
    assert data.get("identities") == []
    assert {p.get("status") for p in data.get("providers", [])} == {"disabled"}


def test_nhi_discover_provider_filter(monkeypatch):
    _bind_mcp_tenant(monkeypatch, "t-nhi2")
    data = _run(nhi_discover_impl(providers="okta", tenant_id="t-nhi2", _truncate_response=_trunc))
    assert "error" not in data
    assert len(data.get("providers", [])) == 1


# ---------------------------------------------------------------------------
# cloud_inventory  (gated off by default — inventory flags unset)
# ---------------------------------------------------------------------------


def test_cloud_inventory_gated_off_clean_status(monkeypatch):
    _bind_mcp_tenant(monkeypatch, "t-ci")
    for var in ("AGENT_BOM_CLOUD_INVENTORY", "AGENT_BOM_AZURE_INVENTORY", "AGENT_BOM_GCP_INVENTORY"):
        monkeypatch.delenv(var, raising=False)
    data = _run(cloud_inventory_impl(tenant_id="t-ci", _truncate_response=_trunc))
    assert "error" not in data
    assert data.get("schema_version") == "cloud.inventory.summary.v1"
    assert data.get("status") == "disabled"
    assert data.get("total_resources") == 0
    assert data.get("total_identities") == 0
    assert {p["status"] for p in data["providers"]} == {"disabled"}


def test_cloud_inventory_provider_filter(monkeypatch):
    _bind_mcp_tenant(monkeypatch, "t-ci2")
    monkeypatch.delenv("AGENT_BOM_CLOUD_INVENTORY", raising=False)
    data = _run(cloud_inventory_impl(providers="aws", region="us-east-1", tenant_id="t-ci2", _truncate_response=_trunc))
    assert "error" not in data
    assert [p["provider"] for p in data["providers"]] == ["aws"]


# ---------------------------------------------------------------------------
# access_review
# ---------------------------------------------------------------------------


def test_access_review_list_empty_tenant(monkeypatch):
    _bind_mcp_tenant(monkeypatch, "t-ar-empty")
    data = _run(access_review_impl(tenant_id="t-ar-empty", _truncate_response=_trunc))
    assert "error" not in data
    assert data.get("schema_version") == "identity.access_review.v1"
    assert data.get("count") == 0
    assert data.get("campaigns") == []


def test_access_review_missing_campaign_returns_not_found(monkeypatch):
    _bind_mcp_tenant(monkeypatch, "t-ar")
    data = _run(access_review_impl(campaign_id="does-not-exist", tenant_id="t-ar", _truncate_response=_trunc))
    assert data.get("status") == "not_found"
    assert data.get("campaign_id") == "does-not-exist"


def test_access_review_get_existing_campaign(monkeypatch):
    from agent_bom.api.access_review import create_campaign, get_access_review_store, set_access_review_store

    set_access_review_store(None)  # reset to a fresh in-memory store
    store = get_access_review_store()
    tenant_id = "t-ar-real"
    _bind_mcp_tenant(monkeypatch, tenant_id)
    campaign, _items = create_campaign(
        store,
        tenant_id=tenant_id,
        name="Q3 NHI recertification",
        subjects=[{"subject_id": "svc-1", "subject_name": "build-bot", "subject_type": "service_account"}],
        created_by="tester",
        due_days=14,
    )
    try:
        data = _run(access_review_impl(campaign_id=campaign.campaign_id, tenant_id=tenant_id, _truncate_response=_trunc))
        assert "error" not in data
        assert data["campaign"]["campaign_id"] == campaign.campaign_id
        assert data["count"] == 1
        assert data["items"][0]["subject_id"] == "svc-1"
    finally:
        set_access_review_store(None)


# ---------------------------------------------------------------------------
# Registration / annotation contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool_name",
    ["cost_forecast", "cost_allocation", "credential_expiry", "nhi_discover", "cloud_inventory", "access_review"],
)
def test_new_tools_registered_read_only_strict(tool_name):
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    tool = server._tool_manager._tools.get(tool_name)
    assert tool is not None, f"{tool_name} not registered"
    params = tool.parameters or {}
    assert params.get("additionalProperties") is False, f"{tool_name} missing additionalProperties:false"
    # All six are read-only posture queries.
    assert tool.annotations is not None and tool.annotations.readOnlyHint is True
