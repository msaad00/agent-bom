"""Posture-query MCP tools — cost, credential, identity, and cloud-inventory reads.

These wrap the recently shipped FinOps / NHI / cloud-inventory / access-review
capabilities so headless agents can query them over MCP, not just the REST API.
Every tool here is READ-ONLY and reference-only: it returns metadata and
posture verdicts, never secret values, and reuses the same implementation
functions the API routes call (no duplicated capability logic).
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from typing import Any, cast

from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


def _request_for_tenant(tenant_id: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(tenant_id=resolve_mcp_tool_tenant_id(tenant_id)))


async def cost_forecast_impl(
    *,
    agent: str = "",
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the cost_forecast tool: burn-rate + budget-runway projection."""
    try:
        from agent_bom.api.cost_forecast import forecast_for_tenant

        scoped_agent = agent.strip() or None
        payload = forecast_for_tenant(resolve_mcp_tool_tenant_id(tenant_id), agent=scoped_agent)
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP cost forecast error")
        return json.dumps({"error": sanitize_error(exc)})


async def cost_allocation_impl(
    *,
    cost_center: str = "",
    tag: str = "",
    agent: str = "",
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the cost_allocation tool: chargeback / showback rollup."""
    try:
        from agent_bom.api.routes.observability import get_llm_costs

        payload = await get_llm_costs(
            cast(Any, _request_for_tenant(tenant_id)),
            agent=agent.strip() or None,
            cost_center=cost_center.strip() or None,
            tag=tag.strip() or None,
        )
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP cost allocation error")
        return json.dumps({"error": sanitize_error(exc)})


async def credential_expiry_impl(
    *,
    _truncate_response,
) -> str:
    """Implementation of the credential_expiry tool: expiring/overdue credential posture."""
    try:
        from agent_bom.api.credential_expiry import describe_credential_expiry_posture

        payload = describe_credential_expiry_posture()
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP credential expiry error")
        return json.dumps({"error": sanitize_error(exc)})


async def nhi_discover_impl(
    *,
    providers: str = "",
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the nhi_discover tool: read-only non-human identity discovery.

    Each provider self-gates on its own discovery env flag/token; a disabled or
    unconfigured provider is reported in ``providers`` rather than failing. Never
    returns secret material.
    """
    try:
        from agent_bom.graph.nhi_overlay import merge_discovery_results
        from agent_bom.identity import (
            discover_entra_non_human_identities,
            discover_okta_non_human_identities,
        )

        selected = {part.strip().lower() for part in providers.split(",") if part.strip()} or {"okta", "entra"}
        results = []
        if "okta" in selected:
            results.append(discover_okta_non_human_identities())
        if "entra" in selected:
            results.append(discover_entra_non_human_identities())

        merged = merge_discovery_results(results)
        payload = {
            "schema_version": "identity.nhi.discovery.v1",
            "tenant_id": resolve_mcp_tool_tenant_id(tenant_id),
            "status": merged["status"],
            "providers": merged["providers"],
            "count": len(merged["identities"]),
            "identities": merged["identities"],
            "warnings": merged["warnings"],
            "note": "Reference-only discovery; no secret values are returned and no identity is mutated.",
        }
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP NHI discover error")
        return json.dumps({"error": sanitize_error(exc)})


_INVENTORY_RESOURCE_KEYS = ("buckets", "instances", "security_groups")
_INVENTORY_IDENTITY_KEYS = ("roles", "users")
_PUBLIC_INVENTORY_STATUSES = {
    "ok",
    "unknown",
    "disabled",
    "boto3_missing",
    "no_credentials",
    "partial",
}


def _summarize_inventory_payload(provider: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Reduce a per-provider inventory payload to non-secret counts.

    Reuses the builder's canonical-shape normalizer so Azure/GCP provider-native
    keys map to the same resource/identity lists the graph counts.
    """
    from agent_bom.graph.builder import _normalize_cloud_inventory

    normalized = _normalize_cloud_inventory(payload)
    resource_count = sum(len(normalized.get(key) or []) for key in _INVENTORY_RESOURCE_KEYS)
    identity_count = sum(len(normalized.get(key) or []) for key in _INVENTORY_IDENTITY_KEYS)
    # Provider discovery warnings are built from caught exceptions
    # (``sanitize_discovery_warning(exc)``), so they must not be surfaced verbatim
    # in a summary that flows to REST/MCP responses. Emit a count-derived,
    # exception-free notice instead; full warnings stay in the server log.
    warning_count = len(payload.get("warnings") or [])
    public_warnings = [f"{warning_count} provider discovery warning(s) — see server logs for detail."] if warning_count else []
    raw_status = str(payload.get("status", "unknown") or "unknown").strip().lower()
    public_status = raw_status if raw_status in _PUBLIC_INVENTORY_STATUSES else "unknown"
    return {
        "provider": provider,
        "status": public_status,
        "account": payload.get("account_id") or payload.get("subscription_id") or payload.get("project_id") or None,
        "region": payload.get("region") or "",
        "resource_count": resource_count,
        "identity_count": identity_count,
        "node_summary": {
            "buckets": len(normalized.get("buckets") or []),
            "instances": len(normalized.get("instances") or []),
            "security_groups": len(normalized.get("security_groups") or []),
            "roles": len(normalized.get("roles") or []),
            "users": len(normalized.get("users") or []),
        },
        "warnings": public_warnings,
    }


async def cloud_inventory_impl(
    *,
    providers: str = "",
    region: str = "",
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the cloud_inventory tool: estate-wide cloud asset summary.

    Each provider self-gates on its own ``AGENT_BOM_*_INVENTORY`` env flag and
    credentials; a disabled provider returns a clear ``status`` (``disabled`` /
    ``no_credentials`` / ``sdk_missing`` …) and contributes zero nodes. Returns
    resource/identity counts and a node summary only — never resource secrets.
    """
    try:
        from agent_bom.cloud import aws_inventory, azure_inventory, gcp_inventory

        selected = {part.strip().lower() for part in providers.split(",") if part.strip()} or {"aws", "azure", "gcp"}
        scoped_region = region.strip() or None
        summaries: list[dict[str, Any]] = []
        if "aws" in selected:
            summaries.append(_summarize_inventory_payload("aws", aws_inventory.discover_inventory(region=scoped_region)))
        if "azure" in selected:
            summaries.append(_summarize_inventory_payload("azure", azure_inventory.discover_inventory()))
        if "gcp" in selected:
            summaries.append(_summarize_inventory_payload("gcp", gcp_inventory.discover_inventory()))

        any_enabled = any(s["status"] != "disabled" for s in summaries)
        payload = {
            "schema_version": "cloud.inventory.summary.v1",
            "tenant_id": resolve_mcp_tool_tenant_id(tenant_id),
            "status": "ok" if any_enabled else "disabled",
            "total_resources": sum(s["resource_count"] for s in summaries),
            "total_identities": sum(s["identity_count"] for s in summaries),
            "providers": summaries,
            "note": (
                "Estate-wide inventory is opt-in per provider via AGENT_BOM_CLOUD_INVENTORY / "
                "AGENT_BOM_AZURE_INVENTORY / AGENT_BOM_GCP_INVENTORY. Reference-only counts; no resource secrets are returned."
            ),
        }
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP cloud inventory error")
        return json.dumps({"error": sanitize_error(exc)})


async def access_review_impl(
    *,
    campaign_id: str = "",
    tenant_id: str = "default",
    limit: int = 200,
    _truncate_response,
) -> str:
    """Implementation of the access_review tool: list / get recertification campaigns.

    Not read-only: fetching/listing recomputes and persists each campaign's
    status (to surface overdue), so this is an idempotent write. Pass
    ``campaign_id`` to fetch one campaign with its review items; omit it to list
    campaigns. Creating a campaign or submitting a decision is a separate WRITE
    not exposed here.
    """
    try:
        from agent_bom.api.access_review import get_access_review_store, refresh_campaign_status

        tid = resolve_mcp_tool_tenant_id(tenant_id)
        store = get_access_review_store()
        target = campaign_id.strip()
        if target:
            campaign = refresh_campaign_status(store, tenant_id=tid, campaign_id=target)
            if campaign is None:
                return json.dumps({"status": "not_found", "campaign_id": target, "tenant_id": tid})
            items = store.list_items(target, tid)
            payload = {
                "schema_version": "identity.access_review.v1",
                "tenant_id": tid,
                "campaign": campaign.to_public_dict(),
                "count": len(items),
                "items": [i.to_public_dict() for i in items],
            }
            return _truncate_response(json.dumps(payload, indent=2, default=str))

        bounded = max(1, min(int(limit), 1000))
        campaigns = store.list_campaigns(tid, limit=bounded)
        refreshed = [refresh_campaign_status(store, tenant_id=tid, campaign_id=c.campaign_id) or c for c in campaigns]
        payload = {
            "schema_version": "identity.access_review.v1",
            "tenant_id": tid,
            "count": len(refreshed),
            "campaigns": [c.to_public_dict() for c in refreshed],
        }
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP access review error")
        return json.dumps({"error": sanitize_error(exc)})
