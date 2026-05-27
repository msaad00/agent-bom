"""Bundled gateway runtime policy templates."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from agent_bom.api.policy_store import GatewayPolicy, GatewayRule, PolicyMode
from agent_bom.gateway import gateway_policies_to_proxy_bundle

GatewayBaselineMode = Literal["audit", "enforce"]
GatewayBaselineFormat = Literal["proxy", "control-plane"]

BASELINE_GATEWAY_POLICY_ID = "agent-bom-gateway-baseline"
BASELINE_GATEWAY_POLICY_NAME = "agent-bom gateway baseline"
BASELINE_GATEWAY_SCHEMA_VERSION = "gateway.policy_pack.v1"


def baseline_gateway_rules() -> list[GatewayRule]:
    """Return secure-by-default gateway rules shared by all renderers."""
    return [
        GatewayRule(
            id="baseline-dangerous-tool-classes",
            description="Warn or block shell, process, destructive, and admin-style tools.",
            action="block",
            deny_tool_classes=["execute", "destructive", "admin"],
        ),
        GatewayRule(
            id="baseline-read-only",
            description="Warn or block write and execute behavior unless an operator opts out.",
            action="block",
            read_only=True,
        ),
        GatewayRule(
            id="baseline-secret-paths",
            description="Warn or block tool calls that reference common credential and secret paths.",
            action="block",
            block_secret_paths=True,
        ),
        GatewayRule(
            id="baseline-screen-capture",
            description="Warn or block screenshot and screen-capture tools by default.",
            action="block",
            deny_tool_classes=["screen_capture"],
        ),
        GatewayRule(
            id="baseline-unknown-egress",
            description="Warn or block outbound URL/host arguments until allowed hosts are added.",
            action="block",
            block_unknown_egress=True,
            allowed_hosts=[],
        ),
    ]


def baseline_gateway_policy(
    *,
    mode: GatewayBaselineMode = "audit",
    tenant_id: str = "default",
) -> GatewayPolicy:
    """Return the bundled baseline as a GatewayPolicy model."""
    policy_mode = PolicyMode(mode)
    now = datetime.now(timezone.utc).isoformat()
    return GatewayPolicy(
        policy_id=BASELINE_GATEWAY_POLICY_ID,
        name=BASELINE_GATEWAY_POLICY_NAME,
        description=(
            "Bundled secure-by-default gateway baseline for MCP runtime traffic. "
            "Audit mode is the default so first rollout produces warnings before enforcement."
        ),
        mode=policy_mode,
        rules=baseline_gateway_rules(),
        created_at=now,
        updated_at=now,
        enabled=True,
        tenant_id=tenant_id,
    )


def render_gateway_baseline_policy(
    *,
    mode: GatewayBaselineMode = "audit",
    output_format: GatewayBaselineFormat = "proxy",
    tenant_id: str = "default",
) -> dict:
    """Render the baseline for local gateway use or control-plane import."""
    policy = baseline_gateway_policy(mode=mode, tenant_id=tenant_id)
    if output_format == "control-plane":
        payload = policy.model_dump(mode="json")
        payload["schema_version"] = BASELINE_GATEWAY_SCHEMA_VERSION
        return payload
    if output_format != "proxy":
        raise ValueError(f"unsupported gateway baseline format: {output_format}")

    bundle = gateway_policies_to_proxy_bundle([policy])
    bundle.update(
        {
            "schema_version": BASELINE_GATEWAY_SCHEMA_VERSION,
            "name": BASELINE_GATEWAY_POLICY_NAME,
            "policy_id": BASELINE_GATEWAY_POLICY_ID,
            "mode": mode,
            "description": policy.description,
        }
    )
    return bundle


__all__ = [
    "BASELINE_GATEWAY_POLICY_ID",
    "BASELINE_GATEWAY_POLICY_NAME",
    "BASELINE_GATEWAY_SCHEMA_VERSION",
    "baseline_gateway_policy",
    "baseline_gateway_rules",
    "render_gateway_baseline_policy",
]
