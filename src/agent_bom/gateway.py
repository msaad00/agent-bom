"""Gateway evaluation engine — bridges policy store with proxy check_policy.

Converts GatewayPolicy models into the dict format that
``proxy.check_policy()`` already understands, then delegates rule
evaluation to that existing function.  This avoids duplicating logic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.proxy import check_policy
from agent_bom.proxy_policy import summarize_policy_bundle

if TYPE_CHECKING:
    from agent_bom.api.policy_store import GatewayPolicy


def gateway_policy_to_proxy_format(policy: "GatewayPolicy") -> dict:
    """Convert a GatewayPolicy to the dict format proxy.check_policy expects.

    The proxy format is::

        {"rules": [{"id": "...", "action": "block", "block_tools": [...], ...}]}
    """
    rules = []
    for rule in policy.rules:
        d: dict = {"id": rule.id, "action": rule.action}
        if rule.block_tools:
            d["block_tools"] = rule.block_tools
        if rule.tool_name:
            d["tool_name"] = rule.tool_name
        if rule.tool_name_pattern:
            d["tool_name_pattern"] = rule.tool_name_pattern
        if rule.arg_pattern:
            d["arg_pattern"] = rule.arg_pattern
        if rule.deny_tool_classes:
            d["deny_tool_classes"] = rule.deny_tool_classes
        if rule.read_only:
            d["read_only"] = True
        if rule.block_secret_paths:
            d["block_secret_paths"] = True
        if rule.block_unknown_egress:
            d["block_unknown_egress"] = True
        if rule.allowed_hosts:
            d["allowed_hosts"] = rule.allowed_hosts
        if rule.rate_limit is not None:
            d["rate_limit"] = rule.rate_limit
        rules.append(d)
    return {"rules": rules}


def gateway_policies_to_proxy_bundle(policies: list["GatewayPolicy"]) -> dict:
    """Convert enabled gateway policies into an effective proxy policy bundle.

    Audit-mode policies are translated to advisory-only rules so any rollout
    summary reflects actual runtime behavior rather than raw stored rule
    actions.
    """
    rules: list[dict] = []
    for policy in policies:
        if not policy.enabled:
            continue
        proxy_fmt = gateway_policy_to_proxy_format(policy)
        for rule in proxy_fmt["rules"]:
            effective_rule = dict(rule)
            if policy.mode.value != "enforce" and effective_rule.get("action", "block") in ("block", "fail"):
                effective_rule["action"] = "warn"
            rules.append(effective_rule)
    return {"rules": rules}


def summarize_gateway_policies(policies: list["GatewayPolicy"]) -> dict[str, object]:
    """Summarize the effective runtime posture of control-plane gateway policies."""
    return summarize_policy_bundle(gateway_policies_to_proxy_bundle(policies))


def evaluate_gateway_policies(
    policies: list["GatewayPolicy"],
    tool_name: str,
    arguments: dict,
) -> tuple[bool, str, str | None]:
    """Evaluate a tool call against a list of gateway policies.

    Args:
        policies: Active gateway policies to evaluate.
        tool_name: Name of the tool being called.
        arguments: Tool call arguments.

    Returns:
        ``(allowed, reason, policy_id)`` — if blocked, ``reason``
        explains why and ``policy_id`` identifies the blocking policy.
    """
    for policy in policies:
        if not policy.enabled:
            continue

        proxy_fmt = gateway_policy_to_proxy_format(policy)
        allowed, reason = check_policy(proxy_fmt, tool_name, arguments)

        if not allowed:
            if policy.mode.value == "enforce":
                return False, reason, policy.policy_id
            # audit mode — log but allow
            return True, f"[audit] {reason}", policy.policy_id

    return True, "", None
