"""Gateway evaluation engine — bridges policy store with proxy check_policy.

Converts GatewayPolicy models into the dict format that
``proxy.check_policy()`` already understands, then delegates rule
evaluation to that existing function.  This avoids duplicating logic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.proxy import check_policy

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
        rules.append(d)
    return {"rules": rules}


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
