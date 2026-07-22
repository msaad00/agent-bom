"""Fix-first / fusion path ranking helpers — criticality, environment, capabilities.

Pure functions used by the fix-first view and fusion node boosts so environment
and tool capability evidence affect rank without inventing new node kinds.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.risk_analyzer import CAPABILITY_WEIGHTS, ToolCapability

if TYPE_CHECKING:
    from agent_bom.graph.container import AttackPath, UnifiedGraph
    from agent_bom.graph.node import UnifiedNode


_PROD_ENVIRONMENTS = frozenset({"prod", "production", "prd", "live"})
_STAGING_ENVIRONMENTS = frozenset({"staging", "stage", "preprod", "pre-production"})


def environment_weight(node: UnifiedNode) -> float:
    """Multiplier from node environment / asset_criticality attributes."""
    attrs = node.attributes or {}
    criticality = str(attrs.get("asset_criticality") or attrs.get("criticality") or "").strip().lower()
    if criticality in {"critical", "crown_jewel", "tier0", "tier-0"}:
        return 1.25
    if criticality in {"high", "tier1", "tier-1"}:
        return 1.15
    if criticality in {"medium", "tier2", "tier-2"}:
        return 1.05

    env = str(
        attrs.get("environment")
        or getattr(getattr(node, "dimensions", None), "environment", "")
        or ""
    ).strip().lower()
    if env in _PROD_ENVIRONMENTS:
        return 1.15
    if env in _STAGING_ENVIRONMENTS:
        return 1.05
    return 1.0


def tool_capability_boost(node: UnifiedNode) -> float:
    """Standing boost from MCP tool capability tags on TOOL nodes."""
    et = getattr(node.entity_type, "value", node.entity_type)
    if str(et) != "tool":
        return 0.0
    caps = (node.attributes or {}).get("capabilities") or []
    if not isinstance(caps, list):
        return 0.0
    weights: list[float] = []
    for raw in caps:
        try:
            cap = ToolCapability(str(raw).strip().lower())
        except ValueError:
            continue
        weights.append(CAPABILITY_WEIGHTS.get(cap, 0.0))
    if not weights:
        return 0.0
    # Cap so capability never dominates toxic/admin boosts.
    return min(8.0, max(weights) * 0.8)


def path_rank_tuple(graph: UnifiedGraph, path: AttackPath) -> tuple[float, float, int, int, int]:
    """Sort key for fix-first ranking (higher is worse / fix first)."""
    env_mult = 1.0
    cap_boost = 0.0
    for hop in path.hops:
        node = graph.nodes.get(hop)
        if node is None:
            continue
        env_mult = max(env_mult, environment_weight(node))
        cap_boost = max(cap_boost, tool_capability_boost(node))
    weighted_risk = float(path.composite_risk) * env_mult + cap_boost
    return (
        weighted_risk,
        float(path.composite_risk),
        len(path.hops),
        len(path.credential_exposure),
        len(path.tool_exposure),
    )


def criticality_rank_meta(graph: UnifiedGraph, path: AttackPath) -> dict[str, object]:
    """Explainability fields for UI chips (environment + capability tags)."""
    environments: list[str] = []
    capabilities: list[str] = []
    max_env = 1.0
    for hop in path.hops:
        node = graph.nodes.get(hop)
        if node is None:
            continue
        max_env = max(max_env, environment_weight(node))
        attrs = node.attributes or {}
        env = attrs.get("environment") or getattr(getattr(node, "dimensions", None), "environment", "")
        if isinstance(env, str) and env and env not in environments:
            environments.append(env)
        et = getattr(node.entity_type, "value", node.entity_type)
        if str(et) == "tool":
            caps = attrs.get("capabilities") or []
            if isinstance(caps, list):
                for cap in caps:
                    text = str(cap).strip().lower()
                    if text and text not in capabilities:
                        capabilities.append(text)
    return {
        "environment_weight": round(max_env, 3),
        "environments": environments[:4],
        "tool_capabilities": capabilities[:8],
    }
