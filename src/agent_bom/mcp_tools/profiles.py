"""Bounded, startup-selected MCP catalogs. Profiles are not authorization grants."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_bom.mcp_server_metadata import _DEFAULT_PROFILE_TOOL_NAMES

DEFAULT_PROFILE = "scan"
PROFILE_VERSION = 1


@dataclass(frozen=True)
class ToolProfile:
    description: str
    tools: frozenset[str] | None
    prompts: frozenset[str] | None
    resources: frozenset[str] | None


_COMMON_RESOURCES = frozenset({"profiles://catalog", "metrics://tools"})

_GUIDED_TOOL_NAMES = frozenset(
    {
        "audit_integrity",
        "check",
        "cis_benchmark",
        "cloud_inventory",
        "compliance",
        "context_graph",
        "exposure_paths",
        "firewall_check",
        "fleet_scan",
        "gateway_status",
        "generate_sbom",
        "graph_export",
        "graph_correlate",
        "graph_correlation_status",
        "intel_lookup",
        "inventory_asset",
        "inventory_list",
        "inventory_summary",
        "policy_check",
        "proxy_alerts",
        "registry_lookup",
        "remediate",
        "runtime_correlate",
        "scan",
        "should_i_deploy",
    }
)

PROFILES = {
    "scan": ToolProfile(
        "Scan a project or package, inspect exposure, and draft a fix plan.",
        frozenset(_DEFAULT_PROFILE_TOOL_NAMES),
        frozenset({"quick-audit", "pre-install-check", "remediation-plan"}),
        _COMMON_RESOURCES | {"policy://template", "compliance://framework-controls"},
    ),
    "graph": ToolProfile(
        "Browse persisted assets and inspect or correlate scoped graph evidence.",
        frozenset(
            {
                "inventory_summary",
                "inventory_list",
                "inventory_asset",
                "context_graph",
                "exposure_paths",
                "graph_correlate",
                "graph_correlation_status",
                "graph_export",
            }
        ),
        frozenset(),
        _COMMON_RESOURCES | {"schema://inventory-v1"},
    ),
    "cloud": ToolProfile(
        "Inspect cloud inventory, connection scope and CIS posture.",
        frozenset({"cloud_inventory", "cis_benchmark", "graph_export", "inventory_summary", "inventory_asset"}),
        frozenset({"cloud-connection-review"}),
        _COMMON_RESOURCES | {"schema://inventory-v1", "bestpractices://mcp-hardening"},
    ),
    "runtime": ToolProfile(
        "Inspect gateway policy, alerts, fleet evidence and incident context.",
        frozenset(
            {"gateway_status", "proxy_alerts", "firewall_check", "fleet_scan", "runtime_correlate", "intel_lookup", "exposure_paths"}
        ),
        frozenset({"incident-triage", "gateway-fleet-live-demo"}),
        _COMMON_RESOURCES | {"schema://inventory-v1", "bestpractices://mcp-hardening"},
    ),
    "audit": ToolProfile(
        "Scan and review compliance mappings, policy and audit integrity.",
        frozenset({"scan", "compliance", "policy_check", "audit_integrity"}),
        frozenset({"compliance-report"}),
        _COMMON_RESOURCES | {"policy://template", "compliance://framework-controls"},
    ),
    "guided": ToolProfile("Compatibility catalog for all eight workflow prompts.", _GUIDED_TOOL_NAMES, None, None),
    "full": ToolProfile("Explicit compatibility catalog with all tools and optional plugins.", None, None, None),
}


def get_profile(name: str) -> ToolProfile:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(f"Unknown MCP tool profile {name!r}; expected one of: {', '.join(PROFILES)}") from None


def profile_catalog(active: str) -> dict[str, Any]:
    """Discover capabilities without sending the complete catalog's schemas."""
    get_profile(active)
    return {
        "version": PROFILE_VERSION,
        "active_profile": active,
        "default_profile": DEFAULT_PROFILE,
        "selection": (
            "Select a profile at startup with agent-bom mcp server --profile NAME, "
            "then reconnect the client. Profiles do not grant permissions."
        ),
        "profiles": [
            {
                "name": name,
                "description": spec.description,
                "tools": sorted(spec.tools) if spec.tools is not None else "complete catalog",
                "command": f"agent-bom mcp server --profile {name}",
            }
            for name, spec in PROFILES.items()
        ],
    }


def _selected_decorator(original: Any, allowed: frozenset[str], kind: str) -> Any:
    def filtered(*args: Any, **kwargs: Any) -> Any:
        def decorate(fn: Any) -> Any:
            key = (
                (args[0] if args else kwargs.get("uri"))
                if kind == "resource"
                else kwargs.get("name", args[0] if args else None) or fn.__name__
            )
            return original(*args, **kwargs)(fn) if key in allowed else fn

        return decorate

    return filtered


def configure_registration(mcp: Any, name: str) -> None:
    """Skip excluded decorators before FastMCP constructs expensive schemas.

    Registration is scoped to this server instance, never a global manager.
    Keeping the filter installed also bounds later plugin registration.
    """
    spec = get_profile(name)
    for kind, allowed in (("tool", spec.tools), ("prompt", spec.prompts), ("resource", spec.resources)):
        if allowed is None:
            continue
        setattr(mcp, kind, _selected_decorator(getattr(mcp, kind), allowed, kind))
