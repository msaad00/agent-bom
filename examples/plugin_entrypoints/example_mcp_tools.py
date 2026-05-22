"""Example third-party MCP tool plugin registration.

The entry point advertises where the operator-owned package registers tools.
agent-bom discovers this metadata only; it does not attach the tool unless an
operator intentionally imports and wires the package.
"""

from __future__ import annotations

import json
from typing import Any

from agent_bom.extensions import ExtensionCapabilities
from agent_bom.plugin_entrypoints import McpToolPluginRegistration


def registration() -> McpToolPluginRegistration:
    """Return the plugin registration advertised by package entry points."""

    return McpToolPluginRegistration(
        name="example-posture-tool",
        module="example_mcp_tools",
        register_attr="register_tools",
        capabilities=ExtensionCapabilities(
            scan_modes=("mcp_tool",),
            required_scopes=("operator_enabled_mcp_tool",),
            data_boundary="metadata_only_example",
            writes=False,
            network_access=False,
            guarantees=("read_only", "operator_enabled"),
        ),
        source="example",
    )


def register_tools(mcp: Any) -> None:
    """Register one read-only tool on a FastMCP-compatible object."""

    @mcp.tool(title="Example Asset Posture")
    def example_asset_posture(asset_id: str = "local") -> str:
        """Return a small metadata-only posture payload for an operator asset."""

        return json.dumps(
            {
                "asset_id": asset_id,
                "status": "observed",
                "data_boundary": "metadata_only_example",
                "writes": False,
            },
            sort_keys=True,
        )
