"""Per-server dependencies captured by operator tool registration factories."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations


@dataclass(frozen=True)
class OperatorToolBindings:
    mcp: FastMCP
    read_only: ToolAnnotations
    write_action: ToolAnnotations
    write_idempotent: ToolAnnotations
    execute_tool_async: Callable[..., Awaitable[str]]
    execute_tool_sync_async: Callable[..., Awaitable[str]]
    safe_path: Callable[..., Any]
    run_scan_pipeline: Callable[..., Awaitable[Any]]
    truncate_response: Callable[..., str]
    validate_ecosystem: Callable[..., Any]
    get_registry_data_raw: Callable[..., Any]
    build_dep_graph_from_agents: Callable[..., Any]
