"""Registration boundary for connected endpoint and ticketing tools."""

from typing import Any

from agent_bom.mcp_server_specialized import register_specialized_ai_tools
from agent_bom.mcp_server_ticketing_tools import register_ticketing_tools
from agent_bom.mcp_tools.compromise import register_compromise_tool
from agent_bom.mcp_tools.endpoint_connectors import register_endpoint_tools


def register_connected_tools(
    mcp: Any, *, read_only: Any, write_action: Any, execute_tool_async: Any, truncate_response: Any, safe_path: Any
) -> None:
    register_compromise_tool(mcp, read_only=read_only, execute_tool_async=execute_tool_async, truncate_response=truncate_response)
    register_endpoint_tools(mcp, read_only=read_only, write_action=write_action, execute_tool_async=execute_tool_async)
    register_ticketing_tools(mcp, write_action=write_action, execute_tool_async=execute_tool_async, truncate_response=truncate_response)
    register_specialized_ai_tools(
        mcp,
        read_only=read_only,
        write_action=write_action,
        execute_tool_async=execute_tool_async,
        safe_path=safe_path,
        truncate_response=truncate_response,
    )
