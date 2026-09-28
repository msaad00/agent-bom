"""Compatibility entry point for bounded operator MCP registration groups."""

from __future__ import annotations


def register_operator_tools(
    mcp,
    *,
    read_only,
    write_action,
    write_idempotent,
    execute_tool_async,
    execute_tool_sync_async,
    safe_path,
    run_scan_pipeline,
    truncate_response,
    validate_ecosystem,
    get_registry_data_raw,
    build_dep_graph_from_agents,
) -> None:
    """Register operator tools in their public order with server-local dependencies."""
    from agent_bom.mcp_tools.operator import benchmarks, findings, governance, graphs, identity, runtime, scanning
    from agent_bom.mcp_tools.operator.bindings import OperatorToolBindings

    bindings = OperatorToolBindings(
        mcp=mcp,
        read_only=read_only,
        write_action=write_action,
        write_idempotent=write_idempotent,
        execute_tool_async=execute_tool_async,
        execute_tool_sync_async=execute_tool_sync_async,
        safe_path=safe_path,
        run_scan_pipeline=run_scan_pipeline,
        truncate_response=truncate_response,
        validate_ecosystem=validate_ecosystem,
        get_registry_data_raw=get_registry_data_raw,
        build_dep_graph_from_agents=build_dep_graph_from_agents,
    )
    for group in (findings, scanning, graphs, benchmarks, runtime, identity, governance):
        for register in group.REGISTRATIONS:
            register(bindings)
