"""Read-only MCP projection of the canonical pinned compromise assessment."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from pydantic import Field, ValidationError

from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.mcp_errors import (
    CODE_NOT_FOUND_RESOURCE,
    CODE_UNSUPPORTED_BACKEND,
    CODE_UPSTREAM_UNAVAILABLE,
    CODE_VALIDATION_INVALID_ARGUMENT,
    mcp_error_json,
)
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id


async def compromise_assessment_impl(
    *,
    root_node_id: str,
    scan_id: str,
    assume_control: bool,
    snapshot_generation: str | None = None,
    affected_node_id: str | None = None,
    assume_exploitation: bool = False,
    max_relationships: int = 128,
    max_evidence_age_seconds: int = 3600,
    tenant_id: str = "default",
    _get_graph_store=None,
    _truncate_response=None,
) -> str:
    try:
        from fastapi import HTTPException

        from agent_bom.api.graph_compromise import GraphCompromiseRequest, assess_snapshot
    except ImportError:
        return mcp_error_json(CODE_UNSUPPORTED_BACKEND, "Install agent-bom[api] to assess persisted graph snapshots.")
    try:
        request = GraphCompromiseRequest.model_validate(
            {
                "root_node_id": root_node_id,
                "scan_id": scan_id,
                "assume_control": assume_control,
                "snapshot_generation": snapshot_generation,
                "affected_node_id": affected_node_id,
                "assume_exploitation": assume_exploitation,
                "max_relationships": max_relationships,
                "max_evidence_age_seconds": max_evidence_age_seconds,
            }
        )
    except ValidationError:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT, "Explicit control and valid snapshot, node, and evidence bounds are required."
        )
    tenant = resolve_mcp_tool_tenant_id(tenant_id)
    try:
        if _get_graph_store is None:
            from agent_bom.mcp_tools.storage import default_graph_store as _get_graph_store

        async with adaptive_backpressure("graph"):
            result = await asyncio.to_thread(assess_snapshot, _get_graph_store(), request, tenant_id=tenant)
        encoded = result.model_dump_json()
        return _truncate_response(encoded) if _truncate_response else encoded
    except HTTPException as exc:
        code = {404: CODE_NOT_FOUND_RESOURCE, 501: CODE_UNSUPPORTED_BACKEND}.get(exc.status_code, CODE_VALIDATION_INVALID_ARGUMENT)
        return mcp_error_json(
            code,
            "Assessment unavailable for this snapshot or assumption; reload the snapshot and verify its scope.",
            details={"status": exc.status_code},
        )
    except BackpressureRejectedError:
        return mcp_error_json(CODE_UPSTREAM_UNAVAILABLE, "Graph assessment capacity is busy; retry later.")
    except Exception:
        return mcp_error_json(CODE_UPSTREAM_UNAVAILABLE, "Graph storage is temporarily unavailable; retry the request.")


def register_compromise_tool(mcp: Any, *, read_only: Any, execute_tool_async: Any, truncate_response: Any) -> None:
    @mcp.tool(annotations=read_only, title="Compromise Assessment")
    async def compromise_assessment(
        root_node_id: Annotated[str, Field(min_length=1, max_length=1024, description="Selected node in the authorized graph snapshot.")],
        scan_id: Annotated[
            str, Field(min_length=1, max_length=1024, description="Persisted snapshot to assess; use graph inventory to select it.")
        ],
        assume_control: Annotated[
            bool,
            Field(strict=True, description="Must explicitly be true: this is a hypothetical control assumption, not observed compromise."),
        ],
        snapshot_generation: Annotated[
            str | None, Field(max_length=256, description="Require this previously returned snapshot revision.")
        ] = None,
        affected_node_id: Annotated[str | None, Field(max_length=1024, description="Affected component linked to a finding root.")] = None,
        assume_exploitation: Annotated[
            bool, Field(strict=True, description="Required for a finding root; hypothetical exploitation only.")
        ] = False,
        max_relationships: Annotated[int, Field(ge=1, le=512, description="Maximum direct outgoing relationships examined.")] = 128,
        max_evidence_age_seconds: Annotated[int, Field(ge=1, le=86400, description="Maximum authorization receipt age in seconds.")] = 3600,
        tenant_id: Annotated[str, Field(description="Compatibility hint; the server-bound tenant remains authoritative.")] = "default",
    ) -> str:
        """Inspect action-scoped permission receipts under an explicit control assumption.

        Returns the pinned revision, denials, observations and missing evidence.
        Current access and successful execution are not established. Use the graph
        profile for investigation; an empty result leaves collection coverage unknown.
        """
        return await execute_tool_async(
            "compromise_assessment",
            compromise_assessment_impl,
            root_node_id=root_node_id,
            scan_id=scan_id,
            assume_control=assume_control,
            snapshot_generation=snapshot_generation,
            affected_node_id=affected_node_id,
            assume_exploitation=assume_exploitation,
            max_relationships=max_relationships,
            max_evidence_age_seconds=max_evidence_age_seconds,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )
