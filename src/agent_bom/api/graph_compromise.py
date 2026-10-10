"""Generation-pinned compromise reads shared by HTTP and MCP surfaces."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from pydantic import Field, field_validator

from agent_bom.api.graph_generation import pin_generation, verify_generation
from agent_bom.graph.compromise import CompromiseAssessment, CompromiseRequest, assess_direct_compromise


class GraphCompromiseRequest(CompromiseRequest):
    scan_id: str = Field(min_length=1, max_length=1024, pattern=r"^[^\x00]+$")
    snapshot_generation: str | None = Field(default=None, min_length=1, max_length=256, pattern=r"^[^\x00]+$")

    @field_validator("scan_id", "root_node_id", "affected_node_id")
    @classmethod
    def valid_identity(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or "\x00" in value):
            raise ValueError("identity must be nonblank and contain no NUL")
        return value


class GraphCompromiseResponse(CompromiseAssessment):
    snapshot_generation: str


def assess_snapshot(store: Any, body: GraphCompromiseRequest, *, tenant_id: str) -> GraphCompromiseResponse:
    """Reject partial/replaced snapshots; never enrich them from live evidence."""
    identity = pin_generation(store, tenant=tenant_id, scan_id=body.scan_id, generation=body.snapshot_generation, offset=0)
    if not identity[1]:
        raise HTTPException(404, "Graph snapshot not found.")
    roots = [body.root_node_id]
    if body.affected_node_id and body.affected_node_id not in roots:
        roots.append(body.affected_node_id)
    graph, _, truncated = store.traverse_subgraph(
        tenant_id=tenant_id,
        scan_id=identity[0],
        roots=roots,
        direction="forward",
        max_depth=1,
        max_nodes=1024,
        max_edges=4096,
        deadline_monotonic=time.monotonic() + 2.5,
        traversable_only=False,
    )
    if graph.tenant_id != tenant_id or graph.scan_id != identity[0]:
        raise HTTPException(409, "Graph snapshot scope changed; restart the assessment.")
    if truncated or graph.completeness.truncated:
        raise HTTPException(413, "Snapshot exceeds the assessment budget; select a smaller complete snapshot.")
    if body.root_node_id not in graph.nodes:
        raise HTTPException(404, "Compromise root not found in this snapshot.")
    request = CompromiseRequest.model_validate(body.model_dump(exclude={"scan_id", "snapshot_generation"}))
    try:
        result = assess_direct_compromise(graph, request, tenant_id=tenant_id, at=datetime.now(timezone.utc))
    except ValueError as exc:
        raise HTTPException(422, "Invalid affected-component or exploitation assumption for this root.") from exc
    verify_generation(store, tenant=tenant_id, identity=identity, has_rows=True)
    return GraphCompromiseResponse(**result.model_dump(), snapshot_generation=identity[1])
