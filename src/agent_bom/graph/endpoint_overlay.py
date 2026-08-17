"""Privacy-safe endpoint inventory projection onto UnifiedGraph."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.api.fleet_store import endpoint_summary_from_inventory
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType


def apply_endpoint_inventory_overlay(graph: UnifiedGraph, report: Mapping[str, Any]) -> int:
    """Add one bounded workstation root; raw process/service rows stay off graph."""

    inventory = report.get("endpoint_inventory")
    endpoint_id = str(report.get("source_id") or "").strip()
    if not endpoint_id or not isinstance(inventory, dict):
        return 0
    summary = endpoint_summary_from_inventory(
        endpoint_id=endpoint_id,
        tenant_id=graph.tenant_id,
        inventory=inventory,
        scan_id=graph.scan_id,
        observed_at=str(report.get("observed_at") or report.get("scan_timestamp") or ""),
    )
    graph.add_node(
        UnifiedNode(
            id=f"endpoint:{endpoint_id}",
            entity_type=EntityType.FLEET,
            label=endpoint_id,
            attributes={
                "endpoint_id": summary.endpoint_id,
                "platform": summary.platform,
                "counts": summary.counts,
                "collector_status": summary.collector_status,
                "collector_messages": summary.collector_messages,
                "privacy": summary.privacy,
                "completeness": summary.completeness,
                "last_scan_id": summary.last_scan_id,
            },
            dimensions=NodeDimensions(surface="endpoint", environment="workstation"),
            data_sources=["endpoint_inventory"],
        )
    )
    return 1
