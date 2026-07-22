"""CI/CD graph overlay — emit ``ci_job`` nodes from GitHub Actions evidence.

When a scan already carries agents with ``source="github-actions"`` (from
``agent_bom.github_actions.scan_github_actions``), this overlay materialises
reserved CI vocabulary instead of leaving workflow topology only as synthetic
agent/server nodes:

- ``CI_JOB`` per workflow (stable id ``ci_job:<workflow-stem>``)
- ``CONFIGURES`` from matching ``CONFIG_FILE`` / agent ``config_path`` when present
- ``RUNS`` from the CI job to tool nodes already linked under the GHA server

Complete no-op when the report has no github-actions agents. Idempotent.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, GraphSemanticLayer, RelationshipType

_OVERLAY_SOURCE = "ci_graph_overlay"
_GHA_SOURCE = "github-actions"


def _norm_path(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _ci_job_id(workflow_stem: str) -> str:
    return f"ci_job:{workflow_stem}"


def apply_ci_graph_overlay(
    graph: UnifiedGraph,
    report_json: dict[str, Any],
    now: datetime,
) -> dict[str, int]:
    """Emit CI_JOB / RUNS / CONFIGURES from github-actions scan evidence."""
    counts = {"ci_jobs": 0, "runs_edges": 0, "configures_edges": 0}
    agents = report_json.get("agents") if isinstance(report_json, dict) else None
    if not isinstance(agents, list):
        return counts

    gha_agents = [
        agent
        for agent in agents
        if isinstance(agent, dict) and str(agent.get("source") or "") == _GHA_SOURCE
    ]
    if not gha_agents:
        return counts

    now_iso = now.isoformat()
    config_by_path: dict[str, str] = {}
    for node in graph.nodes.values():
        if node.entity_type not in {EntityType.CONFIG_FILE, EntityType.SOURCE_FILE}:
            continue
        path = _norm_path((node.attributes or {}).get("path") or node.label)
        if path:
            config_by_path[path] = node.id

    tool_ids_by_label = {
        node.label: node.id
        for node in graph.nodes.values()
        if node.entity_type == EntityType.TOOL
    }

    for agent in sorted(gha_agents, key=lambda item: str(item.get("name") or "")):
        name = str(agent.get("name") or "")
        stem = name.removeprefix("gha:") if name.startswith("gha:") else name
        if not stem:
            continue
        job_id = _ci_job_id(stem)
        config_path = _norm_path(agent.get("config_path") or "")
        if job_id not in graph.nodes:
            counts["ci_jobs"] += 1
        graph.add_node(
            UnifiedNode(
                id=job_id,
                entity_type=EntityType.CI_JOB,
                label=stem,
                first_seen=now_iso,
                last_seen=now_iso,
                attributes={
                    "workflow": stem,
                    "config_path": config_path,
                    "agent_name": name,
                    "evidence_tier": "static_scan",
                    "source": _GHA_SOURCE,
                },
                data_sources=[_OVERLAY_SOURCE, _GHA_SOURCE],
                dimensions=NodeDimensions(surface=GraphSemanticLayer.CI.value),
            )
        )

        if config_path and config_path in config_by_path:
            graph.add_edge(
                UnifiedEdge(
                    source=config_by_path[config_path],
                    target=job_id,
                    relationship=RelationshipType.CONFIGURES,
                    evidence={"source": _OVERLAY_SOURCE, "config_path": config_path},
                )
            )
            counts["configures_edges"] += 1

        servers = agent.get("mcp_servers") if isinstance(agent.get("mcp_servers"), list) else []
        for server in servers:
            if not isinstance(server, dict):
                continue
            tools = server.get("tools") if isinstance(server.get("tools"), list) else []
            for tool in tools:
                tool_name = ""
                if isinstance(tool, dict):
                    tool_name = str(tool.get("name") or "")
                elif isinstance(tool, str):
                    tool_name = tool
                tool_id = tool_ids_by_label.get(tool_name)
                if not tool_id:
                    continue
                graph.add_edge(
                    UnifiedEdge(
                        source=job_id,
                        target=tool_id,
                        relationship=RelationshipType.RUNS,
                        evidence={"source": _OVERLAY_SOURCE, "tool": tool_name},
                    )
                )
                counts["runs_edges"] += 1

    return counts
