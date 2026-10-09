"""Snowflake governance and query-activity projection."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from agent_bom.graph.builder_snowflake_lane import _SnowflakeLane
from agent_bom.graph.cloud_context import _add_identity_node, _prepare_cloud_payload
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import merge_edge_evidence
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def _add_snowflake_activity(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Summarize the Snowflake activity timeline onto the account node.

    QUERY_HISTORY can carry a year of rows; exploding them into per-query nodes
    would bury the graph (the data-store-scale lesson). Instead this attaches a
    compact ``activity_summary`` to the account node — total/agent query counts,
    distinct users, and a capped sample of notable agent-pattern statements — and
    creates **no per-query nodes**. Never raises; non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-activity")
    if prepared is None:
        return
    account, data_sources = prepared
    if not account:
        return

    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    query_history = payload.get("query_history") or []

    distinct_users: set[str] = set()
    notable: list[dict[str, str]] = []
    notable_cap = 25
    for q in query_history:
        if not isinstance(q, dict):
            continue
        user = _clean_graph_part(q.get("user_name"))
        if user:
            distinct_users.add(user)
        if q.get("is_agent_query") and len(notable) < notable_cap:
            notable.append(
                {
                    "query_id": _clean_graph_part(q.get("query_id")),
                    "user_name": user,
                    "agent_pattern": _clean_graph_part(q.get("agent_pattern")),
                    "query_type": _clean_graph_part(q.get("query_type")),
                    "start_time": _clean_graph_part(q.get("start_time")),
                }
            )

    activity_summary = {
        "total_queries": int(summary.get("total_queries") or 0),
        "agent_queries": int(summary.get("agent_queries") or 0),
        "observability_events": int(summary.get("observability_events") or 0),
        "unique_agents": int(summary.get("unique_agents") or 0),
        "tool_calls": int(summary.get("tool_calls") or 0),
        "distinct_users": len(distinct_users),
        "notable_agent_statements": notable,
    }

    # Merge onto the account node (add_node unions attributes by id).
    _add_identity_node(
        graph,
        EntityType.ACCOUNT,
        account,
        "snowflake",
        data_sources,
        label=account or "snowflake",
        account_id=account,
        cloud_provider="snowflake",
        source="snowflake-activity",
        activity_summary=activity_summary,
    )


def _snowflake_access_receipt(rec: dict[str, Any], account: str) -> dict[str, Any]:
    receipt: dict[str, Any] = {"source": "snowflake-governance", "account": account}
    for field_name in ("query_id", "user_name", "role_name", "query_start", "object_name", "object_type", "operation", "source_field"):
        receipt[field_name] = _clean_graph_part(rec.get(field_name))
    receipt["is_write"] = rec.get("is_write") if isinstance(rec.get("is_write"), bool) else None
    for field_name in ("columns", "base_objects"):
        values = rec.get(field_name)
        receipt[field_name] = sorted({value for value in values if isinstance(value, str)}) if isinstance(values, list) else []
    return receipt


def _collect_snowflake_access(lane: _SnowflakeLane, records: Any, account: str) -> dict[tuple[str, str], list[dict[str, Any]]]:
    access_records_by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        user_name = _clean_graph_part(rec.get("user_name"))
        object_name = _clean_graph_part(rec.get("object_name"))
        if not user_name or not object_name:
            continue
        access_records_by_pair[(user_name, object_name)].append(_snowflake_access_receipt(rec, account))
        object_node_id = f"data_store:snowflake:{object_name}"
        if object_node_id not in lane.graph.nodes:
            # Thin object node — the object/exfil layers, if also run, own the
            # rich one (same id → merges, no duplicate).
            lane.own(
                UnifiedNode(
                    id=object_node_id,
                    entity_type=EntityType.DATA_STORE,
                    label=f"{_clean_graph_part(rec.get('object_type')) or 'object'}: {object_name}",
                    attributes={
                        "fqn": object_name,
                        "object_type": _clean_graph_part(rec.get("object_type")) or "object",
                        "cloud_provider": "snowflake",
                        "is_data_store": True,
                    },
                    data_sources=lane.data_sources,
                    dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
                )
            )
    return access_records_by_pair


def _add_snowflake_access_edges(lane: _SnowflakeLane, access_records_by_pair: dict[tuple[str, str], list[dict[str, Any]]]) -> None:
    """ACCESS_HISTORY: user ACCESSED data store (collapsed per user+object)."""
    seen_users: set[str] = set()
    for (user_name, object_name), receipts in access_records_by_pair.items():
        evidence: dict[str, Any] = {
            "source": "snowflake-governance",
            "evidence_kind": "historical_access",
            "authorization_state": "not_evaluated",
            "data_impact_state": "unknown",
        }
        # Aggregate once per edge rather than repeatedly merging its growing
        # history. Keep whole records so different queries/roles cannot combine.
        merge_edge_evidence(evidence, {"access_receipts": receipts})
        user_node_id = f"user:snowflake:{user_name}"
        if user_node_id not in seen_users:
            seen_users.add(user_node_id)
            _add_identity_node(
                lane.graph,
                EntityType.USER,
                user_name,
                "snowflake",
                lane.data_sources,
                label=f"user: {user_name}",
                user_name=user_name,
                cloud_provider="snowflake",
                source="snowflake-governance",
            )
        _add_rel_edge(lane.graph, user_node_id, f"data_store:snowflake:{object_name}", RelationshipType.ACCESSED, evidence)


def _aggregate_cortex_agent_usage(records: Any) -> dict[str, dict[str, Any]]:
    agent_aggregate: dict[str, dict[str, Any]] = {}
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        agent_name = _clean_graph_part(rec.get("agent_name"))
        if not agent_name:
            continue
        agg = agent_aggregate.setdefault(
            agent_name,
            {"calls": 0, "total_tokens": 0, "credits_used": 0.0, "tool_calls": 0, "models": set(), "users": set()},
        )
        agg["calls"] += 1
        agg["total_tokens"] += int(rec.get("total_tokens") or 0)
        agg["credits_used"] += float(rec.get("credits_used") or 0.0)
        agg["tool_calls"] += int(rec.get("tool_calls") or 0)
        model = _clean_graph_part(rec.get("model_name"))
        if model:
            agg["models"].add(model)
        user = _clean_graph_part(rec.get("user_name"))
        if user:
            agg["users"].add(user)
    return agent_aggregate


def _add_cortex_agent_nodes(lane: _SnowflakeLane, agent_aggregate: dict[str, dict[str, Any]]) -> None:
    """CORTEX_AGENT_USAGE_HISTORY: one AGENT node per name, aggregated."""
    for agent_name, agg in agent_aggregate.items():
        agent_node_id = f"agent:snowflake:{agent_name}"
        lane.graph.add_node(
            UnifiedNode(
                id=agent_node_id,
                entity_type=EntityType.AGENT,
                label=f"cortex agent: {agent_name}",
                attributes={
                    "agent_name": agent_name,
                    "cloud_provider": "snowflake",
                    "source": "cortex-agent-usage",
                    "call_count": agg["calls"],
                    "total_tokens": agg["total_tokens"],
                    "credits_used": round(agg["credits_used"], 4),
                    "tool_calls": agg["tool_calls"],
                    "models": sorted(agg["models"]),
                    "distinct_users": len(agg["users"]),
                },
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="identity"),
            )
        )
        if lane.account_node_id:
            _add_rel_edge(lane.graph, lane.account_node_id, agent_node_id, RelationshipType.OWNS, {"source": "snowflake-governance"})


def _add_snowflake_governance(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake governance telemetry into the graph (CIEM read-access layer).

    De-duplicated against ``_add_snowflake_object_graph`` (grants + role
    memberships) and ``_add_snowflake_exfil`` (sensitivity tags): only the
    non-redundant value is wired here.

    - **ACCESS_HISTORY** → for each ``(user, object)`` pair, a ``USER`` node
      ``ACCESSED`` the object's ``DATA_STORE`` node. The data-store id matches the
      scheme the object/exfil layers emit (``data_store:snowflake:{fqn}``), so the
      edge lands on the existing object node rather than a duplicate. Records are
      collapsed per ``(user, object)`` with distinct query/action/role receipts.
      Historical observations do not establish current permission or row impact.
    - **CORTEX_AGENT_USAGE_HISTORY** → one ``AGENT`` node per distinct agent name,
      ``OWNS``-attached to the account, carrying aggregate telemetry (calls, tokens,
      credits) as attributes — not one node per call.
    - **Derived findings** are converged into the unified findings stream by
      ``GraphIndices.to_findings`` (``_snowflake_governance_findings``), not into
      nodes, so ``--fail-on-severity`` sees them.

    Never raises; a missing/empty/non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-governance")
    if prepared is None:
        return
    account, data_sources = prepared
    lane = _SnowflakeLane(graph, account, data_sources, "snowflake-governance")
    access = _collect_snowflake_access(lane, payload.get("access_records", []), account)
    _add_snowflake_access_edges(lane, access)
    _add_cortex_agent_nodes(lane, _aggregate_cortex_agent_usage(payload.get("agent_usage", [])))
