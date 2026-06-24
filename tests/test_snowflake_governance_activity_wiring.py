"""Snowflake governance + activity discovery wiring (end-to-end).

Governance ACCESS_HISTORY → USER ACCESSED DATA_STORE edges; Cortex agent usage →
aggregated AGENT nodes; derived findings → unified findings stream. Activity
timeline → compact summary on the account node (no per-query node explosion).
De-duplicated: grants/role-memberships (object graph) and sensitivity tags (exfil)
are NOT re-emitted here.
"""

from __future__ import annotations

from agent_bom.finding import FindingSource
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import to_json


def _governance_payload() -> dict:
    return {
        "status": "ok",
        "account": "ACCT1",
        "discovered_at": "2026-06-24T00:00:00Z",
        "summary": {"access_records": 3, "agent_usage_records": 2, "findings": 1},
        "access_records": [
            {
                "query_id": "q1",
                "user_name": "ANALYST",
                "role_name": "ANALYST_ROLE",
                "query_start": "2026-06-23T10:00:00Z",
                "object_name": "DB.PUBLIC.CUSTOMERS",
                "object_type": "TABLE",
                "operation": "SELECT",
                "is_write": False,
            },
            # Same (user, object, write) collapses to one edge.
            {
                "query_id": "q2",
                "user_name": "ANALYST",
                "role_name": "ANALYST_ROLE",
                "query_start": "2026-06-23T11:00:00Z",
                "object_name": "DB.PUBLIC.CUSTOMERS",
                "object_type": "TABLE",
                "operation": "SELECT",
                "is_write": False,
            },
            {
                "query_id": "q3",
                "user_name": "ETL_SVC",
                "role_name": "ETL_ROLE",
                "query_start": "2026-06-23T12:00:00Z",
                "object_name": "DB.PUBLIC.PAYMENTS",
                "object_type": "TABLE",
                "operation": "INSERT",
                "is_write": True,
            },
        ],
        "agent_usage": [
            {
                "agent_name": "SUPPORT_AGENT",
                "user_name": "BOT",
                "total_tokens": 100,
                "credits_used": 0.5,
                "tool_calls": 2,
                "model_name": "claude",
                "status": "SUCCESS",
            },
            {
                "agent_name": "SUPPORT_AGENT",
                "user_name": "BOT",
                "total_tokens": 50,
                "credits_used": 0.25,
                "tool_calls": 1,
                "model_name": "claude",
                "status": "SUCCESS",
            },
        ],
        "findings": [
            {
                "category": "access",
                "severity": "high",
                "title": "Write access to sensitive table",
                "description": "ETL_SVC wrote to DB.PUBLIC.PAYMENTS",
                "agent_or_role": "ETL_ROLE",
                "object_name": "DB.PUBLIC.PAYMENTS",
                "details": {"operation": "INSERT"},
            }
        ],
        "warnings": [],
    }


def _activity_payload(num_queries: int = 400) -> dict:
    history = []
    for i in range(num_queries):
        history.append(
            {
                "query_id": f"qh{i}",
                "query_text": "SELECT 1",
                "user_name": f"USER_{i % 5}",
                "role_name": "R",
                "start_time": "2026-06-23T10:00:00Z",
                "execution_status": "SUCCESS",
                "query_type": "SELECT",
                "is_agent_query": i % 50 == 0,
                "agent_pattern": "CORTEX" if i % 50 == 0 else "",
                "execution_time_ms": 12,
            }
        )
    return {
        "status": "ok",
        "account": "ACCT1",
        "discovered_at": "2026-06-24T00:00:00Z",
        "summary": {
            "total_queries": num_queries,
            "agent_queries": sum(1 for q in history if q["is_agent_query"]),
            "observability_events": 0,
            "unique_agents": 0,
            "tool_calls": 0,
        },
        "query_history": history,
        "observability_events": [],
        "warnings": [],
    }


def _build(report: dict):
    g = build_unified_graph_from_report(report)
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    return g, edges


# ── Report field population + JSON serialization ──────────────────────────


def test_report_fields_and_json_serialize() -> None:
    report = AIBOMReport(agents=[])
    report.snowflake_governance_data = _governance_payload()
    report.snowflake_activity_data = _activity_payload()

    out = to_json(report)
    assert out["snowflake_governance"]["account"] == "ACCT1"
    # De-dup: redundant blocks must NOT be present in the stored governance data.
    assert "privilege_grants" not in out["snowflake_governance"]
    assert "data_classifications" not in out["snowflake_governance"]
    assert out["snowflake_activity"]["summary"]["total_queries"] == 400


# ── Graph: ACCESSED edges, no grant/tag duplication ───────────────────────


def test_access_history_produces_accessed_edges_collapsed() -> None:
    g, edges = _build({"snowflake_governance": _governance_payload()})
    accessed = {(e.source, e.target) for e in edges if e.relationship.value == "accessed"}
    assert ("user:snowflake:ANALYST", "data_store:snowflake:DB.PUBLIC.CUSTOMERS") in accessed
    assert ("user:snowflake:ETL_SVC", "data_store:snowflake:DB.PUBLIC.PAYMENTS") in accessed
    # Two identical SELECT records on the same object collapse to one edge.
    analyst_edges = [e for e in edges if e.relationship.value == "accessed" and e.source == "user:snowflake:ANALYST"]
    assert len(analyst_edges) == 1


def test_governance_does_not_emit_grants_or_tags() -> None:
    g, edges = _build({"snowflake_governance": _governance_payload()})
    rels = {e.relationship.value for e in edges}
    # HAS_PERMISSION (grants) and ASSUMES (role memberships) belong to the object
    # graph; sensitivity is the exfil layer. Governance must not re-emit them.
    assert "has_permission" not in rels
    assert "assumes" not in rels


def test_cortex_agent_usage_aggregates_one_node() -> None:
    g, _ = _build({"snowflake_governance": _governance_payload()})
    node = g.nodes.get("agent:snowflake:SUPPORT_AGENT")
    assert node is not None
    assert node.attributes["call_count"] == 2
    assert node.attributes["total_tokens"] == 150
    assert node.attributes["tool_calls"] == 3


# ── Governance findings converge into to_findings() ───────────────────────


def test_governance_findings_reach_to_findings() -> None:
    report = AIBOMReport(agents=[])
    report.snowflake_governance_data = _governance_payload()
    findings = report.to_findings()
    gov = [f for f in findings if f.source == FindingSource.CLOUD_CIS and "governance" in f.title.lower()]
    assert len(gov) == 1
    assert gov[0].severity == "HIGH"


# ── Activity: summary onto account, NO per-query explosion ─────────────────


def test_activity_summary_no_per_query_nodes() -> None:
    g, _ = _build({"snowflake_activity": _activity_payload(400)})
    acct = g.nodes.get("account:snowflake:ACCT1")
    assert acct is not None
    summary = acct.attributes["activity_summary"]
    assert summary["total_queries"] == 400
    assert summary["distinct_users"] == 5
    # 400 queries must not become hundreds of nodes; notable sample is capped.
    assert len(summary["notable_agent_statements"]) <= 25
    assert len(g.nodes) < 50


def test_activity_and_governance_share_one_account_node() -> None:
    report = {"snowflake_governance": _governance_payload(), "snowflake_activity": _activity_payload(120)}
    g, _ = _build(report)
    acct_nodes = [nid for nid in g.nodes if nid.startswith("account:snowflake:")]
    assert acct_nodes == ["account:snowflake:ACCT1"]
    acct = g.nodes["account:snowflake:ACCT1"]
    assert "activity_summary" in acct.attributes
