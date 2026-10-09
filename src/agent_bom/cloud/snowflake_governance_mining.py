"""Snowflake governance and activity mining from ACCOUNT_USAGE views."""

from __future__ import annotations

import logging
import re
from typing import Any

from agent_bom.governance import (
    ActivityTimeline,
    AgentUsageRecord,
    DataClassification,
    ObservabilityEvent,
    PrivilegeGrant,
    QueryHistoryRecord,
)
from agent_bom.security import sanitize_error

from .snowflake_common import _coerce_snowflake_days, _env_or_value, _parse_json_object, _record_snowflake_inventory_failure, _sf

# Log under the façade's logger so existing log routing and filters keep applying.
logger = logging.getLogger("agent_bom.cloud.snowflake")


def _mine_grants_to_roles(
    conn: Any,
) -> tuple[list[PrivilegeGrant], list[str]]:
    """Mine SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES for privilege grants."""
    grants: list[PrivilegeGrant] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    elevated_privs = {
        "OWNERSHIP",
        "ALL",
        "ALL PRIVILEGES",
        "CREATE ROLE",
        "MANAGE GRANTS",
        "CREATE USER",
        "EXECUTE TASK",
        "EXECUTE MANAGED TASK",
        "MONITOR",
    }

    try:
        cursor.execute(
            "SELECT grantee_name, privilege, granted_on, name, "
            "       granted_by, grant_option "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES "
            "WHERE deleted_on IS NULL "
            "ORDER BY grantee_name, granted_on "
            "LIMIT 5000"
        )
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))
            privilege = str(row_dict.get("privilege", ""))

            grants.append(
                PrivilegeGrant(
                    grantee=str(row_dict.get("grantee_name", "")),
                    grantee_type="ROLE",
                    privilege=privilege,
                    granted_on=str(row_dict.get("granted_on", "")),
                    object_name=str(row_dict.get("name", "")),
                    granted_by=str(row_dict.get("granted_by", "")),
                    grant_option=bool(row_dict.get("grant_option", False)),
                    is_elevated=privilege.upper() in elevated_privs,
                )
            )

    except Exception as exc:
        _record_snowflake_inventory_failure(
            exc=exc,
            resource_type="GRANTS_TO_ROLES",
            inventory_key="grants_to_roles",
            warnings=warnings,
        )

    finally:
        cursor.close()

    return grants, warnings


def _mine_tag_references(
    conn: Any,
) -> tuple[list[DataClassification], list[str]]:
    """Mine SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES for data classification tags.

    Identifies PII, PHI, financial, and confidential data labels.
    """
    tags: list[DataClassification] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT tag_name, tag_value, object_database, object_schema, "
            "       object_name, column_name, domain "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES "
            "WHERE tag_name ILIKE ANY ('%PII%', '%PHI%', '%SENSITIVE%', "
            "       '%CONFIDENTIAL%', '%FINANCIAL%', '%CLASSIFICATION%', "
            "       '%PRIVACY%', '%SECURITY%', '%SEMANTIC_CATEGORY%') "
            "ORDER BY object_name "
            "LIMIT 2000"
        )
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))
            obj_db = str(row_dict.get("object_database", ""))
            obj_schema = str(row_dict.get("object_schema", ""))
            obj_name = str(row_dict.get("object_name", ""))
            fqn = f"{obj_db}.{obj_schema}.{obj_name}" if obj_db else obj_name

            tags.append(
                DataClassification(
                    object_name=fqn,
                    object_type=str(row_dict.get("domain", "TABLE")),
                    column_name=row_dict.get("column_name"),
                    tag_name=str(row_dict.get("tag_name", "")),
                    tag_value=str(row_dict.get("tag_value", "")),
                    tag_database=obj_db,
                    tag_schema=obj_schema,
                )
            )

    except Exception as exc:
        msg = str(exc)
        if "tag_references" in msg.lower():
            warnings.append("TAG_REFERENCES not accessible. Data classification analysis skipped.")
        else:
            warnings.append(f"Could not query TAG_REFERENCES: {sanitize_error(exc)}")

    finally:
        cursor.close()

    return tags, warnings


def _mine_cortex_agent_usage(
    conn: Any,
    days: int,
) -> tuple[list[AgentUsageRecord], list[str]]:
    """Mine SNOWFLAKE.ACCOUNT_USAGE.CORTEX_AGENT_USAGE_HISTORY.

    GA since February 25, 2026. Provides per-call agent telemetry including
    token counts, credit usage, model, and tool call counts.
    """
    records: list[AgentUsageRecord] = []
    warnings: list[str] = []
    cursor = conn.cursor()
    days = _coerce_snowflake_days(days)

    try:
        # Real CORTEX_AGENT_USAGE_HISTORY schema: agent/database/schema are
        # AGENT_*_NAME columns, there is no ROLE_NAME, TOKENS is a scalar total,
        # TOKEN_CREDITS holds the credit cost, and per-model/input/output detail
        # lives in METADATA (OBJECT) / TOKENS_GRANULAR (ARRAY).
        cursor.execute(
            "SELECT agent_name, agent_database_name, agent_schema_name, "
            "       user_name, start_time, end_time, request_id, "
            "       tokens, token_credits, metadata "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.CORTEX_AGENT_USAGE_HISTORY "
            f"WHERE start_time >= DATEADD(day, -{days}, CURRENT_TIMESTAMP()) "  # nosec B608 — days is int
            "ORDER BY start_time DESC "
            "LIMIT 2000"
        )
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))
            metadata = _parse_json_object(row_dict.get("metadata"))
            total_tokens = int(row_dict.get("tokens", 0) or 0)
            input_tokens = int(metadata.get("input_tokens", metadata.get("inputTokens", 0)) or 0)
            output_tokens = int(metadata.get("output_tokens", metadata.get("outputTokens", 0)) or 0)

            records.append(
                AgentUsageRecord(
                    agent_name=str(row_dict.get("agent_name", "")),
                    database_name=str(row_dict.get("agent_database_name", "")),
                    schema_name=str(row_dict.get("agent_schema_name", "")),
                    user_name=str(row_dict.get("user_name", "")),
                    role_name="",
                    start_time=str(row_dict.get("start_time", "")),
                    end_time=str(row_dict.get("end_time", "")),
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    total_tokens=total_tokens,
                    credits_used=float(row_dict.get("token_credits", 0.0) or 0.0),
                    model_name=str(metadata.get("model_name", metadata.get("model", "")) or ""),
                    tool_calls=int(metadata.get("tool_calls", metadata.get("toolCalls", 0)) or 0),
                    status=str(metadata.get("status", "") or ""),
                )
            )

    except Exception as exc:
        msg = str(exc)
        if "cortex_agent_usage" in msg.lower() or "does not exist" in msg.lower():
            warnings.append("CORTEX_AGENT_USAGE_HISTORY not available. Requires Cortex Agents (GA Feb 2026). Skipping agent telemetry.")
        else:
            warnings.append(f"Could not query CORTEX_AGENT_USAGE_HISTORY: {sanitize_error(exc)}")

    finally:
        cursor.close()

    return records, warnings


# ---------------------------------------------------------------------------
# Activity Timeline — QUERY_HISTORY 365-day + AI_OBSERVABILITY_EVENTS
# ---------------------------------------------------------------------------

# Patterns in query_text that indicate agent/AI activity
_AGENT_QUERY_PATTERNS: list[tuple[str, str]] = [
    (r"\bCREATE\s+(OR\s+REPLACE\s+)?AGENT\b", "CREATE AGENT"),
    (r"\bCREATE\s+(OR\s+REPLACE\s+)?MCP\s+SERVER\b", "CREATE MCP SERVER"),
    (r"\bALTER\s+AGENT\b", "ALTER AGENT"),
    (r"\bALTER\s+MCP\s+SERVER\b", "ALTER MCP SERVER"),
    (r"\bDESCRIBE\s+AGENT\b", "DESCRIBE AGENT"),
    (r"\bDESCRIBE\s+MCP\s+SERVER\b", "DESCRIBE MCP SERVER"),
    (r"\bSHOW\s+AGENTS\b", "SHOW AGENTS"),
    (r"\bSHOW\s+MCP\s+SERVERS\b", "SHOW MCP SERVERS"),
    (r"\bCORTEX\b", "CORTEX"),
    (r"\bSNOWFLAKE\.CORTEX\b", "CORTEX FUNCTION"),
    (r"\bCORTEX_SEARCH\b", "CORTEX SEARCH"),
    (r"\bSYSTEM\$EXECUTE_SQL\b", "SYSTEM_EXECUTE_SQL"),
    (r"\bSNOWFLAKE\.ML\b", "ML FUNCTION"),
]

_COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), label) for p, label in _AGENT_QUERY_PATTERNS]


def discover_activity(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
    days: int = 30,
) -> ActivityTimeline:
    """Reconstruct agent activity timeline from Snowflake telemetry.

    Mines QUERY_HISTORY (up to 365 days via ACCOUNT_USAGE) for agent-related
    queries and AI_OBSERVABILITY_EVENTS for full execution traces.

    Args:
        account: Snowflake account identifier.
        user: Snowflake username.
        authenticator: Auth method.
        database: Default database context.
        schema: Default schema context.
        days: Look-back window (max 365 for QUERY_HISTORY via ACCOUNT_USAGE).

    Returns:
        ActivityTimeline with query history and observability events.
    """
    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    resolved_user = _env_or_value(user, "SNOWFLAKE_USER")
    timeline = ActivityTimeline(account=resolved_account)
    days = _coerce_snowflake_days(days, max_days=365)

    if not resolved_account:
        timeline.warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return timeline

    try:
        import snowflake.connector
        from snowflake.connector.errors import DatabaseError  # noqa: F401
    except ImportError:
        from .base import CloudDiscoveryError

        raise CloudDiscoveryError("snowflake-connector-python is required. Install with: pip install 'agent-bom[snowflake]'")

    conn_kwargs: dict[str, Any] = {
        "account": resolved_account,
        "user": resolved_user,
    }
    if authenticator:
        conn_kwargs["authenticator"] = authenticator
    if database:
        conn_kwargs["database"] = database
    if schema:
        conn_kwargs["schema"] = schema

    _sf()._resolve_snowflake_auth(conn_kwargs, authenticator)

    borrowed = _sf()._active_borrowed_connection()
    if borrowed is not None:
        conn = borrowed
    else:
        try:
            conn = snowflake.connector.connect(**conn_kwargs)
        except (DatabaseError, Exception) as exc:
            timeline.warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
            return timeline

    try:
        # 1. QUERY_HISTORY from ACCOUNT_USAGE (365-day lookback)
        queries, qh_warns = _mine_query_history_365(conn, days)
        timeline.query_history = queries
        timeline.warnings.extend(qh_warns)

        # 2. AI_OBSERVABILITY_EVENTS
        events, ev_warns = _mine_observability_events(conn, days)
        timeline.observability_events = events
        timeline.warnings.extend(ev_warns)

    finally:
        conn.close()

    return timeline


def _mine_query_history_365(
    conn: Any,
    days: int,
) -> tuple[list[QueryHistoryRecord], list[str]]:
    """Mine SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY for agent-related queries.

    ACCOUNT_USAGE.QUERY_HISTORY provides up to 365 days of history
    (vs INFORMATION_SCHEMA which only has 7 days). Filters for queries
    containing agent/MCP/Cortex keywords.
    """
    records: list[QueryHistoryRecord] = []
    warnings: list[str] = []
    cursor = conn.cursor()
    days = _coerce_snowflake_days(days, max_days=365)

    try:
        cursor.execute(
            "SELECT query_id, query_text, user_name, role_name, "
            "       start_time, end_time, execution_status, "
            "       warehouse_name, database_name, schema_name, "
            "       query_type, rows_produced, bytes_scanned, "
            "       total_elapsed_time "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
            f"WHERE start_time >= DATEADD(day, -{min(days, 365)}, CURRENT_TIMESTAMP()) "  # nosec B608 — days is int
            "  AND (query_text ILIKE '%AGENT%' "
            "       OR query_text ILIKE '%MCP%SERVER%' "
            "       OR query_text ILIKE '%CORTEX%' "
            "       OR query_text ILIKE '%SNOWFLAKE.ML%' "
            "       OR query_text ILIKE '%EXECUTE_SQL%') "
            "ORDER BY start_time DESC "
            "LIMIT 2000"
        )
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))
            query_text = str(row_dict.get("query_text", ""))

            # Classify the query
            is_agent, pattern = _classify_agent_query(query_text)

            records.append(
                QueryHistoryRecord(
                    query_id=str(row_dict.get("query_id", "")),
                    query_text=query_text,
                    user_name=str(row_dict.get("user_name", "")),
                    role_name=str(row_dict.get("role_name", "")),
                    start_time=str(row_dict.get("start_time", "")),
                    end_time=str(row_dict.get("end_time", "")),
                    execution_status=str(row_dict.get("execution_status", "")),
                    warehouse_name=str(row_dict.get("warehouse_name", "")),
                    database_name=str(row_dict.get("database_name", "")),
                    schema_name=str(row_dict.get("schema_name", "")),
                    query_type=str(row_dict.get("query_type", "")),
                    rows_produced=int(row_dict.get("rows_produced", 0) or 0),
                    bytes_scanned=int(row_dict.get("bytes_scanned", 0) or 0),
                    execution_time_ms=int(row_dict.get("total_elapsed_time", 0) or 0),
                    is_agent_query=is_agent,
                    agent_pattern=pattern,
                )
            )

    except Exception as exc:
        msg = str(exc)
        if "query_history" in msg.lower():
            warnings.append(
                "ACCOUNT_USAGE.QUERY_HISTORY not accessible. Requires ACCOUNTADMIN or IMPORTED PRIVILEGES on SNOWFLAKE database."
            )
        else:
            warnings.append(f"Could not query QUERY_HISTORY: {sanitize_error(exc)}")

    finally:
        cursor.close()

    return records, warnings


def _mine_observability_events(
    conn: Any,
    days: int,
) -> tuple[list[ObservabilityEvent], list[str]]:
    """Mine SNOWFLAKE.LOCAL.AI_OBSERVABILITY_EVENTS for agent execution traces.

    Provides full execution traces including tool calls, LLM inferences,
    and user feedback. Available when AI observability is enabled.
    """
    events: list[ObservabilityEvent] = []
    warnings: list[str] = []
    cursor = conn.cursor()
    days = _coerce_snowflake_days(days, max_days=365)

    try:
        cursor.execute(
            "SELECT event_id, event_type, agent_name, timestamp, "
            "       duration_ms, status, model_name, "
            "       input_tokens, output_tokens, "
            "       tool_name, tool_input, tool_output_summary, "
            "       user_feedback, trace_id, parent_event_id "
            "FROM TABLE(SNOWFLAKE.LOCAL.AI_OBSERVABILITY_EVENTS("
            f"  INTERVAL => '{min(days, 365)} days'"  # nosec B608 — days is int
            ")) "
            "ORDER BY timestamp DESC "
            "LIMIT 5000"
        )
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))
            events.append(
                ObservabilityEvent(
                    event_id=str(row_dict.get("event_id", "")),
                    event_type=str(row_dict.get("event_type", "")),
                    agent_name=str(row_dict.get("agent_name", "")),
                    timestamp=str(row_dict.get("timestamp", "")),
                    duration_ms=int(row_dict.get("duration_ms", 0) or 0),
                    status=str(row_dict.get("status", "")),
                    model_name=str(row_dict.get("model_name", "")),
                    input_tokens=int(row_dict.get("input_tokens", 0) or 0),
                    output_tokens=int(row_dict.get("output_tokens", 0) or 0),
                    tool_name=str(row_dict.get("tool_name", "")),
                    tool_input=str(row_dict.get("tool_input", ""))[:500],
                    tool_output_summary=str(row_dict.get("tool_output_summary", ""))[:500],
                    user_feedback=str(row_dict.get("user_feedback", "")),
                    trace_id=str(row_dict.get("trace_id", "")),
                    parent_event_id=str(row_dict.get("parent_event_id", "")),
                )
            )

    except Exception as exc:
        msg = str(exc)
        if "ai_observability" in msg.lower() or "does not exist" in msg.lower():
            warnings.append("AI_OBSERVABILITY_EVENTS not available. Enable AI observability in Snowflake to capture agent traces.")
        else:
            warnings.append(f"Could not query AI_OBSERVABILITY_EVENTS: {sanitize_error(exc)}")

    finally:
        cursor.close()

    return events, warnings


def _classify_agent_query(query_text: str) -> tuple[bool, str]:
    """Classify a query as agent-related based on pattern matching.

    Returns (is_agent_query, matched_pattern_label).
    """
    for pattern, label in _COMPILED_PATTERNS:
        if pattern.search(query_text):
            return True, label
    return False, ""
