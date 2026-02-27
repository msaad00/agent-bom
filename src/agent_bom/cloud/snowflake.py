"""Snowflake cloud discovery — Cortex agents, MCP servers, Snowpark packages, governance.

Requires ``snowflake-connector-python``.  Install with::

    pip install 'agent-bom[snowflake]'

Authentication uses standard Snowflake connector auth (env vars SNOWFLAKE_ACCOUNT,
SNOWFLAKE_USER, SNOWFLAKE_PASSWORD, or external browser / key pair / SSO).
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from agent_bom.governance import (
    AccessRecord,
    ActivityTimeline,
    AgentUsageRecord,
    DataClassification,
    GovernanceCategory,
    GovernanceFinding,
    GovernanceReport,
    GovernanceSeverity,
    ObservabilityEvent,
    PrivilegeGrant,
    QueryHistoryRecord,
)
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


def discover(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover Cortex agents, MCP servers, and Snowpark packages from Snowflake.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``snowflake-connector-python`` is not installed.
    """
    try:
        import snowflake.connector  # noqa: F811
        from snowflake.connector.errors import DatabaseError  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake discovery. Install with: pip install 'agent-bom[snowflake]'"
        )

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_account = account or os.environ.get("SNOWFLAKE_ACCOUNT", "")
    resolved_user = user or os.environ.get("SNOWFLAKE_USER", "")

    if not resolved_account:
        warnings.append("SNOWFLAKE_ACCOUNT not set. Provide --snowflake-account or set the SNOWFLAKE_ACCOUNT env var.")
        return agents, warnings

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

    # Try password from env if no authenticator specified
    if not authenticator:
        password = os.environ.get("SNOWFLAKE_PASSWORD", "")
        if password:
            conn_kwargs["password"] = password
        else:
            conn_kwargs["authenticator"] = "externalbrowser"

    try:
        conn = snowflake.connector.connect(**conn_kwargs)
    except (DatabaseError, Exception) as exc:
        warnings.append(f"Could not connect to Snowflake: {exc}")
        return agents, warnings

    try:
        # ── Cortex Search Services ────────────────────────────────────────
        cortex_agents, cortex_warns = _discover_cortex_services(conn, resolved_account, database, schema)
        agents.extend(cortex_agents)
        warnings.extend(cortex_warns)

        # ── Cortex Agents (v2025 Agent framework) ─────────────────────────
        cortex_agent_list, ca_warns = _discover_cortex_agents(conn, resolved_account)
        agents.extend(cortex_agent_list)
        warnings.extend(ca_warns)

        # ── Snowflake MCP Servers (GA Nov 2025) ───────────────────────────
        mcp_agents, mcp_warns = _discover_mcp_servers(conn, resolved_account)
        agents.extend(mcp_agents)
        warnings.extend(mcp_warns)

        # ── Query History audit (supplementary) ───────────────────────────
        qh_agents, qh_warns = _discover_from_query_history(conn, resolved_account)
        agents.extend(qh_agents)
        warnings.extend(qh_warns)

        # ── Custom Tools (functions & procedures) ─────────────────────────
        custom_tools, ct_warns = _discover_custom_tools(conn, resolved_account)
        warnings.extend(ct_warns)
        # Attach to cortex agents if any, otherwise create a standalone agent
        if custom_tools and cortex_agent_list:
            for a in cortex_agent_list:
                for srv in a.mcp_servers:
                    srv.tools.extend(custom_tools)
        elif custom_tools:
            tool_server = MCPServer(
                name="snowflake-custom-tools",
                transport=TransportType.UNKNOWN,
                tools=custom_tools,
            )
            agents.append(
                Agent(
                    name=f"snowflake-tools:{resolved_account}",
                    agent_type=AgentType.CUSTOM,
                    config_path=f"snowflake://{resolved_account}/custom-tools",
                    source="snowflake-tools",
                    mcp_servers=[tool_server],
                )
            )

        # ── Snowpark packages ─────────────────────────────────────────────
        snowpark_pkgs, sp_warns = _discover_snowpark_packages(conn, resolved_account)
        warnings.extend(sp_warns)

        # If we found Snowpark packages but no Cortex agents, create a generic agent
        all_cortex = cortex_agents + cortex_agent_list
        if snowpark_pkgs and not all_cortex:
            server = MCPServer(
                name="snowpark-packages",
                transport=TransportType.UNKNOWN,
                packages=snowpark_pkgs,
            )
            agent = Agent(
                name=f"snowflake:{resolved_account}",
                agent_type=AgentType.CUSTOM,
                config_path=f"snowflake://{resolved_account}",
                source="snowflake",
                mcp_servers=[server],
            )
            agents.append(agent)

        # ── Streamlit apps ────────────────────────────────────────────────
        streamlit_agents, st_warns = _discover_streamlit_apps(conn, resolved_account)
        agents.extend(streamlit_agents)
        warnings.extend(st_warns)

    finally:
        conn.close()

    return agents, warnings


def _discover_cortex_services(
    conn: Any,
    account: str,
    database: str | None,
    schema: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover Cortex Search Services and their configurations."""
    agents: list[Agent] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute("SHOW CORTEX SEARCH SERVICES")
        rows = cursor.fetchall()
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in rows:
            row_dict = dict(zip(columns, row)) if columns else {}
            service_name = row_dict.get("name", str(row[0]) if row else "unknown")
            svc_database = row_dict.get("database_name", database or "")
            svc_schema = row_dict.get("schema_name", schema or "")

            config_path = f"snowflake://{account}/{svc_database}/{svc_schema}/{service_name}"

            tools = [
                MCPTool(name="semantic_search", description="Search indexed documents"),
                MCPTool(name="document_retrieve", description="Retrieve document by ID"),
            ]

            server = MCPServer(
                name=f"cortex-search:{service_name}",
                transport=TransportType.STREAMABLE_HTTP,
                url=f"https://{account}.snowflakecomputing.com/cortex/search/{service_name}",
                tools=tools,
            )

            agent = Agent(
                name=f"cortex:{service_name}",
                agent_type=AgentType.CUSTOM,
                config_path=config_path,
                source="snowflake-cortex",
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        # Cortex Search Services may not be available in all accounts
        warnings.append(f"Could not list Cortex Search Services: {exc}")

    finally:
        cursor.close()

    return agents, warnings


def _discover_snowpark_packages(
    conn: Any,
    account: str,
) -> tuple[list[Package], list[str]]:
    """Query INFORMATION_SCHEMA.PACKAGES for installed Snowpark Python packages."""
    packages: list[Package] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT PACKAGE_NAME, VERSION FROM INFORMATION_SCHEMA.PACKAGES WHERE LANGUAGE = 'python' ORDER BY PACKAGE_NAME")
        seen: set[str] = set()
        for row in cursor.fetchall():
            name = str(row[0])
            version = str(row[1])
            if name.lower() not in seen:
                seen.add(name.lower())
                packages.append(Package(name=name, version=version, ecosystem="pypi"))

    except Exception as exc:
        # INFORMATION_SCHEMA.PACKAGES may not exist or may not be accessible
        warnings.append(f"Could not query Snowpark packages: {exc}")

    finally:
        cursor.close()

    return packages, warnings


def _discover_streamlit_apps(
    conn: Any,
    account: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Streamlit apps deployed in Snowflake."""
    agents: list[Agent] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute("SHOW STREAMLIT IN ACCOUNT")
        rows = cursor.fetchall()
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in rows:
            row_dict = dict(zip(columns, row)) if columns else {}
            app_name = row_dict.get("name", str(row[0]) if row else "unknown")
            app_db = row_dict.get("database_name", "")
            app_schema = row_dict.get("schema_name", "")

            server = MCPServer(
                name=f"streamlit:{app_name}",
                transport=TransportType.STREAMABLE_HTTP,
                url=f"https://{account}.snowflakecomputing.com/streamlit/{app_name}",
            )
            agent = Agent(
                name=f"streamlit:{app_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"snowflake://{account}/{app_db}/{app_schema}/streamlit/{app_name}",
                source="snowflake-streamlit",
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Streamlit apps: {exc}")

    finally:
        cursor.close()

    return agents, warnings


# ---------------------------------------------------------------------------
# Deep discovery — Cortex Agents, MCP Servers, Query History, Custom Tools
# ---------------------------------------------------------------------------


def _discover_cortex_agents(
    conn: Any,
    account: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Cortex Agents via SHOW AGENTS IN ACCOUNT.

    The Cortex Agent framework (v2025) is distinct from Cortex Search Services.
    These are agentic orchestration systems combining semantic models, search
    services, and custom tools.
    """
    agents: list[Agent] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute("SHOW AGENTS IN ACCOUNT")
        rows = cursor.fetchall()
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in rows:
            row_dict = dict(zip(columns, row)) if columns else {}
            agent_name = row_dict.get("name", str(row[0]) if row else "unknown")
            db_name = row_dict.get("database_name", "")
            schema_name = row_dict.get("schema_name", "")

            # Parse profile JSON if available (contains display_name)
            profile_str = row_dict.get("profile", "")
            display_name = agent_name
            if profile_str:
                try:
                    profile = json.loads(profile_str)
                    display_name = profile.get("display_name", agent_name)
                except (json.JSONDecodeError, TypeError):
                    pass

            config_path = f"snowflake://{account}/{db_name}/{schema_name}/{agent_name}"

            server = MCPServer(
                name=f"cortex-agent:{agent_name}",
                transport=TransportType.STREAMABLE_HTTP,
                url=f"https://{account}.snowflakecomputing.com/api/v2/cortex/agent/{agent_name}",
            )

            agent = Agent(
                name=f"cortex-agent:{display_name}",
                agent_type=AgentType.CUSTOM,
                config_path=config_path,
                source="snowflake-cortex-agent",
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Cortex Agents: {exc}")

    finally:
        cursor.close()

    return agents, warnings


def _discover_mcp_servers(
    conn: Any,
    account: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Snowflake-native MCP Servers via SHOW MCP SERVERS.

    GA since November 2025. Follows up with DESCRIBE MCP SERVER to get
    tool specifications from the YAML definition.
    """
    agents: list[Agent] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute("SHOW MCP SERVERS IN ACCOUNT")
        rows = cursor.fetchall()
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in rows:
            row_dict = dict(zip(columns, row)) if columns else {}
            server_name = row_dict.get("name", str(row[0]) if row else "unknown")
            db_name = row_dict.get("database_name", "")
            schema_name = row_dict.get("schema_name", "")

            tools = _describe_mcp_server_tools(conn, server_name, db_name, schema_name, warnings)

            fqn = f"{db_name}.{schema_name}.{server_name}" if db_name else server_name
            config_path = f"snowflake://{account}/{db_name}/{schema_name}/mcp/{server_name}"

            mcp_server = MCPServer(
                name=f"snowflake-mcp:{server_name}",
                transport=TransportType.STREAMABLE_HTTP,
                url=f"https://{account}.snowflakecomputing.com/api/v2/mcp/{fqn}",
                tools=tools,
            )

            agent = Agent(
                name=f"mcp-server:{server_name}",
                agent_type=AgentType.CUSTOM,
                config_path=config_path,
                source="snowflake-mcp",
                mcp_servers=[mcp_server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Snowflake MCP Servers: {exc}")

    finally:
        cursor.close()

    return agents, warnings


def _describe_mcp_server_tools(
    conn: Any,
    server_name: str,
    db_name: str,
    schema_name: str,
    warnings: list[str],
) -> list[MCPTool]:
    """Run DESCRIBE MCP SERVER and parse the YAML spec for tool definitions.

    Flags SYSTEM_EXECUTE_SQL tools with a high-risk warning in the description.
    """
    tools: list[MCPTool] = []
    cursor = conn.cursor()

    try:
        fqn = f"{db_name}.{schema_name}.{server_name}" if db_name else server_name
        cursor.execute(f"DESCRIBE MCP SERVER {fqn}")
        rows = cursor.fetchall()
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in rows:
            row_dict = dict(zip(columns, row)) if columns else {}
            prop_name = row_dict.get("property", row_dict.get("name", ""))
            prop_value = row_dict.get("property_value", row_dict.get("value", ""))

            if "spec" in str(prop_name).lower() or "definition" in str(prop_name).lower():
                try:
                    import yaml

                    spec = yaml.safe_load(str(prop_value))
                    if isinstance(spec, dict):
                        for tool_def in spec.get("tools", []):
                            tool_name = tool_def.get("name", "unknown")
                            tool_type = tool_def.get("type", "")
                            description = tool_def.get("description", "")

                            if tool_type == "SYSTEM_EXECUTE_SQL" or "execute_sql" in tool_name.lower():
                                description = f"[HIGH-RISK: SYSTEM_EXECUTE_SQL] {description}"

                            tools.append(MCPTool(name=tool_name, description=description))
                except Exception:
                    pass

    except Exception as exc:
        warnings.append(f"Could not describe MCP Server {server_name}: {exc}")

    finally:
        cursor.close()

    return tools


def _discover_from_query_history(
    conn: Any,
    account: str,
) -> tuple[list[Agent], list[str]]:
    """Audit QUERY_HISTORY for recent CREATE AGENT / CREATE MCP SERVER statements.

    Catches objects created recently or subsequently dropped (shadow inventory).
    """
    agents: list[Agent] = []
    warnings: list[str] = []
    cursor = conn.cursor()
    seen_names: set[str] = set()

    try:
        cursor.execute(
            "SELECT query_text, user_name, start_time "
            "FROM TABLE(INFORMATION_SCHEMA.QUERY_HISTORY()) "
            "WHERE query_text ILIKE '%CREATE%MCP SERVER%' "
            "   OR query_text ILIKE '%CREATE%AGENT%' "
            "ORDER BY start_time DESC "
            "LIMIT 100"
        )
        rows = cursor.fetchall()

        for row in rows:
            query_text = str(row[0]) if row else ""

            obj_name = _parse_create_statement_name(query_text)
            if not obj_name or obj_name in seen_names:
                continue
            seen_names.add(obj_name)

            is_mcp = "MCP SERVER" in query_text.upper()
            source = "snowflake-mcp-audit" if is_mcp else "snowflake-agent-audit"
            obj_type = "mcp-server" if is_mcp else "agent"

            server = MCPServer(
                name=f"audit:{obj_type}:{obj_name}",
                transport=TransportType.UNKNOWN,
            )
            agent = Agent(
                name=f"audit:{obj_type}:{obj_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"snowflake://{account}/query-history/{obj_name}",
                source=source,
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not query Snowflake query history: {exc}")

    finally:
        cursor.close()

    return agents, warnings


def _parse_create_statement_name(query_text: str) -> str | None:
    """Extract the object name from a CREATE AGENT or CREATE MCP SERVER SQL statement."""
    cleaned = " ".join(query_text.split())
    pattern = r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:AGENT|MCP\s+SERVER)\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_.\"]+)"
    match = re.search(pattern, cleaned, re.IGNORECASE)
    if match:
        name = match.group(1).strip('"')
        return name.split(".")[-1]
    return None


def _discover_custom_tools(
    conn: Any,
    account: str,
) -> tuple[list[MCPTool], list[str]]:
    """Discover user-defined functions and procedures that serve as custom tools.

    The language (Python/Java/SQL/JavaScript) is noted in the description
    because it affects the attack surface.
    """
    tools: list[MCPTool] = []
    warnings: list[str] = []

    # Query functions
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT function_name, argument_signature, data_type, function_language "
            "FROM INFORMATION_SCHEMA.FUNCTIONS "
            "WHERE function_schema NOT IN ('INFORMATION_SCHEMA') "
            "ORDER BY function_name "
            "LIMIT 500"
        )
        for row in cursor.fetchall():
            func_name = str(row[0]) if row else "unknown"
            arg_sig = str(row[1]) if len(row) > 1 else ""
            return_type = str(row[2]) if len(row) > 2 else ""
            language = str(row[3]) if len(row) > 3 else "SQL"

            risk_note = ""
            if language.upper() in ("PYTHON", "JAVA", "JAVASCRIPT"):
                risk_note = f" [external runtime: {language}]"

            tools.append(
                MCPTool(
                    name=func_name,
                    description=f"UDF({arg_sig}) -> {return_type} [{language}]{risk_note}",
                )
            )
    except Exception as exc:
        warnings.append(f"Could not query custom functions: {exc}")
    finally:
        cursor.close()

    # Query procedures
    proc_cursor = conn.cursor()
    try:
        proc_cursor.execute(
            "SELECT procedure_name, argument_signature, data_type, procedure_language "
            "FROM INFORMATION_SCHEMA.PROCEDURES "
            "WHERE procedure_schema NOT IN ('INFORMATION_SCHEMA') "
            "ORDER BY procedure_name "
            "LIMIT 500"
        )
        for row in proc_cursor.fetchall():
            proc_name = str(row[0]) if row else "unknown"
            arg_sig = str(row[1]) if len(row) > 1 else ""
            return_type = str(row[2]) if len(row) > 2 else ""
            language = str(row[3]) if len(row) > 3 else "SQL"

            risk_note = ""
            if language.upper() in ("PYTHON", "JAVA", "JAVASCRIPT"):
                risk_note = f" [external runtime: {language}]"

            tools.append(
                MCPTool(
                    name=proc_name,
                    description=f"PROCEDURE({arg_sig}) -> {return_type} [{language}]{risk_note}",
                )
            )
    except Exception as exc:
        warnings.append(f"Could not query stored procedures: {exc}")
    finally:
        proc_cursor.close()

    return tools, warnings


# ---------------------------------------------------------------------------
# Governance Discovery — ACCESS_HISTORY, GRANTS, TAG_REFERENCES, Agent Usage
# ---------------------------------------------------------------------------


def discover_governance(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
    days: int = 30,
) -> GovernanceReport:
    """Discover governance posture from Snowflake ACCOUNT_USAGE views.

    Mines ACCESS_HISTORY, GRANTS_TO_ROLES, TAG_REFERENCES, and
    CORTEX_AGENT_USAGE_HISTORY to produce a governance report with
    risk findings.

    Requires Enterprise edition or higher for ACCESS_HISTORY.
    CORTEX_AGENT_USAGE_HISTORY requires Cortex Agents (GA Feb 2026).

    Args:
        account: Snowflake account identifier.
        user: Snowflake username.
        authenticator: Auth method (externalbrowser, snowflake_jwt, etc.).
        database: Default database context.
        schema: Default schema context.
        days: Look-back window for ACCESS_HISTORY and agent usage.

    Returns:
        GovernanceReport with findings, access records, grants, and usage data.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    resolved_account = account or os.environ.get("SNOWFLAKE_ACCOUNT", "")
    resolved_user = user or os.environ.get("SNOWFLAKE_USER", "")
    report = GovernanceReport(account=resolved_account)

    if not resolved_account:
        report.warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return report

    try:
        import snowflake.connector
        from snowflake.connector.errors import DatabaseError  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake governance. Install with: pip install 'agent-bom[snowflake]'"
        )

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

    if not authenticator:
        password = os.environ.get("SNOWFLAKE_PASSWORD", "")
        if password:
            conn_kwargs["password"] = password
        else:
            conn_kwargs["authenticator"] = "externalbrowser"

    try:
        conn = snowflake.connector.connect(**conn_kwargs)
    except (DatabaseError, Exception) as exc:
        report.warnings.append(f"Could not connect to Snowflake: {exc}")
        return report

    try:
        # 1. ACCESS_HISTORY — who accessed what tables/columns
        access_records, access_warns = _mine_access_history(conn, days)
        report.access_records = access_records
        report.warnings.extend(access_warns)

        # 2. GRANTS_TO_ROLES — privilege grants
        grants, grant_warns = _mine_grants_to_roles(conn)
        report.privilege_grants = grants
        report.warnings.extend(grant_warns)

        # 3. TAG_REFERENCES — data classification tags
        tags, tag_warns = _mine_tag_references(conn)
        report.data_classifications = tags
        report.warnings.extend(tag_warns)

        # 4. CORTEX_AGENT_USAGE_HISTORY — agent telemetry
        usage, usage_warns = _mine_cortex_agent_usage(conn, days)
        report.agent_usage = usage
        report.warnings.extend(usage_warns)

        # 5. Derive governance findings from raw data
        report.findings = _derive_findings(report)

    finally:
        conn.close()

    return report


def _mine_access_history(
    conn: Any,
    days: int,
) -> tuple[list[AccessRecord], list[str]]:
    """Mine SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY for table/column access patterns.

    Enterprise edition required. Returns up to 1000 most recent records.
    """
    records: list[AccessRecord] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT query_id, user_name, role_name, query_start_time, "
            "       direct_objects_accessed, base_objects_accessed "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY "
            f"WHERE query_start_time >= DATEADD(day, -{days}, CURRENT_TIMESTAMP()) "  # nosec B608 — days is int
            "ORDER BY query_start_time DESC "
            "LIMIT 1000"
        )
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))

            # direct_objects_accessed is a JSON array
            direct_objects = _parse_json_field(row_dict.get("direct_objects_accessed", "[]"))
            base_objects = _parse_json_field(row_dict.get("base_objects_accessed", "[]"))

            for obj in direct_objects:
                obj_name = obj.get("objectName", "")
                obj_type = obj.get("objectDomain", "")
                col_list = [c.get("columnName", "") for c in obj.get("columns", []) if c.get("columnName")]

                records.append(
                    AccessRecord(
                        query_id=str(row_dict.get("query_id", "")),
                        user_name=str(row_dict.get("user_name", "")),
                        role_name=str(row_dict.get("role_name", "")),
                        query_start=str(row_dict.get("query_start_time", "")),
                        object_name=obj_name,
                        object_type=obj_type,
                        columns=col_list,
                        operation=_infer_operation(obj),
                        is_write=_is_write_operation(obj),
                        base_objects=[b.get("objectName", "") for b in base_objects if b.get("objectName")],
                    )
                )

    except Exception as exc:
        msg = str(exc)
        if "access_history" in msg.lower() or "enterprise" in msg.lower():
            warnings.append("ACCESS_HISTORY requires Enterprise edition or higher. Skipping access pattern analysis.")
        else:
            warnings.append(f"Could not query ACCESS_HISTORY: {exc}")

    finally:
        cursor.close()

    return records, warnings


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
        warnings.append(f"Could not query GRANTS_TO_ROLES: {exc}")

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
            warnings.append(f"Could not query TAG_REFERENCES: {exc}")

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

    try:
        cursor.execute(
            "SELECT agent_name, database_name, schema_name, "
            "       user_name, role_name, start_time, end_time, "
            "       input_tokens, output_tokens, total_tokens, "
            "       credits_used, model_name, tool_calls, status "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.CORTEX_AGENT_USAGE_HISTORY "
            f"WHERE start_time >= DATEADD(day, -{days}, CURRENT_TIMESTAMP()) "  # nosec B608 — days is int
            "ORDER BY start_time DESC "
            "LIMIT 2000"
        )
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))
            records.append(
                AgentUsageRecord(
                    agent_name=str(row_dict.get("agent_name", "")),
                    database_name=str(row_dict.get("database_name", "")),
                    schema_name=str(row_dict.get("schema_name", "")),
                    user_name=str(row_dict.get("user_name", "")),
                    role_name=str(row_dict.get("role_name", "")),
                    start_time=str(row_dict.get("start_time", "")),
                    end_time=str(row_dict.get("end_time", "")),
                    input_tokens=int(row_dict.get("input_tokens", 0) or 0),
                    output_tokens=int(row_dict.get("output_tokens", 0) or 0),
                    total_tokens=int(row_dict.get("total_tokens", 0) or 0),
                    credits_used=float(row_dict.get("credits_used", 0.0) or 0.0),
                    model_name=str(row_dict.get("model_name", "")),
                    tool_calls=int(row_dict.get("tool_calls", 0) or 0),
                    status=str(row_dict.get("status", "")),
                )
            )

    except Exception as exc:
        msg = str(exc)
        if "cortex_agent_usage" in msg.lower() or "does not exist" in msg.lower():
            warnings.append("CORTEX_AGENT_USAGE_HISTORY not available. Requires Cortex Agents (GA Feb 2026). Skipping agent telemetry.")
        else:
            warnings.append(f"Could not query CORTEX_AGENT_USAGE_HISTORY: {exc}")

    finally:
        cursor.close()

    return records, warnings


# ---------------------------------------------------------------------------
# Finding derivation — analyze raw data to produce governance risk findings
# ---------------------------------------------------------------------------


def _derive_findings(report: GovernanceReport) -> list[GovernanceFinding]:
    """Analyze raw governance data and derive risk findings."""
    findings: list[GovernanceFinding] = []

    findings.extend(_find_write_access_risks(report))
    findings.extend(_find_elevated_privilege_risks(report))
    findings.extend(_find_sensitive_data_access(report))
    findings.extend(_find_agent_usage_anomalies(report))

    # Sort by severity
    severity_order = {
        GovernanceSeverity.CRITICAL: 0,
        GovernanceSeverity.HIGH: 1,
        GovernanceSeverity.MEDIUM: 2,
        GovernanceSeverity.LOW: 3,
        GovernanceSeverity.INFO: 4,
    }
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    return findings


def _find_write_access_risks(report: GovernanceReport) -> list[GovernanceFinding]:
    """Flag roles/users performing DML (INSERT/UPDATE/DELETE) on production tables."""
    findings: list[GovernanceFinding] = []
    write_ops: dict[str, set[str]] = {}  # role -> set of tables written to

    for rec in report.access_records:
        if rec.is_write:
            write_ops.setdefault(rec.role_name, set()).add(rec.object_name)

    for role, tables in write_ops.items():
        if len(tables) >= 5:
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.ACCESS,
                    severity=GovernanceSeverity.HIGH,
                    title=f"Broad write access: {role}",
                    description=(f"Role '{role}' performed write operations on {len(tables)} distinct tables in the analysis window."),
                    agent_or_role=role,
                    details={"tables": sorted(tables)[:20]},
                )
            )
        elif len(tables) >= 1:
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.ACCESS,
                    severity=GovernanceSeverity.MEDIUM,
                    title=f"Write access detected: {role}",
                    description=(f"Role '{role}' performed write operations on: {', '.join(sorted(tables)[:5])}"),
                    agent_or_role=role,
                    details={"tables": sorted(tables)},
                )
            )

    return findings


def _find_elevated_privilege_risks(report: GovernanceReport) -> list[GovernanceFinding]:
    """Flag roles with dangerous privileges (OWNERSHIP, ALL, CREATE ROLE, etc.)."""
    findings: list[GovernanceFinding] = []
    elevated_by_role: dict[str, list[PrivilegeGrant]] = {}

    for grant in report.privilege_grants:
        if grant.is_elevated:
            elevated_by_role.setdefault(grant.grantee, []).append(grant)

    for role, role_grants in elevated_by_role.items():
        priv_set = {g.privilege for g in role_grants}
        if "OWNERSHIP" in priv_set or "ALL" in priv_set or "ALL PRIVILEGES" in priv_set:
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.PRIVILEGE,
                    severity=GovernanceSeverity.CRITICAL,
                    title=f"Elevated privileges: {role}",
                    description=(
                        f"Role '{role}' has {', '.join(sorted(priv_set))} privileges. "
                        f"If an agent runs under this role, it has full control over "
                        f"granted objects."
                    ),
                    agent_or_role=role,
                    details={
                        "privileges": sorted(priv_set),
                        "grant_count": len(role_grants),
                        "objects": sorted({g.object_name for g in role_grants})[:10],
                    },
                )
            )
        else:
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.PRIVILEGE,
                    severity=GovernanceSeverity.HIGH,
                    title=f"Elevated privileges: {role}",
                    description=(f"Role '{role}' has elevated privileges: {', '.join(sorted(priv_set))}"),
                    agent_or_role=role,
                    details={
                        "privileges": sorted(priv_set),
                        "grant_count": len(role_grants),
                    },
                )
            )

    return findings


def _find_sensitive_data_access(report: GovernanceReport) -> list[GovernanceFinding]:
    """Cross-reference TAG_REFERENCES with ACCESS_HISTORY to find sensitive data access."""
    findings: list[GovernanceFinding] = []

    # Build set of tagged (sensitive) objects
    sensitive_objects: dict[str, list[DataClassification]] = {}
    for tag in report.data_classifications:
        sensitive_objects.setdefault(tag.object_name.upper(), []).append(tag)

    if not sensitive_objects:
        return findings

    # Check which access records touch sensitive objects
    sensitive_access: dict[str, dict[str, set[str]]] = {}  # role -> {object -> {tags}}
    for rec in report.access_records:
        obj_upper = rec.object_name.upper()
        if obj_upper in sensitive_objects:
            tags_for_obj = sensitive_objects[obj_upper]
            tag_names = {t.tag_name for t in tags_for_obj}
            sa = sensitive_access.setdefault(rec.role_name, {})
            sa.setdefault(obj_upper, set()).update(tag_names)

    for role, obj_tags in sensitive_access.items():
        pii_tables = [obj for obj, tags in obj_tags.items() if any("PII" in t.upper() or "PHI" in t.upper() for t in tags)]
        if pii_tables:
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.DATA_CLASSIFICATION,
                    severity=GovernanceSeverity.CRITICAL,
                    title=f"PII/PHI data access: {role}",
                    description=(f"Role '{role}' accessed {len(pii_tables)} PII/PHI-tagged table(s): {', '.join(pii_tables[:5])}"),
                    agent_or_role=role,
                    details={"pii_tables": pii_tables[:20]},
                )
            )

        other_sensitive = [obj for obj, tags in obj_tags.items() if obj not in pii_tables]
        if other_sensitive:
            all_tags = set()
            for obj in other_sensitive:
                all_tags.update(obj_tags[obj])
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.DATA_CLASSIFICATION,
                    severity=GovernanceSeverity.HIGH,
                    title=f"Sensitive data access: {role}",
                    description=(
                        f"Role '{role}' accessed {len(other_sensitive)} classified table(s) with tags: {', '.join(sorted(all_tags))}"
                    ),
                    agent_or_role=role,
                    details={
                        "tables": other_sensitive[:20],
                        "tags": sorted(all_tags),
                    },
                )
            )

    return findings


def _find_agent_usage_anomalies(report: GovernanceReport) -> list[GovernanceFinding]:
    """Analyze CORTEX_AGENT_USAGE_HISTORY for anomalies."""
    findings: list[GovernanceFinding] = []

    if not report.agent_usage:
        return findings

    # Aggregate per agent
    agent_stats: dict[str, dict] = {}
    for rec in report.agent_usage:
        stats = agent_stats.setdefault(
            rec.agent_name,
            {
                "total_calls": 0,
                "total_tokens": 0,
                "total_credits": 0.0,
                "total_tool_calls": 0,
                "failures": 0,
                "roles": set(),
            },
        )
        stats["total_calls"] += 1
        stats["total_tokens"] += rec.total_tokens
        stats["total_credits"] += rec.credits_used
        stats["total_tool_calls"] += rec.tool_calls
        if rec.status and rec.status.upper() != "SUCCESS":
            stats["failures"] += 1
        stats["roles"].add(rec.role_name)

    for agent_name, stats in agent_stats.items():
        # High token usage
        if stats["total_tokens"] > 1_000_000:
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.AGENT_USAGE,
                    severity=GovernanceSeverity.MEDIUM,
                    title=f"High token usage: {agent_name}",
                    description=(
                        f"Agent '{agent_name}' consumed {stats['total_tokens']:,} tokens "
                        f"across {stats['total_calls']} calls "
                        f"({stats['total_credits']:.2f} credits)."
                    ),
                    agent_or_role=agent_name,
                    details={
                        "total_calls": stats["total_calls"],
                        "total_tokens": stats["total_tokens"],
                        "total_credits": stats["total_credits"],
                    },
                )
            )

        # Multi-role usage (agent running under multiple roles)
        roles = stats["roles"] - {""}
        if len(roles) > 1:
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.AGENT_USAGE,
                    severity=GovernanceSeverity.HIGH,
                    title=f"Multi-role agent: {agent_name}",
                    description=(
                        f"Agent '{agent_name}' ran under {len(roles)} different roles: "
                        f"{', '.join(sorted(roles))}. This increases blast radius."
                    ),
                    agent_or_role=agent_name,
                    details={"roles": sorted(roles)},
                )
            )

        # High tool call rate
        if stats["total_tool_calls"] > 500:
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.AGENT_USAGE,
                    severity=GovernanceSeverity.MEDIUM,
                    title=f"High tool usage: {agent_name}",
                    description=(
                        f"Agent '{agent_name}' made {stats['total_tool_calls']} tool calls across {stats['total_calls']} invocations."
                    ),
                    agent_or_role=agent_name,
                    details={
                        "total_tool_calls": stats["total_tool_calls"],
                        "total_calls": stats["total_calls"],
                    },
                )
            )

        # High failure rate
        if stats["failures"] > 0 and stats["total_calls"] > 5:
            failure_rate = stats["failures"] / stats["total_calls"]
            if failure_rate > 0.3:
                findings.append(
                    GovernanceFinding(
                        category=GovernanceCategory.AGENT_USAGE,
                        severity=GovernanceSeverity.MEDIUM,
                        title=f"High failure rate: {agent_name}",
                        description=(
                            f"Agent '{agent_name}' has a {failure_rate:.0%} failure rate "
                            f"({stats['failures']}/{stats['total_calls']} calls)."
                        ),
                        agent_or_role=agent_name,
                        details={
                            "failures": stats["failures"],
                            "total_calls": stats["total_calls"],
                            "failure_rate": round(failure_rate, 3),
                        },
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_json_field(value: Any) -> list[dict]:
    """Parse a JSON-encoded field that may be a string, list, or None."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
    return []


def _infer_operation(obj: dict) -> str:
    """Infer the SQL operation from an ACCESS_HISTORY direct_objects_accessed entry."""
    # Snowflake ACCESS_HISTORY may include objectDomain and columns with DML type
    columns = obj.get("columns", [])
    if not columns:
        return "SELECT"
    # Check if any column access indicates a write
    for col in columns:
        dml_types = col.get("directSources", [])
        for src in dml_types:
            op = src.get("type", "").upper()
            if op in ("INSERT", "UPDATE", "DELETE", "MERGE", "COPY"):
                return op
    return "SELECT"


def _is_write_operation(obj: dict) -> bool:
    """Check if an ACCESS_HISTORY object was written to."""
    op = _infer_operation(obj)
    return op in ("INSERT", "UPDATE", "DELETE", "MERGE", "COPY")


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
    resolved_account = account or os.environ.get("SNOWFLAKE_ACCOUNT", "")
    resolved_user = user or os.environ.get("SNOWFLAKE_USER", "")
    timeline = ActivityTimeline(account=resolved_account)

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

    if not authenticator:
        password = os.environ.get("SNOWFLAKE_PASSWORD", "")
        if password:
            conn_kwargs["password"] = password
        else:
            conn_kwargs["authenticator"] = "externalbrowser"

    try:
        conn = snowflake.connector.connect(**conn_kwargs)
    except (DatabaseError, Exception) as exc:
        timeline.warnings.append(f"Could not connect to Snowflake: {exc}")
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

    try:
        cursor.execute(
            "SELECT query_id, query_text, user_name, role_name, "
            "       start_time, end_time, execution_status, "
            "       warehouse_name, database_name, schema_name, "
            "       query_type, rows_produced, bytes_scanned, "
            "       total_elapsed_time "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
            f"WHERE start_time >= DATEADD(day, -{min(days, 365)}, CURRENT_TIMESTAMP()) "
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
            warnings.append(f"Could not query QUERY_HISTORY: {exc}")

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

    try:
        cursor.execute(
            "SELECT event_id, event_type, agent_name, timestamp, "
            "       duration_ms, status, model_name, "
            "       input_tokens, output_tokens, "
            "       tool_name, tool_input, tool_output_summary, "
            "       user_feedback, trace_id, parent_event_id "
            "FROM TABLE(SNOWFLAKE.LOCAL.AI_OBSERVABILITY_EVENTS("
            f"  INTERVAL => '{min(days, 365)} days'"
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
            warnings.append(f"Could not query AI_OBSERVABILITY_EVENTS: {exc}")

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
