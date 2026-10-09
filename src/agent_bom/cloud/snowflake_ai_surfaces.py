"""Snowflake AI surface discovery: Cortex services and agents, MCP servers, Snowpark, Streamlit, custom tools."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType
from agent_bom.security import sanitize_error, sanitize_text

from .normalization import (
    build_package_purl,
)
from .snowflake_common import _record_snowflake_inventory_failure, _sf, _validate_sf_identifier

# Log under the façade's logger so existing log routing and filters keep applying.
logger = logging.getLogger("agent_bom.cloud.snowflake")


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
                metadata={
                    "cloud_origin": _sf()._snowflake_cloud_origin(
                        account=account,
                        service="cortex-search",
                        resource_type="service",
                        resource_id=config_path,
                        resource_name=service_name,
                        database=svc_database,
                        schema=svc_schema,
                    )
                },
            )
            agents.append(agent)

    except Exception as exc:
        # Cortex Search Services may not be available in all accounts
        warnings.append(f"Could not list Cortex Search Services: {sanitize_error(exc)}")

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
                packages.append(
                    Package(
                        name=name, version=version, ecosystem="pypi", purl=build_package_purl(ecosystem="pypi", name=name, version=version)
                    )
                )

    except Exception as exc:
        # INFORMATION_SCHEMA.PACKAGES may not exist or may not be accessible
        warnings.append(f"Could not query Snowpark packages: {sanitize_error(exc)}")

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
        cursor.execute("SHOW STREAMLITS IN ACCOUNT")
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
        warnings.append(f"Could not list Streamlit apps: {sanitize_error(exc)}")

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
                metadata={
                    "cloud_origin": _sf()._snowflake_cloud_origin(
                        account=account,
                        service="cortex-agents",
                        resource_type="agent",
                        resource_id=config_path,
                        resource_name=agent_name,
                        database=db_name,
                        schema=schema_name,
                    )
                },
            )
            agents.append(agent)

    except Exception as exc:
        _record_snowflake_inventory_failure(
            exc=exc,
            resource_type="Cortex Agents",
            inventory_key="cortex_agents",
            warnings=warnings,
        )

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
                metadata={
                    "cloud_origin": _sf()._snowflake_cloud_origin(
                        account=account,
                        service="mcp",
                        resource_type="server",
                        resource_id=config_path,
                        resource_name=server_name,
                        database=db_name,
                        schema=schema_name,
                    )
                },
            )
            agents.append(agent)

    except Exception as exc:
        _record_snowflake_inventory_failure(
            exc=exc,
            resource_type="Snowflake MCP Servers",
            inventory_key="mcp_servers",
            warnings=warnings,
        )

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
        # Validate identifiers to prevent SQL injection
        _validate_sf_identifier(server_name)
        if db_name:
            _validate_sf_identifier(db_name)
            _validate_sf_identifier(schema_name)
        fqn = f"{db_name}.{schema_name}.{server_name}" if db_name else server_name
        cursor.execute(f"DESCRIBE MCP SERVER {fqn}")  # nosec B608 — identifiers validated above
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
                except (ImportError, ValueError, KeyError, TypeError) as exc:
                    logger.debug("Could not parse tool spec for MCP server: %s", sanitize_text(exc))

    except Exception as exc:
        warnings.append(f"Could not describe MCP Server {server_name}: {sanitize_error(exc)}")

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
                metadata={
                    "cloud_origin": _sf()._snowflake_cloud_origin(
                        account=account,
                        service="query-history",
                        resource_type=obj_type,
                        resource_id=f"{account}/query-history/{obj_name}",
                        resource_name=obj_name,
                    )
                },
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not query Snowflake query history: {sanitize_error(exc)}")

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
        warnings.append(f"Could not query custom functions: {sanitize_error(exc)}")
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
        warnings.append(f"Could not query stored procedures: {sanitize_error(exc)}")
    finally:
        proc_cursor.close()

    return tools, warnings
