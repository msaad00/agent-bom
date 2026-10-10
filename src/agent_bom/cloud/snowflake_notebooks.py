"""Snowflake Notebooks discovery — runtime packages and Cortex usage per notebook."""

from __future__ import annotations

from typing import Any

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType
from agent_bom.security import sanitize_error

from .normalization import build_package_purl
from .snowflake_common import _quote_sf_identifier, _sf

# Known AI/ML packages to flag when found in notebook imports
_AI_ML_PACKAGES = {
    "openai",
    "anthropic",
    "langchain",
    "transformers",
    "torch",
    "tensorflow",
    "keras",
    "huggingface_hub",
    "sentence_transformers",
    "llama_index",
    "vllm",
    "triton",
    "bitsandbytes",
    "peft",
    "trl",
    "diffusers",
    "autogen",
    "crewai",
    "dspy",
    "guidance",
    "promptflow",
    "snowflake-ml-python",
    "snowflake-snowpark-python",
    "snowflake-cortex",
}

# Cortex AI functions flagged when a notebook query calls them.
_CORTEX_NOTEBOOK_FUNCS = (
    "cortex.complete",
    "cortex.embed",
    "cortex.sentiment",
    "cortex.summarize",
    "cortex.translate",
    "cortex.extract_answer",
)


def _add_notebook_packages(prop_val: str, packages: list[Package], tools: list[MCPTool]) -> None:
    """Parse a notebook ``PACKAGES`` property value; AI/ML packages are also flagged as tools."""
    for pkg_spec in prop_val.split(","):
        pkg_spec = pkg_spec.strip()
        if not pkg_spec:
            continue
        parts = pkg_spec.split("==") if "==" in pkg_spec else pkg_spec.split("=")
        pkg_name = parts[0].strip()
        pkg_version = parts[1].strip() if len(parts) > 1 else "unknown"
        packages.append(
            Package(
                name=pkg_name,
                version=pkg_version,
                ecosystem="pypi",
                purl=build_package_purl(ecosystem="pypi", name=pkg_name, version=pkg_version),
            )
        )
        # Flag AI/ML packages as tools for visibility
        if pkg_name.lower().replace("-", "_") in _AI_ML_PACKAGES:
            tools.append(
                MCPTool(
                    name=f"ai-pkg:{pkg_name}",
                    description=f"AI/ML package {pkg_name}@{pkg_version} used in notebook",
                )
            )


def _add_notebook_cortex_tools(prop_val: str, tools: list[MCPTool]) -> None:
    """Flag Cortex AI functions a notebook query property calls."""
    for func in _CORTEX_NOTEBOOK_FUNCS:
        if func.lower() in prop_val.lower():
            tools.append(
                MCPTool(
                    name=f"cortex:{func.split('.')[-1]}",
                    description=f"Cortex AI function {func} called in notebook",
                )
            )


def _describe_notebook(cursor: Any, nb_db: str, nb_schema: str, nb_name: str, packages: list[Package], tools: list[MCPTool]) -> None:
    """``DESCRIBE NOTEBOOK`` → runtime packages and Cortex function usage."""
    fqn = ".".join(_quote_sf_identifier(part) for part in (nb_db, nb_schema, nb_name))
    cursor.execute(
        f"DESCRIBE NOTEBOOK {fqn}"  # noqa: S608
    )
    desc_rows = cursor.fetchall()
    desc_cols = [d[0].lower() for d in cursor.description] if cursor.description else []
    for d_row in desc_rows:
        d_dict = dict(zip(desc_cols, d_row)) if desc_cols else {}
        prop_name = str(d_dict.get("property", d_dict.get("name", ""))).lower()
        prop_val = str(d_dict.get("value", d_dict.get("property_value", "")))

        # Extract packages from PACKAGES property
        if "package" in prop_name and prop_val:
            _add_notebook_packages(prop_val, packages, tools)

        # Check for Cortex function usage in notebook queries
        if "query" in prop_name and prop_val:
            _add_notebook_cortex_tools(prop_val, tools)


def _notebook_agent(cursor: Any, account: str, row: Any, columns: list[str], warnings: list[str]) -> Agent:
    """One ``SHOW NOTEBOOKS`` row → a notebook agent with its described packages/tools."""
    row_dict = dict(zip(columns, row)) if columns else {}
    nb_name = row_dict.get("name", str(row[0]) if row else "unknown")
    nb_db = row_dict.get("database_name", "")
    nb_schema = row_dict.get("schema_name", "")
    nb_owner = row_dict.get("owner", "")
    nb_comment = row_dict.get("comment", "")

    packages: list[Package] = []
    tools: list[MCPTool] = []

    # Try to extract notebook package dependencies from metadata
    # Snowflake stores notebook runtime packages in INFORMATION_SCHEMA
    try:
        _describe_notebook(cursor, nb_db, nb_schema, nb_name, packages, tools)
    except ValueError as exc:
        warnings.append(f"Skipping Snowflake notebook with unsafe identifier: {sanitize_error(exc)}")
    except Exception as exc:
        warnings.append(f"Could not describe Snowflake notebook {nb_name!r}: {sanitize_error(exc)}")

    server = MCPServer(
        name=f"sf-notebook:{nb_name}",
        transport=TransportType.UNKNOWN,
        packages=packages,
        tools=tools,
    )
    return Agent(
        name=f"sf-notebook:{nb_name}",
        agent_type=AgentType.CUSTOM,
        config_path=f"snowflake://{account}/{nb_db}/{nb_schema}/notebooks/{nb_name}",
        source="snowflake-notebook",
        metadata={
            "database": nb_db,
            "schema": nb_schema,
            "owner": nb_owner,
            "comment": nb_comment,
            "cloud_origin": _sf()._snowflake_cloud_origin(
                account=account,
                service="notebooks",
                resource_type="notebook",
                resource_id=f"{account}/{nb_db}/{nb_schema}/{nb_name}",
                resource_name=nb_name,
                database=nb_db,
                schema=nb_schema,
            ),
        },
        mcp_servers=[server],
    )


def _discover_snowflake_notebooks(
    conn: Any,
    account: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Snowflake Notebooks and extract AI/ML package usage.

    Snowflake Notebooks run Python/SQL cells in a managed Snowpark environment.
    They can import AI/ML libraries, call Cortex functions, and access external
    stages — all supply chain vectors we need to inventory.
    """
    agents: list[Agent] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute("SHOW NOTEBOOKS IN ACCOUNT")
        rows = cursor.fetchall()
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in rows:
            agents.append(_notebook_agent(cursor, account, row, columns, warnings))

    except Exception as exc:
        msg = str(exc)
        if "does not exist" in msg.lower() or "syntax error" in msg.lower():
            # SHOW NOTEBOOKS not available on this Snowflake edition/version
            warnings.append("Snowflake Notebooks discovery not available (requires Snowflake 2024.3+)")
        else:
            warnings.append(f"Could not list Snowflake Notebooks: {sanitize_error(exc)}")

    finally:
        cursor.close()

    return agents, warnings
