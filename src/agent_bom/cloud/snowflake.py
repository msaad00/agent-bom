"""Snowflake cloud discovery — Cortex agents, MCP servers, Snowpark packages, governance.

Requires ``snowflake-connector-python``.  Install with::

    pip install 'agent-bom[snowflake]'

Authentication — zero-credential model (no passwords stored or logged):

agent-bom never stores credentials. Auth resolution order:

1. ``SNOWFLAKE_AUTHENTICATOR`` env var (or ``--snowflake-authenticator`` CLI flag)
   Recommended values:
   - ``externalbrowser``   — SSO via Okta/Azure AD/Google (opens browser) ← **default**
   - ``snowflake_jwt``     — RSA key-pair (set SNOWFLAKE_PRIVATE_KEY_PATH)
   - ``oauth``             — OAuth access token (set SNOWFLAKE_TOKEN)

2. ``SNOWFLAKE_PRIVATE_KEY_PATH`` env var — RSA key-pair auth (recommended for CI/CD)

3. ``SNOWFLAKE_PASSWORD`` env var — **deprecated**, emits a runtime warning.
   Migrate to SSO (``externalbrowser``) or key-pair (``SNOWFLAKE_PRIVATE_KEY_PATH``).

All credentials are read from environment at runtime and passed directly to the
Snowflake connector. They are never logged, stored, or transmitted by agent-bom.
Errors are sanitized before display (sanitize_error strips secrets from messages).

Required Snowflake privileges (read-only):
    IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE (for ACCOUNT_USAGE)
    USAGE ON WAREHOUSE <warehouse>
    SELECT on SNOWFLAKE.ACCOUNT_USAGE views (for CIS benchmark)
"""

from __future__ import annotations

import json
import logging
import os
import re
import warnings
from typing import Any

from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode, attach_envelope_to_agents
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
from agent_bom.security import sanitize_error

from .base import CloudDiscoveryError
from .normalization import (
    build_cloud_origin,
    build_package_purl,
    coerce_int_or_none,
    coerce_truthy,
    resolve_env_or_value,
)

logger = logging.getLogger(__name__)

# Backwards-compatible aliases for the shared cloud helpers. Call sites and
# tests may reference either the shared public names or these private aliases.
_env_or_value = resolve_env_or_value
_sf_truthy = coerce_truthy
_coerce_int_or_none = coerce_int_or_none

# Opt-in env flag. Default OFF — estate-wide enumeration must be explicitly
# requested by an operator. Symmetric with the other providers'
# AGENT_BOM_<PROVIDER>_INVENTORY gates (AWS / AZURE / GCP), so an ordinary scan
# can fold the Snowflake estate into the graph without the ``--snowflake`` CLI
# flag.
INVENTORY_ENV_FLAG = "AGENT_BOM_SNOWFLAKE_INVENTORY"

# Opt-in env flag for the Organization → Accounts roll-up. Default OFF and
# separate from the per-account inventory gate because enumerating the
# organization requires the ORGADMIN role (``SHOW ORGANIZATION ACCOUNTS``),
# which the read-only ``ABOM_READONLY`` role typically lacks. Symmetric with the
# GCP/AWS organization gates: a single account graphs unchanged when this is off.
ORG_ENV_FLAG = "AGENT_BOM_SNOWFLAKE_ORG"

_TRUTHY = {"1", "true", "yes", "on"}

# Read-only privileges this discoverer exercises, surfaced on the discovery
# envelope so ``permissions_used`` stays honest (the producer owns the catalog).
_SF_ORG_PERMISSIONS: tuple[str, ...] = (
    "ORGADMIN.ORGANIZATION_ACCOUNTS:SELECT",
    "SNOWFLAKE.ORGANIZATION_USAGE.ACCOUNTS:SELECT",
)

# Cap accounts walked so a very large organization can't run unbounded.
_MAX_ORG_ACCOUNTS = int(os.environ.get("AGENT_BOM_SNOWFLAKE_MAX_ACCOUNTS", "500") or "500")


def inventory_enabled() -> bool:
    """Return whether estate-wide Snowflake inventory enumeration is opted in.

    Default OFF. Operators enable it by setting ``AGENT_BOM_SNOWFLAKE_INVENTORY``
    to a truthy value (``1`` / ``true`` / ``yes`` / ``on``). Read-only with no
    side effects — mirrors the AWS / Azure / GCP inventory gates.
    """
    return os.environ.get(INVENTORY_ENV_FLAG, "").strip().lower() in _TRUTHY


def org_enabled() -> bool:
    """Return whether the Snowflake Organization roll-up is opted in.

    Default OFF. Operators enable it by setting ``AGENT_BOM_SNOWFLAKE_ORG`` to a
    truthy value. Read-only with no side effects — mirrors the GCP/AWS org gates.
    """
    return os.environ.get(ORG_ENV_FLAG, "").strip().lower() in _TRUTHY


def _snowflake_cloud_origin(
    *,
    account: str,
    service: str,
    resource_type: str,
    resource_id: str,
    resource_name: str,
    database: str = "",
    schema: str = "",
) -> dict[str, Any]:
    raw_identity = {
        "account": account,
        "database": database,
        "schema": schema,
        "name": resource_name,
    }
    return build_cloud_origin(
        provider="snowflake",
        service=service,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        account_id=account,
        raw_identity=raw_identity,
    )


def _apply_key_pair(conn_kwargs: dict[str, Any]) -> bool:
    """Load the RSA key-pair (``SNOWFLAKE_PRIVATE_KEY_PATH``) into *conn_kwargs*.

    Returns ``True`` when a key path was configured. Shared by the explicit
    ``snowflake_jwt`` authenticator path and the implicit key-pair fallback so a
    private key is loaded in both — never just the authenticator name alone.
    """
    key_path = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH", "")
    if not key_path:
        return False
    conn_kwargs["private_key_file"] = key_path
    passphrase = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "")
    if passphrase:
        conn_kwargs["private_key_file_pwd"] = passphrase
    return True


def _resolve_snowflake_auth(
    conn_kwargs: dict[str, Any],
    authenticator: str | None,
) -> None:
    """Resolve Snowflake auth into *conn_kwargs* in-place.

    Priority: explicit authenticator → SNOWFLAKE_AUTHENTICATOR env →
    key-pair (SNOWFLAKE_PRIVATE_KEY_PATH) → SNOWFLAKE_PASSWORD (deprecated) →
    externalbrowser SSO (safe default).
    """
    if not authenticator:
        authenticator = os.environ.get("SNOWFLAKE_AUTHENTICATOR", "")
    if authenticator:
        conn_kwargs["authenticator"] = authenticator
        # `snowflake_jwt` is key-pair auth — it still needs the private key
        # loaded. Without this, setting SNOWFLAKE_AUTHENTICATOR=snowflake_jwt
        # (the documented key-pair option) sent the authenticator with no key
        # and the connector failed with "Expected bytes ... got NoneType".
        if authenticator.lower() == "snowflake_jwt":
            _apply_key_pair(conn_kwargs)
        return

    # Key-pair auth (recommended for CI/CD)
    if _apply_key_pair(conn_kwargs):
        return

    # Password auth — deprecated, emit warning
    password = os.environ.get("SNOWFLAKE_PASSWORD", "")
    if password:
        warnings.warn(
            "SNOWFLAKE_PASSWORD is deprecated and will be removed in a future release. "
            "Migrate to SSO (SNOWFLAKE_AUTHENTICATOR=externalbrowser) or key-pair "
            "(SNOWFLAKE_PRIVATE_KEY_PATH). See https://github.com/msaad00/agent-bom#auth",
            DeprecationWarning,
            stacklevel=3,
        )
        conn_kwargs["password"] = password
        return

    # Safe default — SSO via browser
    conn_kwargs["authenticator"] = "externalbrowser"


# Snowflake identifier safety: only allow alphanumeric, underscore, dot, dollar
_SAFE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$]*$")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1F\x7F]")


def _validate_sf_identifier(name: str) -> str:
    """Validate a Snowflake identifier against injection."""
    if not _SAFE_IDENT_RE.match(name):
        raise ValueError(f"Unsafe Snowflake identifier: {name!r}")
    return name


def _quote_sf_identifier(name: str) -> str:
    """Safely quote a Snowflake identifier for SQL interpolation.

    Unlike ``_validate_sf_identifier`` this supports legitimate quoted
    identifiers such as notebook names containing spaces while still
    preventing statement-breaking injection.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("Snowflake identifier must be a non-empty string")
    if _CONTROL_CHAR_RE.search(name):
        raise ValueError(f"Unsafe Snowflake identifier: {name!r}")
    return '"' + name.replace('"', '""') + '"'


def _coerce_snowflake_days(days: Any, *, max_days: int | None = None) -> int:
    """Validate and normalize day-window inputs used in SQL interpolation."""
    try:
        value = int(days)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"days must be an integer, got {days!r}") from exc
    if value < 1:
        raise ValueError(f"days must be >= 1, got {value!r}")
    if max_days is not None:
        value = min(value, max_days)
    return value


def _get_connection(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> Any:
    """Open a Snowflake connection using the standard auth resolution contract."""
    try:
        import snowflake.connector
    except ImportError as exc:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake access. Install with: pip install 'agent-bom[snowflake]'"
        ) from exc

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    resolved_user = _env_or_value(user, "SNOWFLAKE_USER")
    if not resolved_account:
        raise CloudDiscoveryError("SNOWFLAKE_ACCOUNT not set.")

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

    _resolve_snowflake_auth(conn_kwargs, authenticator)
    return snowflake.connector.connect(**conn_kwargs)


def discover(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
    conn: Any = None,
) -> tuple[list[Agent], list[str]]:
    """Discover Cortex agents, MCP servers, and Snowpark packages from Snowflake.

    Args:
        conn: Optional already-open Snowflake connection (e.g. brokered from a
            stored read-only connection). When supplied it is used directly
            instead of building one from env/args, and it is **not** closed here
            — the caller owns its lifecycle. When ``None`` (the default) a
            connection is built from env/args and closed before returning.

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

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    resolved_user = _env_or_value(user, "SNOWFLAKE_USER")

    # An injected connection (the broker path) does not require SNOWFLAKE_ACCOUNT
    # in env; fall back to a placeholder scope label only for graph/envelope use.
    owns_conn = conn is None
    if owns_conn and not resolved_account:
        warnings.append("SNOWFLAKE_ACCOUNT not set. Provide --snowflake-account or set the SNOWFLAKE_ACCOUNT env var.")
        return agents, warnings
    if not resolved_account:
        resolved_account = "connection"

    if conn is None:
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

        _resolve_snowflake_auth(conn_kwargs, authenticator)

        try:
            conn = snowflake.connector.connect(**conn_kwargs)
        except (DatabaseError, Exception) as exc:
            warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
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
                    metadata={
                        "cloud_origin": _snowflake_cloud_origin(
                            account=resolved_account,
                            service="custom-tools",
                            resource_type="tool-collection",
                            resource_id=f"{resolved_account}/custom-tools",
                            resource_name="custom-tools",
                        )
                    },
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
                metadata={
                    "cloud_origin": _snowflake_cloud_origin(
                        account=resolved_account,
                        service="snowpark",
                        resource_type="package-environment",
                        resource_id=resolved_account,
                        resource_name=resolved_account,
                    )
                },
            )
            agents.append(agent)

        # ── Streamlit apps ────────────────────────────────────────────────
        streamlit_agents, st_warns = _discover_streamlit_apps(conn, resolved_account)
        agents.extend(streamlit_agents)
        warnings.extend(st_warns)

        # ── Snowflake Notebooks ─────────────────────────────────────────
        notebook_agents, nb_warns = _discover_snowflake_notebooks(conn, resolved_account)
        agents.extend(notebook_agents)
        warnings.extend(nb_warns)

    finally:
        # Only close a connection we opened; an injected (brokered) connection is
        # the caller's to close.
        if owns_conn:
            conn.close()

    # Per-run discovery envelope (#2083 PR B). Snowflake reads through the
    # SQL surface using the user's role. We expose the role as a scope
    # qualifier so operators can see which Snowflake role this run used.
    scope: list[str] = []
    if resolved_account:
        scope.append(f"snowflake:account/{resolved_account}")
    if database:
        scope.append(f"snowflake:database/{database}")
    if schema:
        scope.append(f"snowflake:schema/{schema}")
    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.SAAS_READ_ONLY,
        discovery_scope=tuple(scope),
        permissions_used=(
            "INFORMATION_SCHEMA.AGENTS:SELECT",
            "INFORMATION_SCHEMA.CORTEX_SEARCH_SERVICES:SELECT",
            "INFORMATION_SCHEMA.PACKAGES:SELECT",
            "INFORMATION_SCHEMA.STAGES:SELECT",
            "INFORMATION_SCHEMA.STREAMLITS:SELECT",
            "INFORMATION_SCHEMA.NOTEBOOKS:SELECT",
        ),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )
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
                metadata={
                    "cloud_origin": _snowflake_cloud_origin(
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

    # Known AI/ML packages to flag when found in notebook imports
    _ai_ml_packages = {
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

    try:
        cursor.execute("SHOW NOTEBOOKS IN ACCOUNT")
        rows = cursor.fetchall()
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in rows:
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
                            if pkg_name.lower().replace("-", "_") in _ai_ml_packages:
                                tools.append(
                                    MCPTool(
                                        name=f"ai-pkg:{pkg_name}",
                                        description=f"AI/ML package {pkg_name}@{pkg_version} used in notebook",
                                    )
                                )

                    # Check for Cortex function usage in notebook queries
                    if "query" in prop_name and prop_val:
                        cortex_funcs = [
                            "cortex.complete",
                            "cortex.embed",
                            "cortex.sentiment",
                            "cortex.summarize",
                            "cortex.translate",
                            "cortex.extract_answer",
                        ]
                        for func in cortex_funcs:
                            if func.lower() in prop_val.lower():
                                tools.append(
                                    MCPTool(
                                        name=f"cortex:{func.split('.')[-1]}",
                                        description=f"Cortex AI function {func} called in notebook",
                                    )
                                )

            except ValueError as exc:
                warnings.append(f"Skipping Snowflake notebook with unsafe identifier: {sanitize_error(exc)}")
            except Exception:
                # DESCRIBE NOTEBOOK may not be available on all editions
                pass

            server = MCPServer(
                name=f"sf-notebook:{nb_name}",
                transport=TransportType.UNKNOWN,
                packages=packages,
                tools=tools,
            )
            agent = Agent(
                name=f"sf-notebook:{nb_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"snowflake://{account}/{nb_db}/{nb_schema}/notebooks/{nb_name}",
                source="snowflake-notebook",
                metadata={
                    "database": nb_db,
                    "schema": nb_schema,
                    "owner": nb_owner,
                    "comment": nb_comment,
                    "cloud_origin": _snowflake_cloud_origin(
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
            agents.append(agent)

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
                    "cloud_origin": _snowflake_cloud_origin(
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
        warnings.append(f"Could not list Cortex Agents: {sanitize_error(exc)}")

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
                    "cloud_origin": _snowflake_cloud_origin(
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
        warnings.append(f"Could not list Snowflake MCP Servers: {sanitize_error(exc)}")

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
                    logger.debug("Could not parse tool spec for MCP server: %s", exc)

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
                    "cloud_origin": _snowflake_cloud_origin(
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
    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    resolved_user = _env_or_value(user, "SNOWFLAKE_USER")
    report = GovernanceReport(account=resolved_account)
    days = _coerce_snowflake_days(days)

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

    _resolve_snowflake_auth(conn_kwargs, authenticator)

    try:
        conn = snowflake.connector.connect(**conn_kwargs)
    except (DatabaseError, Exception) as exc:
        report.warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
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
    days = _coerce_snowflake_days(days)

    try:
        # ACCESS_HISTORY has no ROLE_NAME column; the executing role lives on
        # QUERY_HISTORY, joined via query_id. The accessed/modified objects are
        # VARIANT arrays (objectName/objectDomain/columns) parsed in Python below.
        cursor.execute(
            "SELECT ah.query_id, ah.user_name, qh.role_name, ah.query_start_time, "
            "       ah.direct_objects_accessed, ah.base_objects_accessed, "
            "       ah.objects_modified "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY ah "
            "LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY qh "
            "       ON ah.query_id = qh.query_id "
            f"WHERE ah.query_start_time >= DATEADD(day, -{days}, CURRENT_TIMESTAMP()) "  # nosec B608 — days is int
            "ORDER BY ah.query_start_time DESC "
            "LIMIT 1000"
        )
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))

            query_id = str(row_dict.get("query_id", ""))
            user_name = str(row_dict.get("user_name", ""))
            role_name = str(row_dict.get("role_name") or "")
            query_start = str(row_dict.get("query_start_time", ""))

            # Each is a JSON array of objects with objectName/objectDomain/columns.
            direct_objects = _parse_json_field(row_dict.get("direct_objects_accessed", "[]"))
            base_objects = _parse_json_field(row_dict.get("base_objects_accessed", "[]"))
            objects_modified = _parse_json_field(row_dict.get("objects_modified", "[]"))

            base_names = [b.get("objectName", "") for b in base_objects if b.get("objectName")]
            # Tables written by this query — writes surface in objects_modified,
            # not direct_objects_accessed (which captures reads).
            modified_names = {m.get("objectName", "") for m in objects_modified if m.get("objectName")}

            for obj in direct_objects:
                obj_name = obj.get("objectName", "")
                obj_type = obj.get("objectDomain", "")
                col_list = [c.get("columnName", "") for c in obj.get("columns", []) if c.get("columnName")]
                is_write = obj_name in modified_names or _is_write_operation(obj)

                records.append(
                    AccessRecord(
                        query_id=query_id,
                        user_name=user_name,
                        role_name=role_name,
                        query_start=query_start,
                        object_name=obj_name,
                        object_type=obj_type,
                        columns=col_list,
                        operation=_infer_operation(obj),
                        is_write=is_write,
                        base_objects=base_names,
                    )
                )

            # Surface write targets that only appear in objects_modified (e.g. an
            # INSERT/COPY into a table not present in direct_objects_accessed).
            direct_names = {o.get("objectName", "") for o in direct_objects}
            for obj in objects_modified:
                obj_name = obj.get("objectName", "")
                if not obj_name or obj_name in direct_names:
                    continue
                col_list = [c.get("columnName", "") for c in obj.get("columns", []) if c.get("columnName")]
                records.append(
                    AccessRecord(
                        query_id=query_id,
                        user_name=user_name,
                        role_name=role_name,
                        query_start=query_start,
                        object_name=obj_name,
                        object_type=obj.get("objectDomain", ""),
                        columns=col_list,
                        operation="WRITE",
                        is_write=True,
                        base_objects=base_names,
                    )
                )

    except Exception as exc:
        msg = str(exc)
        if "access_history" in msg.lower() or "enterprise" in msg.lower():
            warnings.append("ACCESS_HISTORY requires Enterprise edition or higher. Skipping access pattern analysis.")
        else:
            warnings.append(f"Could not query ACCESS_HISTORY: {sanitize_error(exc)}")

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
        warnings.append(f"Could not query GRANTS_TO_ROLES: {sanitize_error(exc)}")

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
    from agent_bom.graph.severity import severity_worst_first_rank

    findings.sort(key=lambda f: severity_worst_first_rank(f.severity.value if hasattr(f.severity, "value") else str(f.severity)))

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


def _parse_json_object(value: Any) -> dict:
    """Parse a JSON-encoded object field that may be a string, dict, or None."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


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


def _discover_sf_objects(conn: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate tables + views from ACCOUNT_USAGE as data-store objects (read-only).

    Control-plane metadata only — fully-qualified name, type, and (for tables)
    row/byte counts. Never reads row data.
    """
    objects: list[dict[str, Any]] = []
    for object_type, view in (("table", "TABLES"), ("view", "VIEWS")):
        cursor = conn.cursor()
        try:
            cols = "table_catalog, table_schema, table_name" + (", row_count, bytes" if view == "TABLES" else "")
            cursor.execute(
                f"SELECT {cols} FROM SNOWFLAKE.ACCOUNT_USAGE.{view} "  # nosec B608 — static view name + column list
                "WHERE deleted IS NULL ORDER BY table_catalog, table_schema, table_name LIMIT 50000"
            )
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                db, sch, nm = str(r.get("table_catalog", "")), str(r.get("table_schema", "")), str(r.get("table_name", ""))
                if not nm:
                    continue
                objects.append(
                    {
                        "fqn": f"{db}.{sch}.{nm}",
                        "database": db,
                        "schema": sch,
                        "name": nm,
                        "object_type": object_type,
                        "row_count": int(r["row_count"]) if r.get("row_count") is not None else None,
                        "bytes": int(r["bytes"]) if r.get("bytes") is not None else None,
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list {view}: {sanitize_error(exc)}")
        finally:
            cursor.close()
    return objects


def _discover_sf_dependencies(conn: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate object lineage from ACCOUNT_USAGE.OBJECT_DEPENDENCIES (read-only).

    The referencing object depends on the referenced object (e.g. a view depends
    on its base table) — this is the data-lineage / dependency graph.
    """
    dependencies: list[dict[str, Any]] = []
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT referencing_database, referencing_schema, referencing_object_name, referencing_object_domain, "
            "       referenced_database, referenced_schema, referenced_object_name, referenced_object_domain, "
            "       dependency_type "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES LIMIT 50000"
        )
        keys = [d[0].lower() for d in cursor.description] if cursor.description else []
        for row in cursor.fetchall():
            r = dict(zip(keys, row))
            ring = ".".join(str(r.get(k, "")) for k in ("referencing_database", "referencing_schema", "referencing_object_name"))
            red = ".".join(str(r.get(k, "")) for k in ("referenced_database", "referenced_schema", "referenced_object_name"))
            if not r.get("referencing_object_name") or not r.get("referenced_object_name"):
                continue
            dependencies.append(
                {
                    "referencing_fqn": ring,
                    "referencing_domain": str(r.get("referencing_object_domain", "")),
                    "referenced_fqn": red,
                    "referenced_domain": str(r.get("referenced_object_domain", "")),
                    "dependency_type": str(r.get("dependency_type", "")),
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not query OBJECT_DEPENDENCIES: {sanitize_error(exc)}")
    finally:
        cursor.close()
    return dependencies


def _discover_sf_grants(conn: Any, warnings: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Object-level role grants + user→role memberships (the CIEM access graph).

    ``GRANTS_TO_ROLES`` (filtered to TABLE/VIEW) → a role's privilege on an
    object; ``GRANTS_TO_USERS`` → a user's role memberships. Read-only metadata.
    """
    grants: list[dict[str, Any]] = []
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT grantee_name, privilege, granted_on, name, table_catalog, table_schema "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES "
            "WHERE deleted_on IS NULL AND granted_on IN ('TABLE', 'VIEW') "
            "ORDER BY grantee_name LIMIT 100000"
        )
        keys = [d[0].lower() for d in cursor.description] if cursor.description else []
        for row in cursor.fetchall():
            r = dict(zip(keys, row))
            role = str(r.get("grantee_name", ""))
            db, sch, nm = str(r.get("table_catalog", "")), str(r.get("table_schema", "")), str(r.get("name", ""))
            if not role or not nm:
                continue
            grants.append(
                {
                    "role": role,
                    "privilege": str(r.get("privilege", "")),
                    "object_fqn": f"{db}.{sch}.{nm}",
                    "object_type": str(r.get("granted_on", "")).lower(),
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not query GRANTS_TO_ROLES: {sanitize_error(exc)}")
    finally:
        cursor.close()

    memberships: list[dict[str, Any]] = []
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT grantee_name, role FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS "
            "WHERE deleted_on IS NULL ORDER BY grantee_name LIMIT 10000"
        )
        keys = [d[0].lower() for d in cursor.description] if cursor.description else []
        for row in cursor.fetchall():
            r = dict(zip(keys, row))
            user_name, role = str(r.get("grantee_name", "")), str(r.get("role", ""))
            if user_name and role:
                memberships.append({"user": user_name, "role": role})
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not query GRANTS_TO_USERS: {sanitize_error(exc)}")
    finally:
        cursor.close()

    return grants, memberships


def discover_object_dependencies(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> dict[str, Any]:
    """Discover the Snowflake object + dependency + permission graph (read-only).

    Tables and views become DATA_STORE graph nodes; OBJECT_DEPENDENCIES become
    DEPENDS_ON edges (referencing → referenced). Object-level role grants become
    HAS_PERMISSION edges (role → object) and user→role memberships become
    ASSUMES edges. Read-only, control-plane metadata only — never row data.

    Returns a payload with ``status`` (``"ok"`` / ``"disabled"`` /
    ``"no_account"``), ``objects``, ``dependencies``, ``grants``,
    ``role_memberships``, and ``warnings``.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake object discovery. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    result: dict[str, Any] = {
        "status": "disabled",
        "account": resolved_account,
        "objects": [],
        "dependencies": [],
        "grants": [],
        "role_memberships": [],
        "warnings": [],
    }
    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "no_account"
        warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return result

    try:
        conn = _get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        result["objects"] = _discover_sf_objects(conn, warnings)
        result["dependencies"] = _discover_sf_dependencies(conn, warnings)
        result["grants"], result["role_memberships"] = _discover_sf_grants(conn, warnings)
        result["status"] = "ok"
    finally:
        conn.close()
    return result


# SHOW-based identity discovery reflects current state with no latency, unlike
# ACCOUNT_USAGE.GRANTS_TO_* which lags 45min–2h. Object-level grants we surface
# (so a freshly-created role hierarchy is graphed immediately).
_LIVE_GRANT_OBJECT_TYPES = {"TABLE", "VIEW", "MATERIALIZED VIEW", "DYNAMIC TABLE", "EXTERNAL TABLE", "ICEBERG TABLE"}
# Default bound on the per-role SHOW GRANTS fan-out so a pathological account
# can't stall a scan; override with AGENT_BOM_SNOWFLAKE_MAX_ROLES.
_LIVE_MAX_ROLES = 2000


def discover_identity_live(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> dict[str, Any]:
    """Discover the Snowflake identity graph via SHOW commands (zero latency).

    ``ACCOUNT_USAGE.GRANTS_TO_ROLES`` / ``GRANTS_TO_USERS`` / role-membership
    views lag 45min–2h, so a just-created role hierarchy is invisible on a live
    scan. SHOW commands reflect current account state instantly. All read-only,
    control-plane metadata only — NO passwords or secrets leave Snowflake.

    Queries (all current-state, no ``ACCOUNT_USAGE`` lag):

    * ``SHOW ROLES`` → the role list (capped at ``_LIVE_MAX_ROLES``).
    * For each role: ``SHOW GRANTS TO ROLE "<role>"`` → object privilege grants
      (privilege / granted_on / name) and role→role grants; ``SHOW GRANTS OF
      ROLE "<role>"`` → who the role is granted to (users + roles) = memberships.
    * ``SHOW USERS`` → user metadata (name / default_role / disabled only).

    Returns a payload whose ``grants`` / ``role_memberships`` reuse the
    :func:`discover_object_dependencies` shape so the graph builder's existing
    Snowflake identity wiring consumes it unchanged. ``role_memberships`` carry
    an optional ``parent``/``member_type`` so role→role edges build too.

    Per-role failures degrade to warnings; the function never raises into a scan.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake identity discovery. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    result: dict[str, Any] = {
        "status": "disabled",
        "account": resolved_account,
        "users": [],
        "roles": [],
        "role_memberships": [],
        "grants": [],
        "warnings": [],
    }
    warnings_list: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "no_account"
        warnings_list.append("SNOWFLAKE_ACCOUNT not set.")
        return result

    try:
        conn = _get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings_list.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        roles = _live_show_roles(conn, warnings_list)
        result["roles"] = roles
        result["users"] = _live_show_users(conn, warnings_list)
        grants, memberships = _live_role_grants(conn, [r["name"] for r in roles], warnings_list)
        result["grants"] = grants
        result["role_memberships"] = memberships
        result["status"] = "ok"
    finally:
        conn.close()
    return result


def _live_show_roles(conn: Any, warnings_list: list[str]) -> list[dict[str, Any]]:
    """``SHOW ROLES`` → current role list (name / owner / comment).

    Bounded by ``AGENT_BOM_SNOWFLAKE_MAX_ROLES`` (default ``_LIVE_MAX_ROLES``) so
    large accounts can raise it; hitting the bound emits a warning rather than a
    silent truncation.
    """
    try:
        cap = max(1, int(os.environ.get("AGENT_BOM_SNOWFLAKE_MAX_ROLES", "") or _LIVE_MAX_ROLES))
    except ValueError:
        cap = _LIVE_MAX_ROLES
    roles: list[dict[str, Any]] = []
    cursor = conn.cursor()
    try:
        cursor.execute("SHOW ROLES")
        keys = [d[0].lower() for d in cursor.description] if cursor.description else []
        for row in cursor.fetchall():
            r = dict(zip(keys, row))
            name = str(r.get("name", "") or "")
            if not name:
                continue
            roles.append({"name": name, "owner": str(r.get("owner", "") or ""), "comment": str(r.get("comment", "") or "")})
            if len(roles) >= cap:
                warnings_list.append(f"SHOW ROLES truncated at {cap} roles; raise AGENT_BOM_SNOWFLAKE_MAX_ROLES to see more.")
                break
    except Exception as exc:  # noqa: BLE001
        warnings_list.append(f"Could not list roles (SHOW ROLES): {sanitize_error(exc)}")
    finally:
        cursor.close()
    return roles


def _live_show_users(conn: Any, warnings_list: list[str]) -> list[dict[str, Any]]:
    """``SHOW USERS`` → user metadata only (name / default_role / disabled).

    NO passwords or secrets are read — only the columns the graph needs.
    """
    users: list[dict[str, Any]] = []
    cursor = conn.cursor()
    try:
        cursor.execute("SHOW USERS")
        keys = [d[0].lower() for d in cursor.description] if cursor.description else []
        for row in cursor.fetchall():
            r = dict(zip(keys, row))
            name = str(r.get("name", "") or "")
            if not name:
                continue
            users.append(
                {
                    "name": name,
                    "default_role": str(r.get("default_role", "") or ""),
                    "disabled": _sf_truthy(r.get("disabled")),
                }
            )
    except Exception as exc:  # noqa: BLE001
        # MANAGE GRANTS / USERADMIN may be absent; not fatal.
        warnings_list.append(f"Could not list users (SHOW USERS): {sanitize_error(exc)}")
    finally:
        cursor.close()
    return users


def _live_role_grants(conn: Any, role_names: list[str], warnings_list: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Per-role ``SHOW GRANTS TO/OF ROLE`` → object grants + memberships.

    ``SHOW GRANTS TO ROLE "<role>"`` yields the role's privileges: object grants
    (``granted_on`` a TABLE/VIEW/...) become ``grants`` (role HAS_PERMISSION on
    object); ``granted_on=ROLE`` becomes a role→role membership (this role is a
    member of the granted parent role). ``SHOW GRANTS OF ROLE "<role>"`` yields
    who the role is granted to (users → ``{user, role}``; roles → role→role).
    """
    grants: list[dict[str, Any]] = []
    memberships: list[dict[str, Any]] = []
    # Dedupe so the two SHOW directions don't double-emit the same role→role edge.
    seen_member: set[tuple[str, str]] = set()
    seen_user: set[tuple[str, str]] = set()
    seen_grant: set[tuple[str, str, str]] = set()

    def _add_role_membership(child: str, parent: str) -> None:
        if not child or not parent or child == parent:
            return
        key = (child, parent)
        if key in seen_member:
            return
        seen_member.add(key)
        memberships.append({"role": child, "parent": parent, "member_type": "role"})

    def _add_user_membership(user_name: str, role: str) -> None:
        if not user_name or not role:
            return
        key = (user_name, role)
        if key in seen_user:
            return
        seen_user.add(key)
        memberships.append({"user": user_name, "role": role, "member_type": "user"})

    for role_name in role_names:
        try:
            quoted = _quote_sf_identifier(role_name)
        except ValueError as exc:
            warnings_list.append(f"Skipping unsafe role identifier: {sanitize_error(exc)}")
            continue

        # Privileges this role holds: object grants + role→role parents.
        cursor = conn.cursor()
        try:
            cursor.execute(f"SHOW GRANTS TO ROLE {quoted}")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                granted_on = str(r.get("granted_on", "") or "").upper()
                privilege = str(r.get("privilege", "") or "")
                obj_name = str(r.get("name", "") or "")
                if granted_on == "ROLE" and privilege.upper() == "USAGE" and obj_name:
                    # This role USAGE-on another role => member of that parent role.
                    _add_role_membership(role_name, obj_name)
                elif granted_on in _LIVE_GRANT_OBJECT_TYPES and obj_name:
                    gkey = (role_name, privilege, obj_name)
                    if gkey in seen_grant:
                        continue
                    seen_grant.add(gkey)
                    grants.append(
                        {
                            "role": role_name,
                            "privilege": privilege,
                            "object_fqn": obj_name,
                            "object_type": granted_on.lower(),
                        }
                    )
        except Exception as exc:  # noqa: BLE001
            warnings_list.append(f"Could not read grants TO role {role_name!r}: {sanitize_error(exc)}")
        finally:
            cursor.close()

        # Who this role is granted to: users (memberships) + child roles.
        cursor = conn.cursor()
        try:
            cursor.execute(f"SHOW GRANTS OF ROLE {quoted}")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                granted_to = str(r.get("granted_to", "") or "").upper()
                grantee = str(r.get("grantee_name", "") or "")
                if not grantee:
                    continue
                if granted_to == "USER":
                    _add_user_membership(grantee, role_name)
                elif granted_to == "ROLE":
                    # The grantee role is a member of this role (grantee → role_name).
                    _add_role_membership(grantee, role_name)
        except Exception as exc:  # noqa: BLE001
            warnings_list.append(f"Could not read grants OF role {role_name!r}: {sanitize_error(exc)}")
        finally:
            cursor.close()

    return grants, memberships


def merge_live_identity_into_object_graph(object_graph: dict[str, Any], live: dict[str, Any]) -> dict[str, Any]:
    """Merge zero-latency SHOW identity into the (lagged) object-graph payload.

    Live SHOW data is preferred over the ACCOUNT_USAGE rows: grants and
    memberships from *live* replace any overlapping lagged rows and are then
    unioned with the remainder, deduped. ``users`` (live-only) are carried
    through so freshly-created users graph immediately. Mutates and returns
    *object_graph*. A non-ok *live* payload is a no-op passthrough.
    """
    if not isinstance(object_graph, dict):
        return object_graph
    if not isinstance(live, dict) or live.get("status") != "ok":
        return object_graph

    # Grants keyed by (role, privilege, object_fqn); live wins on collision.
    def _grant_key(g: dict[str, Any]) -> tuple[str, str, str]:
        return (str(g.get("role", "")), str(g.get("privilege", "")), str(g.get("object_fqn", "")))

    merged_grants: dict[tuple[str, str, str], dict[str, Any]] = {}
    for g in object_graph.get("grants", []) or []:
        if isinstance(g, dict):
            merged_grants[_grant_key(g)] = g
    for g in live.get("grants", []) or []:
        if isinstance(g, dict):
            merged_grants[_grant_key(g)] = g  # live overwrites lagged
    object_graph["grants"] = list(merged_grants.values())

    # Memberships: user→role keyed (user, role); role→role keyed (role, parent).
    def _mem_key(m: dict[str, Any]) -> tuple[str, str, str]:
        if m.get("member_type") == "role" or m.get("parent"):
            return ("role", str(m.get("role", "")), str(m.get("parent", "")))
        return ("user", str(m.get("user", "")), str(m.get("role", "")))

    merged_mem: dict[tuple[str, str, str], dict[str, Any]] = {}
    for m in object_graph.get("role_memberships", []) or []:
        if isinstance(m, dict):
            merged_mem[_mem_key(m)] = m
    for m in live.get("role_memberships", []) or []:
        if isinstance(m, dict):
            merged_mem[_mem_key(m)] = m  # live overwrites lagged
    object_graph["role_memberships"] = list(merged_mem.values())

    # Users are live-only (object graph never had them); carry through, deduped.
    if live.get("users"):
        existing = {str(u.get("name", "")) for u in object_graph.get("users", []) or [] if isinstance(u, dict)}
        users = list(object_graph.get("users", []) or [])
        for u in live["users"]:
            if isinstance(u, dict) and str(u.get("name", "")) not in existing:
                users.append(u)
                existing.add(str(u.get("name", "")))
        object_graph["users"] = users

    return object_graph


_EXTERNAL_STAGE_SCHEMES = {"s3": "aws", "s3gov": "aws", "azure": "azure", "gcs": "gcp"}


def discover_data_exfil(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> dict[str, Any]:
    """Discover Snowflake data-exfiltration surfaces (read-only).

    Three egress surfaces, summarized (no row data leaves Snowflake):

    * **Outbound shares** — data shared to consumer accounts (`SHOW SHARES`,
      identified by ``target_accounts``).
    * **External stages** — off-account storage reachable by ``COPY INTO``
      (`SHOW STAGES IN ACCOUNT`, external ``s3://`` / ``azure://`` / ``gcs://``
      URLs). The destination bucket id matches what an AWS/Azure/GCP scan emits,
      so the graph **stitches Snowflake to the actual cloud storage node**.
    * **Sensitive objects** — tables/columns tagged PII/PHI/etc.
      (`ACCOUNT_USAGE.TAG_REFERENCES`) and whether a masking/row-access policy
      protects them (`POLICY_REFERENCES`).

    Returns a payload with ``status``, ``outbound_shares``, ``external_stages``,
    ``sensitive_objects``, derived ``findings``, and ``warnings``.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake exfil discovery. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    result: dict[str, Any] = {
        "status": "disabled",
        "account": resolved_account,
        "outbound_shares": [],
        "external_stages": [],
        "sensitive_objects": [],
        "findings": [],
        "warnings": [],
    }
    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "no_account"
        warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return result

    try:
        conn = _get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        # Outbound shares.
        cursor = conn.cursor()
        try:
            cursor.execute("SHOW SHARES")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                if str(r.get("kind", "")).upper() != "OUTBOUND":
                    continue
                consumers = [c.strip() for c in re.split(r"[,\s]+", str(r.get("to", "") or "")) if c.strip()]
                result["outbound_shares"].append(
                    {
                        "share_name": str(r.get("name", "")),
                        "database_name": str(r.get("database_name", "")),
                        "consumers": consumers,
                        "is_marketplace": bool(str(r.get("listing_global_name", "") or "")),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list outbound shares: {sanitize_error(exc)}")
        finally:
            cursor.close()

        # External stages.
        cursor = conn.cursor()
        try:
            cursor.execute("SHOW STAGES IN ACCOUNT")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                url = str(r.get("url", "") or "")
                if "://" not in url:
                    continue
                scheme = url.split("://", 1)[0].lower()
                cloud = _EXTERNAL_STAGE_SCHEMES.get(scheme, "")
                if not cloud:
                    continue
                bucket = url.split("://", 1)[1].split("/", 1)[0]
                result["external_stages"].append(
                    {
                        "stage_name": str(r.get("name", "")),
                        "database_name": str(r.get("database_name", "")),
                        "schema_name": str(r.get("schema_name", "")),
                        "url": url,
                        "cloud_provider": cloud,
                        "bucket": bucket,
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list external stages: {sanitize_error(exc)}")
        finally:
            cursor.close()

        # Sensitive objects (tagged) + masking/row-access coverage.
        protected: set[str] = set()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT ref_database_name, ref_schema_name, ref_entity_name "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES "
                "WHERE policy_kind IN ('MASKING_POLICY', 'ROW_ACCESS_POLICY') LIMIT 5000"
            )
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                protected.add(".".join(str(r.get(k, "")) for k in ("ref_database_name", "ref_schema_name", "ref_entity_name")).upper())
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not query POLICY_REFERENCES: {sanitize_error(exc)}")
        finally:
            cursor.close()

        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT object_database, object_schema, object_name, "
                "       COUNT(DISTINCT tag_name) AS tags, COUNT(DISTINCT column_name) AS cols "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES "
                "WHERE tag_name ILIKE ANY ('%PII%', '%PHI%', '%SENSITIVE%', '%CONFIDENTIAL%', "
                "      '%FINANCIAL%', '%CLASSIFICATION%', '%PRIVACY%', '%SEMANTIC_CATEGORY%') "
                "GROUP BY 1, 2, 3 LIMIT 5000"
            )
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                fqn = ".".join(str(r.get(k, "")) for k in ("object_database", "object_schema", "object_name"))
                result["sensitive_objects"].append(
                    {
                        "fqn": fqn,
                        "tagged_columns": int(r.get("cols", 0) or 0),
                        "tag_count": int(r.get("tags", 0) or 0),
                        "is_protected": fqn.upper() in protected,
                        "sensitivity": "sensitive",
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not query TAG_REFERENCES: {sanitize_error(exc)}")
        finally:
            cursor.close()

        for s in result["outbound_shares"]:
            result["findings"].append(
                {
                    "severity": "high" if s["is_marketplace"] else "medium",
                    "title": "Outbound data share",
                    "detail": f"Share {s['share_name']} exposes data to {len(s['consumers'])} consumer account(s)"
                    + (" via a public Marketplace listing" if s["is_marketplace"] else "")
                    + ".",
                }
            )
        for st in result["external_stages"]:
            result["findings"].append(
                {
                    "severity": "medium",
                    "title": "External stage (exfil destination)",
                    "detail": f"Stage {st['stage_name']} writes to {st['cloud_provider']} bucket '{st['bucket']}'.",
                }
            )
        unprotected = [s["fqn"] for s in result["sensitive_objects"] if not s["is_protected"]]
        if unprotected:
            result["findings"].append(
                {
                    "severity": "high",
                    "title": "Unprotected sensitive data",
                    "detail": f"{len(unprotected)} sensitivity-tagged object(s) have no masking/row-access policy.",
                }
            )
        result["status"] = "ok"
    finally:
        conn.close()
    return result


def discover_login_anomalies(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
    days: int = 7,
    rapid_switch_minutes: int = 10,
    max_distinct_ips: int = 20,
    failed_burst_threshold: int = 5,
) -> dict[str, Any]:
    """Detect Snowflake login anomalies from LOGIN_HISTORY (read-only).

    Three identity-threat signals, all summarized server-side (no raw IPs/PII
    leave Snowflake):

    * **Impossible travel** — the same user logging in from a *different* client
      IP within ``rapid_switch_minutes`` of a prior successful login. Switching
      source IPs faster than one can physically travel is the classic signal
      (geo distance would refine it, but the rapid-IP-switch heuristic needs no
      external GeoIP data).
    * **High distinct-IP count** — a user authenticating from more than
      ``max_distinct_ips`` distinct addresses in the window.
    * **Failed-login bursts** — a user with at least ``failed_burst_threshold``
      failed logins (brute-force / credential-stuffing pressure).

    Returns a payload with ``status``, ``per_user`` summaries, ``impossible_travel``,
    ``failed_bursts``, derived ``findings``, and ``warnings``.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake login anomaly detection. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    days = _coerce_snowflake_days(days, max_days=365)
    result: dict[str, Any] = {
        "status": "disabled",
        "account": resolved_account,
        "window_days": days,
        "per_user": [],
        "impossible_travel": [],
        "failed_bursts": [],
        "findings": [],
        "warnings": [],
    }
    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "no_account"
        warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return result

    try:
        conn = _get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT user_name, COUNT(DISTINCT client_ip) AS distinct_ips, COUNT(*) AS logins, "
                "       SUM(IFF(is_success = 'NO', 1, 0)) AS failed "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY "
                f"WHERE event_timestamp >= DATEADD(day, -{days}, CURRENT_TIMESTAMP()) "  # nosec B608 — int day window
                "GROUP BY user_name ORDER BY distinct_ips DESC LIMIT 1000"
            )
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                distinct_ips = int(r.get("distinct_ips", 0) or 0)
                failed = int(r.get("failed", 0) or 0)
                entry = {
                    "user": str(r.get("user_name", "")),
                    "distinct_ips": distinct_ips,
                    "logins": int(r.get("logins", 0) or 0),
                    "failed": failed,
                }
                result["per_user"].append(entry)
                if failed >= failed_burst_threshold:
                    result["failed_bursts"].append({"user": entry["user"], "failed": failed})
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not summarize LOGIN_HISTORY: {sanitize_error(exc)}")
        finally:
            cursor.close()

        # Impossible travel: consecutive successful logins from a different IP
        # within rapid_switch_minutes (computed server-side via LAG).
        cursor = conn.cursor()
        try:
            cursor.execute(
                "WITH ordered AS ( "
                "  SELECT user_name, client_ip, event_timestamp, "
                "         LAG(client_ip) OVER (PARTITION BY user_name ORDER BY event_timestamp) AS prev_ip, "
                "         LAG(event_timestamp) OVER (PARTITION BY user_name ORDER BY event_timestamp) AS prev_ts "
                "  FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY "
                f"  WHERE is_success = 'YES' AND event_timestamp >= DATEADD(day, -{days}, CURRENT_TIMESTAMP()) "  # nosec B608
                ") "
                "SELECT user_name, COUNT(*) AS rapid_switches "
                "FROM ordered "
                "WHERE prev_ip IS NOT NULL AND client_ip != prev_ip "
                f"  AND TIMESTAMPDIFF(minute, prev_ts, event_timestamp) <= {rapid_switch_minutes} "  # nosec B608
                "GROUP BY user_name HAVING COUNT(*) > 0 ORDER BY rapid_switches DESC LIMIT 1000"
            )
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                result["impossible_travel"].append(
                    {"user": str(r.get("user_name", "")), "rapid_switches": int(r.get("rapid_switches", 0) or 0)}
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not compute impossible-travel signal: {sanitize_error(exc)}")
        finally:
            cursor.close()

        for it in result["impossible_travel"]:
            result["findings"].append(
                {
                    "severity": "high",
                    "title": "Possible impossible travel",
                    "detail": f"User {it['user']} switched source IP within {rapid_switch_minutes} min "
                    f"{it['rapid_switches']} time(s) — faster than physical travel.",
                }
            )
        for u in result["per_user"]:
            if u["distinct_ips"] > max_distinct_ips:
                result["findings"].append(
                    {
                        "severity": "medium",
                        "title": "High distinct source-IP count",
                        "detail": f"User {u['user']} logged in from {u['distinct_ips']} distinct IPs in {days} days.",
                    }
                )
        for b in result["failed_bursts"]:
            result["findings"].append(
                {
                    "severity": "medium",
                    "title": "Failed-login burst",
                    "detail": f"User {b['user']} had {b['failed']} failed logins (brute-force / stuffing pressure).",
                }
            )
        result["status"] = "ok"
    finally:
        conn.close()
    return result


def discover_auth_posture(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> dict[str, Any]:
    """Inventory Snowflake authentication posture (read-only).

    The preventive complement to :func:`discover_login_anomalies` (which is
    detective). Two surfaces:

    * **Per-user auth matrix** — for each enabled user, which credential types
      exist (password / key-pair / federated SSO), whether MFA is enrolled
      (``ext_authn_duo``), and whether a network policy is bound
      (`ACCOUNT_USAGE.USERS`).
    * **Network policies** — IP allow/block lists and whether one is applied at
      the account level (`SHOW NETWORK POLICIES` + the ``NETWORK_POLICY``
      account parameter).

    Surfaces concrete exposures: password users without MFA, human users not
    behind any network policy, and an account with no default network policy.

    Returns ``status``, ``account``, ``users``, ``network_policies``,
    ``account_network_policy``, ``findings``, ``warnings``. Never leaks
    credential material — only boolean capability flags.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake auth-posture discovery. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    result: dict[str, Any] = {
        "status": "disabled",
        "account": resolved_account,
        "users": [],
        "network_policies": [],
        "account_network_policy": None,
        "findings": [],
        "warnings": [],
    }
    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "no_account"
        warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return result

    try:
        conn = _get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        # Account-level default network policy.
        cursor = conn.cursor()
        try:
            cursor.execute("SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                val = str(r.get("value", "") or "")
                if val:
                    result["account_network_policy"] = val
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not read account network policy: {sanitize_error(exc)}")
        finally:
            cursor.close()

        # Network policies (allow/block IP ranges).
        cursor = conn.cursor()
        try:
            cursor.execute("SHOW NETWORK POLICIES")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                result["network_policies"].append(
                    {
                        "name": str(r.get("name", "")),
                        "allowed_ip_count": int(r.get("entries_in_allowed_ip_list", 0) or 0),
                        "blocked_ip_count": int(r.get("entries_in_blocked_ip_list", 0) or 0),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list network policies: {sanitize_error(exc)}")
        finally:
            cursor.close()

        # Per-user auth matrix.
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT name, disabled, has_password, has_rsa_public_key, ext_authn_duo, "
                "       default_role, type, has_mfa "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.USERS "
                "WHERE deleted_on IS NULL LIMIT 10000"
            )
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                name = str(r.get("name", ""))
                if not name:
                    continue
                disabled = _sf_truthy(r.get("disabled"))
                has_password = _sf_truthy(r.get("has_password"))
                has_key_pair = _sf_truthy(r.get("has_rsa_public_key"))
                # MFA: ext_authn_duo (Duo) or the newer has_mfa column when present.
                has_mfa = _sf_truthy(r.get("ext_authn_duo")) or _sf_truthy(r.get("has_mfa"))
                user_type = str(r.get("type", "") or "").upper()  # PERSON / SERVICE / LEGACY_SERVICE / NULL
                auth_methods = []
                if has_password:
                    auth_methods.append("password")
                if has_key_pair:
                    auth_methods.append("key_pair")
                if not auth_methods:
                    auth_methods.append("federated_or_none")
                result["users"].append(
                    {
                        "name": name,
                        "disabled": disabled,
                        "auth_methods": auth_methods,
                        "has_mfa": has_mfa,
                        "user_type": user_type or "UNKNOWN",
                        "default_role": str(r.get("default_role", "") or ""),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not query USERS auth matrix: {sanitize_error(exc)}")
        finally:
            cursor.close()

        # Findings.
        if result["users"] and not result["account_network_policy"]:
            result["findings"].append(
                {
                    "severity": "medium",
                    "title": "No account-level network policy",
                    "detail": "No default NETWORK_POLICY is set at the account level; logins are not IP-restricted by default.",
                }
            )
        # Password users without MFA (skip disabled + non-person service identities,
        # which legitimately use key-pair/OAuth and cannot enroll interactive MFA).
        weak = [
            u["name"]
            for u in result["users"]
            if not u["disabled"] and "password" in u["auth_methods"] and not u["has_mfa"] and u["user_type"] in ("PERSON", "UNKNOWN", "")
        ]
        if weak:
            result["findings"].append(
                {
                    "severity": "high",
                    "title": "Password users without MFA",
                    "detail": f"{len(weak)} enabled human user(s) authenticate with a password and have no MFA enrolled.",
                }
            )
        result["status"] = "ok"
    finally:
        conn.close()
    return result


def discover_snowflake_services(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> dict[str, Any]:
    """Inventory Snowflake compute + the database/schema containment hierarchy (read-only).

    Completes the object catalog beyond tables/views: the **warehouses** that run
    queries (the compute service) and the **database → schema** containers that
    organize the data. With the object graph's table/view nodes, this lets the
    graph render a navigable DB → schema → table tree and surface compute.

    * Warehouses — `SHOW WAREHOUSES`: size, state, auto-suspend.
    * Databases — `SHOW DATABASES`: owner, retention (time-travel) window.
    * Schemas — `SHOW SCHEMAS IN ACCOUNT`: parent database.

    Returns ``status``, ``account``, ``warehouses``, ``databases``, ``schemas``,
    ``findings``, ``warnings``. Never leaks data — only object metadata.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake service discovery. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    result: dict[str, Any] = {
        "status": "disabled",
        "account": resolved_account,
        "warehouses": [],
        "databases": [],
        "schemas": [],
        "findings": [],
        "warnings": [],
    }
    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "no_account"
        warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return result

    try:
        conn = _get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        cursor = conn.cursor()
        try:
            cursor.execute("SHOW WAREHOUSES")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                name = str(r.get("name", ""))
                if not name:
                    continue
                result["warehouses"].append(
                    {
                        "name": name,
                        "size": str(r.get("size", "") or ""),
                        "state": str(r.get("state", "") or ""),
                        "auto_suspend": _coerce_int_or_none(r.get("auto_suspend")),
                        "type": str(r.get("type", "") or "STANDARD"),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list warehouses: {sanitize_error(exc)}")
        finally:
            cursor.close()

        cursor = conn.cursor()
        try:
            cursor.execute("SHOW DATABASES")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                name = str(r.get("name", ""))
                if not name:
                    continue
                result["databases"].append(
                    {
                        "name": name,
                        "owner": str(r.get("owner", "") or ""),
                        "retention_time": _coerce_int_or_none(r.get("retention_time")),
                        "is_default": str(r.get("is_default", "") or "").upper() in ("Y", "YES", "TRUE"),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list databases: {sanitize_error(exc)}")
        finally:
            cursor.close()

        cursor = conn.cursor()
        try:
            cursor.execute("SHOW SCHEMAS IN ACCOUNT")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                name = str(r.get("name", ""))
                db = str(r.get("database_name", "") or "")
                if not name or not db:
                    continue
                if name in ("INFORMATION_SCHEMA",):
                    continue
                result["schemas"].append({"name": name, "database_name": db, "fqn": f"{db}.{name}", "owner": str(r.get("owner", "") or "")})
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list schemas: {sanitize_error(exc)}")
        finally:
            cursor.close()

        warehouses: list[dict[str, Any]] = result["warehouses"]
        for wh_item in warehouses:
            if wh_item["auto_suspend"] in (None, 0):
                result["findings"].append(
                    {
                        "severity": "low",
                        "title": "Warehouse without auto-suspend",
                        "detail": f"Warehouse {wh_item['name']} has no auto-suspend; it accrues compute cost while idle.",
                    }
                )
        databases: list[dict[str, Any]] = result["databases"]
        for db_item in databases:
            if db_item["retention_time"] == 0:
                result["findings"].append(
                    {
                        "severity": "low",
                        "title": "Database without time-travel retention",
                        "detail": f"Database {db_item['name']} has 0-day retention; dropped/changed data cannot be recovered.",
                    }
                )
        result["status"] = "ok"
    finally:
        conn.close()
    return result


# Substrings that mark an ORGADMIN-privilege / not-in-org failure of
# ``SHOW ORGANIZATION ACCOUNTS`` rather than a transient connection error. Used to
# distinguish "this role can't see the org" (a clean degrade) from "the org has a
# single account". Matched case-insensitively against the sanitized error text.
_SF_ORG_NOT_AUTHORIZED_MARKERS: tuple[str, ...] = (
    "orgadmin",
    "insufficient privileges",
    "not authorized",
    "unsupported feature",
    "does not exist or not authorized",
    "organization",
)


def discover_organization(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    *,
    force: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    """Enumerate the Snowflake Organization → member accounts roll-up (read-only).

    The Snowflake analogue of the GCP Organization → Folders → Projects and AWS
    Organizations → OU → Account hierarchies: multiple Snowflake accounts roll up
    under a parent ORGANIZATION node so the estate is traversable top-down. Uses
    ``SHOW ORGANIZATION ACCOUNTS`` to read the org name and its member accounts.

    Returns a payload destined for ``report_json`` (carried on the Snowflake
    services payload under ``organization``) with a ``status``:

    - ``"disabled"``       — the org flag is off and ``force`` was not set.
    - ``"sdk_missing"``    — snowflake-connector-python is not installed.
    - ``"not_authorized"`` — the connected role lacks ORGADMIN (the read-only
      ``ABOM_READONLY`` role typically does); single-account scanning still works.
    - ``"not_in_org"``     — the account is standalone (no organization visible).
    - ``"ok"``             — enumeration ran (possibly with per-call warnings).

    Read-only (``SHOW`` only — no writes), opt-in (``AGENT_BOM_SNOWFLAKE_ORG`` or
    ``force``), and crash-safe: SDK absence, missing ORGADMIN, connection / auth /
    SQL errors all degrade to a clear status plus an actionable warning. Never
    raises; a single account graphs exactly as it does today when this no-ops.

    ``now`` (an ISO-8601 string) is injected for the ``discovered_at`` stamp so
    the payload is deterministic under test; callers pass a clock value rather
    than the discoverer reading wall-clock time inline.
    """
    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    result: dict[str, Any] = {
        "status": "disabled",
        "org_name": "",
        "accounts": [],
        "findings": [],
        "warnings": [],
        "discovered_at": now or "",
        "discovery_envelope": None,
    }
    if not force and not org_enabled():
        return result

    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        result["status"] = "sdk_missing"
        result["warnings"] = [
            "snowflake-connector-python is required for Snowflake org inventory. Install with: pip install 'agent-bom[snowflake]'"
        ]
        return result

    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "not_in_org"
        warnings.append("SNOWFLAKE_ACCOUNT not set; cannot enumerate the organization. Single-account scanning is unaffected.")
        return result

    try:
        conn = _get_connection(account, user, authenticator)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001 — connection failure degrades, never crashes the scan
        warnings.append(f"Could not connect to Snowflake for org inventory: {sanitize_error(exc)}")
        return result

    try:
        cursor = conn.cursor()
        try:
            # SHOW ORGANIZATION ACCOUNTS requires the ORGADMIN role. The read-only
            # ABOM_READONLY role usually lacks it, so a privilege error here is the
            # expected, graceful degrade — not a scan failure.
            cursor.execute("SHOW ORGANIZATION ACCOUNTS")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                if len(result["accounts"]) >= _MAX_ORG_ACCOUNTS:
                    warnings.append(
                        f"Snowflake org enumeration capped at {_MAX_ORG_ACCOUNTS} accounts (set AGENT_BOM_SNOWFLAKE_MAX_ACCOUNTS to raise)."
                    )
                    break
                r = dict(zip(keys, row))
                locator = str(r.get("account_locator", "") or r.get("account_name", "") or r.get("name", "") or "").strip()
                if not locator:
                    continue
                org_name = str(r.get("organization_name", "") or "").strip()
                if org_name and not result["org_name"]:
                    result["org_name"] = org_name
                result["accounts"].append(
                    {
                        "locator": locator,
                        "name": str(r.get("account_name", "") or r.get("name", "") or locator).strip(),
                        "region": str(r.get("snowflake_region", "") or r.get("region", "") or "").strip(),
                        "edition": str(r.get("edition", "") or "").strip(),
                        "is_org_admin": str(r.get("is_org_admin", "") or "").strip().upper() in ("Y", "YES", "TRUE"),
                    }
                )
        except Exception as exc:  # noqa: BLE001 — missing ORGADMIN / not-in-org degrades cleanly
            message = sanitize_error(exc)
            lowered = message.lower()
            if any(marker in lowered for marker in _SF_ORG_NOT_AUTHORIZED_MARKERS):
                result["status"] = "not_authorized"
                warnings.append(
                    "SHOW ORGANIZATION ACCOUNTS requires the ORGADMIN role, which the connected "
                    "(read-only) role lacks. Grant ORGADMIN to enumerate the organization, or "
                    f"continue single-account scanning (unaffected). Detail: {message}"
                )
            else:
                warnings.append(f"Could not enumerate Snowflake organization accounts: {message}")
            return result
        finally:
            cursor.close()
    finally:
        conn.close()

    if not result["accounts"]:
        # Connected fine and ORGADMIN-capable but the account is standalone.
        result["status"] = "not_in_org"
        if resolved_account not in {a["locator"] for a in result["accounts"]}:
            warnings.append("No organization accounts visible; the account appears standalone. Single-account scanning is unaffected.")
        return result

    if not result["org_name"]:
        result["org_name"] = "organization"

    _derive_org_findings(result)
    result["status"] = "ok"
    result["discovery_envelope"] = DiscoveryEnvelope(
        scan_mode=ScanMode.SAAS_READ_ONLY,
        discovery_scope=(f"snowflake:organization/{result['org_name']}",),
        permissions_used=_SF_ORG_PERMISSIONS,
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    ).to_dict()
    return result


def _derive_org_findings(result: dict[str, Any]) -> None:
    """Flag cheap org-shape posture signals, mirroring the GCP org findings."""
    accounts = result.get("accounts", []) or []
    if len(accounts) > 1:
        result["findings"].append(
            {
                "severity": "info",
                "title": "Multi-account Snowflake organization",
                "detail": (
                    f"{len(accounts)} accounts roll up under organization "
                    f"'{result.get('org_name') or 'organization'}'. Org-wide policies and "
                    "least-privilege should be reviewed across every member account."
                ),
            }
        )
    if accounts and not any(a.get("is_org_admin") for a in accounts):
        result["findings"].append(
            {
                "severity": "low",
                "title": "No ORGADMIN account flagged",
                "detail": ("No member account is marked as the ORGADMIN account; organization-level governance ownership is unclear."),
            }
        )


def _split_fqn_parts(name: str, database: str, schema: str) -> str:
    """Build a DB.SCHEMA.NAME fqn from SHOW-command columns, tolerating blanks."""
    parts = [p for p in (database, schema, name) if p]
    return ".".join(parts)


def discover_snowflake_pipeline(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> dict[str, Any]:
    """Inventory Snowflake data-pipeline + automation objects (read-only).

    The data-movement layer the object graph was missing:

    * **Tasks** (`SHOW TASKS IN ACCOUNT`) — scheduled SQL. Carries the warehouse
      it runs on and the role it runs as (a privilege surface), plus schedule
      and predecessor wiring.
    * **Streams** (`SHOW STREAMS IN ACCOUNT`) — change-data-capture on a source
      table/view; staleness signals an unconsumed CDC backlog.
    * **Pipes** (`SHOW PIPES IN ACCOUNT`) — Snowpipe continuous ingestion;
      reads from a stage (the data-ingress path), optionally auto-ingest via a
      notification integration.

    Returns ``status``, ``account``, ``tasks``, ``streams``, ``pipes``,
    ``findings``, ``warnings``. Definitions are summarized, never the data they
    move.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake pipeline discovery. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    result: dict[str, Any] = {
        "status": "disabled",
        "account": resolved_account,
        "tasks": [],
        "streams": [],
        "pipes": [],
        "findings": [],
        "warnings": [],
    }
    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "no_account"
        warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return result

    try:
        conn = _get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        cursor = conn.cursor()
        try:
            cursor.execute("SHOW TASKS IN ACCOUNT")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                name = str(r.get("name", ""))
                db = str(r.get("database_name", "") or "")
                sch = str(r.get("schema_name", "") or "")
                if not name:
                    continue
                result["tasks"].append(
                    {
                        "name": name,
                        "fqn": _split_fqn_parts(name, db, sch),
                        "warehouse": str(r.get("warehouse", "") or ""),
                        "schedule": str(r.get("schedule", "") or ""),
                        "state": str(r.get("state", "") or ""),
                        "owner": str(r.get("owner", "") or ""),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list tasks: {sanitize_error(exc)}")
        finally:
            cursor.close()

        cursor = conn.cursor()
        try:
            cursor.execute("SHOW STREAMS IN ACCOUNT")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                name = str(r.get("name", ""))
                db = str(r.get("database_name", "") or "")
                sch = str(r.get("schema_name", "") or "")
                if not name:
                    continue
                source = str(r.get("table_name", "") or "")
                result["streams"].append(
                    {
                        "name": name,
                        "fqn": _split_fqn_parts(name, db, sch),
                        "source_fqn": source,
                        "stale": _sf_truthy(r.get("stale")),
                        "type": str(r.get("type", "") or ""),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list streams: {sanitize_error(exc)}")
        finally:
            cursor.close()

        cursor = conn.cursor()
        try:
            cursor.execute("SHOW PIPES IN ACCOUNT")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                name = str(r.get("name", ""))
                db = str(r.get("database_name", "") or "")
                sch = str(r.get("schema_name", "") or "")
                if not name:
                    continue
                # The COPY INTO definition references the source stage (@db.schema.stage).
                definition = str(r.get("definition", "") or "")
                stage = ""
                m = re.search(r"FROM\s+@([A-Za-z0-9_$.\"]+)", definition, re.IGNORECASE)
                if m:
                    stage = m.group(1).replace('"', "")
                result["pipes"].append(
                    {
                        "name": name,
                        "fqn": _split_fqn_parts(name, db, sch),
                        "stage": stage,
                        "auto_ingest": bool(str(r.get("notification_channel", "") or "") or str(r.get("integration", "") or "")),
                        "integration": str(r.get("integration", "") or ""),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list pipes: {sanitize_error(exc)}")
        finally:
            cursor.close()

        suspended = [t["name"] for t in result["tasks"] if t["state"].upper() == "SUSPENDED"]
        if suspended:
            result["findings"].append(
                {
                    "severity": "low",
                    "title": "Suspended scheduled tasks",
                    "detail": f"{len(suspended)} task(s) are suspended; scheduled automation is not running.",
                }
            )
        stale_streams = [s["name"] for s in result["streams"] if s["stale"]]
        if stale_streams:
            result["findings"].append(
                {
                    "severity": "medium",
                    "title": "Stale change-data-capture streams",
                    "detail": f"{len(stale_streams)} stream(s) are stale; unconsumed CDC may be permanently lost.",
                }
            )
        result["status"] = "ok"
    finally:
        conn.close()
    return result


_SF_INTEGRATION_EGRESS = {"EXTERNAL_ACCESS", "API", "NOTIFICATION", "STORAGE", "CATALOG"}


def discover_snowflake_integrations(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> dict[str, Any]:
    """Inventory Snowflake account integrations (read-only).

    Integrations are the account's connections to the outside world — every one
    is an egress / federation / external-trust surface:

    * **STORAGE** — external cloud buckets backing stages (S3 / Azure / GCS).
    * **API** — external-function endpoints (API Gateway / Functions).
    * **EXTERNAL ACCESS** — outbound network access from UDFs/procedures
      (allowed network rules + secrets).
    * **SECURITY** — external OAuth / SAML / SCIM federation.
    * **NOTIFICATION** — SNS / SQS / Event Grid auto-ingest channels.
    * **CATALOG** — external Iceberg / Polaris (Open Catalog) REST catalogs.

    Discovered via ``SHOW INTEGRATIONS`` (name / type / category / enabled).
    Returns ``status``, ``account``, ``integrations``, ``findings``,
    ``warnings``. No secret material is read.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake integration discovery. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    result: dict[str, Any] = {
        "status": "disabled",
        "account": resolved_account,
        "integrations": [],
        "findings": [],
        "warnings": [],
    }
    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "no_account"
        warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return result

    try:
        conn = _get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        cursor = conn.cursor()
        try:
            cursor.execute("SHOW INTEGRATIONS")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                name = str(r.get("name", ""))
                if not name:
                    continue
                # SHOW INTEGRATIONS returns a high-level "category"
                # (SECURITY / STORAGE / API / EXTERNAL_ACCESS / NOTIFICATION /
                # CATALOG) plus a "type" subtype (SAML2, EXTERNAL_OAUTH, S3, …).
                # Prefer the category column; fall back to the type prefix.
                itype = str(r.get("type", "") or "").upper()
                category = str(r.get("category", "") or "").upper().replace(" ", "_")
                if not category:
                    category = itype.split("-")[0].split(" ")[0].strip()
                result["integrations"].append(
                    {
                        "name": name,
                        "type": itype,
                        "category": category,
                        "enabled": _sf_truthy(r.get("enabled")),
                        "comment": str(r.get("comment", "") or "")[:200],
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list integrations: {sanitize_error(exc)}")
        finally:
            cursor.close()

        enabled_egress = [i for i in result["integrations"] if i["enabled"] and i["category"] in _SF_INTEGRATION_EGRESS]
        ext_access = [i["name"] for i in enabled_egress if i["category"] == "EXTERNAL_ACCESS"]
        if ext_access:
            result["findings"].append(
                {
                    "severity": "medium",
                    "title": "External-access integrations enabled",
                    "detail": f"{len(ext_access)} external-access integration(s) let UDFs/procedures make outbound network calls.",
                }
            )
        security = [i["name"] for i in result["integrations"] if i["enabled"] and i["category"] == "SECURITY"]
        if security:
            result["findings"].append(
                {
                    "severity": "low",
                    "title": "External identity federation configured",
                    "detail": f"{len(security)} security integration(s) federate identity to an external IdP/OAuth provider.",
                }
            )
        result["status"] = "ok"
    finally:
        conn.close()
    return result


_SF_EXTERNAL_SCHEMES = {"s3": "aws", "s3gov": "aws", "azure": "azure", "gcs": "gcp"}


def _parse_external_location(url: str) -> tuple[str, str]:
    """Return (cloud_provider, bucket) for an s3:// / azure:// / gcs:// path, else ('','')."""
    if "://" not in (url or ""):
        return "", ""
    scheme, rest = url.split("://", 1)
    cloud = _SF_EXTERNAL_SCHEMES.get(scheme.lower(), "")
    if not cloud:
        return "", ""
    return cloud, rest.split("/", 1)[0]


def discover_snowflake_external_data(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> dict[str, Any]:
    """Inventory Snowflake open-table-format + external data objects (read-only).

    The data that physically lives outside Snowflake-managed storage:

    * **Iceberg tables** (`SHOW ICEBERG TABLES IN ACCOUNT`) — Apache Iceberg
      tables, with their external base location (cloud bucket) and catalog
      (Snowflake-managed or external / Polaris-Open-Catalog).
    * **External tables** (`SHOW EXTERNAL TABLES IN ACCOUNT`) — query-in-place
      over files in a stage, with the backing stage/location.

    Both point at off-account storage, so they are data-residency / exfil
    relevant; the graph links them to the destination bucket (the same node a
    cloud scan emits) and to their stage.

    Returns ``status``, ``account``, ``iceberg_tables``, ``external_tables``,
    ``findings``, ``warnings``. Object metadata only; never the data.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake external-data discovery. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    result: dict[str, Any] = {
        "status": "disabled",
        "account": resolved_account,
        "iceberg_tables": [],
        "external_tables": [],
        "findings": [],
        "warnings": [],
    }
    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "no_account"
        warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return result

    try:
        conn = _get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        cursor = conn.cursor()
        try:
            cursor.execute("SHOW ICEBERG TABLES IN ACCOUNT")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                name = str(r.get("name", ""))
                db = str(r.get("database_name", "") or "")
                sch = str(r.get("schema_name", "") or "")
                if not name:
                    continue
                base_location = str(r.get("base_location", "") or r.get("external_volume", "") or "")
                cloud, bucket = _parse_external_location(base_location)
                result["iceberg_tables"].append(
                    {
                        "name": name,
                        "fqn": _split_fqn_parts(name, db, sch),
                        "catalog": str(r.get("catalog", "") or ""),
                        "catalog_source": str(r.get("catalog_source", "") or ""),
                        "base_location": base_location,
                        "cloud_provider": cloud,
                        "bucket": bucket,
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list Iceberg tables: {sanitize_error(exc)}")
        finally:
            cursor.close()

        cursor = conn.cursor()
        try:
            cursor.execute("SHOW EXTERNAL TABLES IN ACCOUNT")
            keys = [d[0].lower() for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                r = dict(zip(keys, row))
                name = str(r.get("name", ""))
                db = str(r.get("database_name", "") or "")
                sch = str(r.get("schema_name", "") or "")
                if not name:
                    continue
                location = str(r.get("location", "") or "")
                # location is typically @db.schema.stage/path — capture the stage.
                stage = ""
                if location.startswith("@"):
                    stage = location[1:].split("/", 1)[0]
                result["external_tables"].append(
                    {
                        "name": name,
                        "fqn": _split_fqn_parts(name, db, sch),
                        "location": location,
                        "stage": stage,
                        "file_format": str(r.get("file_format_name", "") or r.get("file_format_type", "") or ""),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list external tables: {sanitize_error(exc)}")
        finally:
            cursor.close()

        external_catalog = [
            t["fqn"] for t in result["iceberg_tables"] if t["catalog_source"] and t["catalog_source"].upper() not in ("SNOWFLAKE", "")
        ]
        if external_catalog:
            result["findings"].append(
                {
                    "severity": "low",
                    "title": "Iceberg tables on an external catalog",
                    "detail": f"{len(external_catalog)} Iceberg table(s) use an external catalog; governance is shared externally.",
                }
            )
        if result["external_tables"]:
            result["findings"].append(
                {
                    "severity": "low",
                    "title": "External tables query data in place",
                    "detail": f"{len(result['external_tables'])} external table(s) read files from a stage outside Snowflake storage.",
                }
            )
        result["status"] = "ok"
    finally:
        conn.close()
    return result


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

    _resolve_snowflake_auth(conn_kwargs, authenticator)

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


def enrich_report_with_snowflake_estate(report: Any) -> None:
    """Run the Snowflake estate discoveries and attach their ``snowflake_*_data`` blocks.

    Mutates ``report`` in place, populating the ``snowflake_*_data`` fields the
    graph builder consumes (object graph, login anomalies, exfil graph, auth
    posture, services, pipeline, integrations, external data, governance,
    activity). Each discovery is best-effort: a connector raising never breaks
    the scan; that block is simply skipped.

    Unlike :func:`collect_cloud_inventory`, the Snowflake estate does not fit the
    single inventory-dict shape AWS / Azure / GCP contribute — it produces
    distinct ``snowflake_*_data`` blocks — so this parallel helper is the shared
    entry point for both the ``--snowflake`` CLI path and the gated
    ``AGENT_BOM_SNOWFLAKE_INVENTORY`` enrichment path. Callers decide *whether*
    to run it (CLI flag vs. env gate); this function owns *what* it runs so the
    two surfaces stay identical.
    """
    # Object + dependency graph: tables/views → DATA_STORE nodes,
    # OBJECT_DEPENDENCIES → DEPENDS_ON lineage edges. Best-effort.
    #
    # The object graph's grants/memberships come from ACCOUNT_USAGE, which lags
    # 45min–2h, so a freshly-created role hierarchy is invisible. Overlay
    # zero-latency SHOW-based identity (current state) and prefer it over the
    # lagged rows so new users/roles/grants graph immediately. Best-effort.
    try:
        _sf_object_graph = discover_object_dependencies()
        try:
            _sf_live_identity = discover_identity_live()
            _sf_object_graph = merge_live_identity_into_object_graph(_sf_object_graph, _sf_live_identity)
        except Exception:  # noqa: BLE001 — live overlay is supplementary; never fail the object graph
            pass
        if _sf_object_graph.get("status") == "ok" and (
            _sf_object_graph.get("objects")
            or _sf_object_graph.get("dependencies")
            or _sf_object_graph.get("grants")
            or _sf_object_graph.get("role_memberships")
            or _sf_object_graph.get("users")
        ):
            report.snowflake_object_graph_data = _sf_object_graph
    except Exception:  # noqa: BLE001 — object graph is supplementary; never fail the scan
        pass
    # Login anomalies: impossible travel, high distinct-IP, failed-login bursts. Best-effort.
    try:
        _sf_login_anomalies = discover_login_anomalies()
        if _sf_login_anomalies.get("status") == "ok" and _sf_login_anomalies.get("findings"):
            report.snowflake_login_anomalies_data = _sf_login_anomalies
    except Exception:  # noqa: BLE001 — anomaly detection is supplementary; never fail the scan
        pass
    # Exfil graph: outbound shares, external stages, sensitivity-tagged objects. Best-effort.
    try:
        _sf_exfil = discover_data_exfil()
        if _sf_exfil.get("status") == "ok" and (
            _sf_exfil.get("outbound_shares") or _sf_exfil.get("external_stages") or _sf_exfil.get("sensitive_objects")
        ):
            report.snowflake_exfil_graph_data = _sf_exfil
    except Exception:  # noqa: BLE001 — exfil graph is supplementary; never fail the scan
        pass
    # Auth posture: per-user MFA/key-pair/password matrix + network policies. Best-effort.
    try:
        _sf_auth = discover_auth_posture()
        if _sf_auth.get("status") == "ok" and (_sf_auth.get("users") or _sf_auth.get("network_policies")):
            report.snowflake_auth_posture_data = _sf_auth
    except Exception:  # noqa: BLE001 — auth posture is supplementary; never fail the scan
        pass
    # Services: warehouses (compute) + database/schema containment hierarchy. Best-effort.
    try:
        _sf_services = discover_snowflake_services()
        # Organization → Accounts roll-up (opt-in, ORGADMIN-gated). Carried on the
        # services payload under ``organization`` so the graph builder can parent
        # the account node(s) under the org without a new top-level report field.
        # A single account / missing ORGADMIN no-ops cleanly (non-ok status).
        try:
            _sf_org = discover_organization()
            if isinstance(_sf_org, dict) and _sf_org.get("status") == "ok" and _sf_org.get("accounts"):
                _sf_services["organization"] = _sf_org
        except Exception:  # noqa: BLE001 — org roll-up is supplementary; never fail the scan
            pass
        if _sf_services.get("status") == "ok" and (
            _sf_services.get("warehouses") or _sf_services.get("databases") or _sf_services.get("schemas")
        ):
            report.snowflake_services_data = _sf_services
    except Exception:  # noqa: BLE001 — service inventory is supplementary; never fail the scan
        pass
    # Pipeline objects: tasks (automation), streams (CDC), pipes (ingestion). Best-effort.
    try:
        _sf_pipeline = discover_snowflake_pipeline()
        if _sf_pipeline.get("status") == "ok" and (_sf_pipeline.get("tasks") or _sf_pipeline.get("streams") or _sf_pipeline.get("pipes")):
            report.snowflake_pipeline_data = _sf_pipeline
    except Exception:  # noqa: BLE001 — pipeline inventory is supplementary; never fail the scan
        pass
    # Integrations: storage/API/external-access/security/notification/catalog. Best-effort.
    try:
        _sf_integrations = discover_snowflake_integrations()
        if _sf_integrations.get("status") == "ok" and _sf_integrations.get("integrations"):
            report.snowflake_integrations_data = _sf_integrations
    except Exception:  # noqa: BLE001 — integration inventory is supplementary; never fail the scan
        pass
    # External data: iceberg + external tables (open-table-format / query-in-place). Best-effort.
    try:
        _sf_external = discover_snowflake_external_data()
        if _sf_external.get("status") == "ok" and (_sf_external.get("iceberg_tables") or _sf_external.get("external_tables")):
            report.snowflake_external_data_data = _sf_external
    except Exception:  # noqa: BLE001 — external-data inventory is supplementary; never fail the scan
        pass
    # Governance: ACCESS_HISTORY reads + Cortex agent telemetry + derived risk
    # findings. De-duplicated against object-dependency and exfil discoveries.
    # Best-effort.
    try:
        _sf_governance = discover_governance().to_dict()
        if _sf_governance.get("access_records") or _sf_governance.get("agent_usage") or _sf_governance.get("findings"):
            report.snowflake_governance_data = {
                "status": "ok",
                "account": _sf_governance.get("account", ""),
                "discovered_at": _sf_governance.get("discovered_at", ""),
                "summary": _sf_governance.get("summary", {}),
                "access_records": _sf_governance.get("access_records", []),
                "agent_usage": _sf_governance.get("agent_usage", []),
                "findings": _sf_governance.get("findings", []),
                "warnings": _sf_governance.get("warnings", []),
            }
    except Exception:  # noqa: BLE001 — governance is supplementary; never fail the scan
        pass
    # Activity timeline: QUERY_HISTORY (365-day lookback) + AI observability
    # events. Summarized onto the account node. Best-effort.
    try:
        _sf_activity = discover_activity().to_dict()
        if (
            (_sf_activity.get("summary") or {}).get("total_queries")
            or _sf_activity.get("query_history")
            or _sf_activity.get("observability_events")
        ):
            _sf_activity["status"] = "ok"
            report.snowflake_activity_data = _sf_activity
    except Exception:  # noqa: BLE001 — activity timeline is supplementary; never fail the scan
        pass
