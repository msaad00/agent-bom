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

import contextlib
import contextvars
import logging
import os
import re
import warnings
from typing import Any

from agent_bom.cloud.snowflake_spcs_auth import apply_spcs_workload_identity
from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.governance import (
    AccessRecord,
    GovernanceCategory,
    GovernanceFinding,
    GovernanceReport,
    GovernanceSeverity,
)
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType
from agent_bom.security import sanitize_error

from .base import CloudDiscoveryError
from .normalization import (
    build_cloud_origin,
    build_package_purl,
)
from .snowflake_ai_surfaces import (
    _describe_mcp_server_tools as _describe_mcp_server_tools,
)
from .snowflake_ai_surfaces import (
    _discover_cortex_agents as _discover_cortex_agents,
)
from .snowflake_ai_surfaces import (
    _discover_cortex_services as _discover_cortex_services,
)
from .snowflake_ai_surfaces import (
    _discover_custom_tools as _discover_custom_tools,
)
from .snowflake_ai_surfaces import (
    _discover_from_query_history as _discover_from_query_history,
)
from .snowflake_ai_surfaces import (
    _discover_mcp_servers as _discover_mcp_servers,
)
from .snowflake_ai_surfaces import (
    _discover_snowpark_packages as _discover_snowpark_packages,
)
from .snowflake_ai_surfaces import (
    _discover_streamlit_apps as _discover_streamlit_apps,
)
from .snowflake_ai_surfaces import (
    _parse_create_statement_name as _parse_create_statement_name,
)
from .snowflake_common import (
    _CONTROL_CHAR_RE as _CONTROL_CHAR_RE,
)
from .snowflake_common import (
    _SAFE_IDENT_RE as _SAFE_IDENT_RE,
)
from .snowflake_common import (
    _SNOWFLAKE_INVENTORY_FAILURES as _SNOWFLAKE_INVENTORY_FAILURES,
)
from .snowflake_common import (
    _coerce_int_or_none as _coerce_int_or_none,
)
from .snowflake_common import (
    _coerce_snowflake_days as _coerce_snowflake_days,
)
from .snowflake_common import (
    _env_or_value as _env_or_value,
)
from .snowflake_common import (
    _parse_json_field as _parse_json_field,
)
from .snowflake_common import (
    _parse_json_object as _parse_json_object,
)
from .snowflake_common import (
    _quote_sf_identifier as _quote_sf_identifier,
)
from .snowflake_common import (
    _record_snowflake_inventory_failure as _record_snowflake_inventory_failure,
)
from .snowflake_common import (
    _sf_truthy as _sf_truthy,
)
from .snowflake_common import (
    _validate_sf_identifier as _validate_sf_identifier,
)
from .snowflake_estate_inventory import (
    _SF_EXTERNAL_SCHEMES as _SF_EXTERNAL_SCHEMES,
)
from .snowflake_estate_inventory import (
    _SF_INTEGRATION_EGRESS as _SF_INTEGRATION_EGRESS,
)
from .snowflake_estate_inventory import (
    _collect_show_rows as _collect_show_rows,
)
from .snowflake_estate_inventory import (
    _database_row as _database_row,
)
from .snowflake_estate_inventory import (
    _estate_result as _estate_result,
)
from .snowflake_estate_inventory import (
    _open_estate_connection as _open_estate_connection,
)
from .snowflake_estate_inventory import (
    _parse_external_location as _parse_external_location,
)
from .snowflake_estate_inventory import (
    _schema_row as _schema_row,
)
from .snowflake_estate_inventory import (
    _split_fqn_parts as _split_fqn_parts,
)
from .snowflake_estate_inventory import (
    _warehouse_row as _warehouse_row,
)
from .snowflake_estate_inventory import (
    discover_snowflake_external_data as discover_snowflake_external_data,
)
from .snowflake_estate_inventory import (
    discover_snowflake_integrations as discover_snowflake_integrations,
)
from .snowflake_estate_inventory import (
    discover_snowflake_pipeline as discover_snowflake_pipeline,
)
from .snowflake_estate_inventory import (
    discover_snowflake_services as discover_snowflake_services,
)
from .snowflake_governance_findings import (
    _access_actor as _access_actor,
)
from .snowflake_governance_findings import (
    _access_actor_context as _access_actor_context,
)
from .snowflake_governance_findings import (
    _derive_findings as _derive_findings,
)
from .snowflake_governance_findings import (
    _find_elevated_privilege_risks as _find_elevated_privilege_risks,
)
from .snowflake_governance_findings import (
    _find_sensitive_data_access as _find_sensitive_data_access,
)
from .snowflake_governance_findings import (
    _find_write_access_risks as _find_write_access_risks,
)
from .snowflake_governance_mining import (
    _AGENT_QUERY_PATTERNS as _AGENT_QUERY_PATTERNS,
)
from .snowflake_governance_mining import (
    _COMPILED_PATTERNS as _COMPILED_PATTERNS,
)
from .snowflake_governance_mining import (
    _classify_agent_query as _classify_agent_query,
)
from .snowflake_governance_mining import (
    _mine_cortex_agent_usage as _mine_cortex_agent_usage,
)
from .snowflake_governance_mining import (
    _mine_grants_to_roles as _mine_grants_to_roles,
)
from .snowflake_governance_mining import (
    _mine_observability_events as _mine_observability_events,
)
from .snowflake_governance_mining import (
    _mine_query_history_365 as _mine_query_history_365,
)
from .snowflake_governance_mining import (
    _mine_tag_references as _mine_tag_references,
)
from .snowflake_governance_mining import (
    discover_activity as discover_activity,
)
from .snowflake_object_graph import (
    _LIVE_GRANT_OBJECT_TYPES as _LIVE_GRANT_OBJECT_TYPES,
)
from .snowflake_object_graph import (
    _LIVE_MAX_ROLES as _LIVE_MAX_ROLES,
)
from .snowflake_object_graph import (
    _discover_sf_dependencies as _discover_sf_dependencies,
)
from .snowflake_object_graph import (
    _discover_sf_grants as _discover_sf_grants,
)
from .snowflake_object_graph import (
    _discover_sf_objects as _discover_sf_objects,
)
from .snowflake_object_graph import (
    _grant_object_fqn as _grant_object_fqn,
)
from .snowflake_object_graph import (
    _live_show_users as _live_show_users,
)
from .snowflake_object_graph import (
    discover_identity_live as discover_identity_live,
)
from .snowflake_object_graph import (
    discover_object_dependencies as discover_object_dependencies,
)
from .snowflake_organization import (
    _SF_ORG_NOT_AUTHORIZED_MARKERS as _SF_ORG_NOT_AUTHORIZED_MARKERS,
)
from .snowflake_organization import (
    _derive_org_findings as _derive_org_findings,
)
from .snowflake_organization import (
    discover_organization as discover_organization,
)

logger = logging.getLogger(__name__)

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


def _org_discovery_envelope(org_name: str) -> dict[str, Any]:
    """Discovery envelope for an enumerated organization; the façade owns the permission catalog."""
    return DiscoveryEnvelope(
        scan_mode=ScanMode.SAAS_READ_ONLY,
        discovery_scope=(f"snowflake:organization/{org_name}",),
        permissions_used=_SF_ORG_PERMISSIONS,
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    ).to_dict()


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
    if apply_spcs_workload_identity(conn_kwargs):
        return

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


# A caller-owned Snowflake connection (e.g. a brokered read-only connection from
# a stored cloud connection) can be lent to the estate-sweep discovery helpers,
# which each open+close their own connection from env/args. When set, every
# ``_get_connection`` (and the two direct-connect discoverers) reuse this one
# connection instead of building one, and never close it — the borrower owns the
# lifecycle. Scoped via ``_borrowed_connection`` so it is per-call and never
# leaks across tenants/requests on a shared server.
_ACTIVE_CONNECTION: contextvars.ContextVar[Any | None] = contextvars.ContextVar("_sf_active_connection", default=None)


class _BorrowedConnection:
    """Proxy over a caller-owned Snowflake connection whose ``close`` is a no-op.

    Estate discovery helpers each ``conn.close()`` in a ``finally``. When they run
    against a lent (brokered) connection they must not close it — the borrower
    owns its lifecycle — so this proxy forwards every attribute to the real
    connection but swallows ``close``.
    """

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def close(self) -> None:  # noqa: D401 - lifecycle owned by the borrower
        return None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


@contextlib.contextmanager
def _borrowed_connection(conn: Any):
    """Lend ``conn`` to the estate discovery helpers for the duration of the block."""
    token = _ACTIVE_CONNECTION.set(conn)
    try:
        yield
    finally:
        _ACTIVE_CONNECTION.reset(token)


def _active_borrowed_connection() -> Any | None:
    """Return a non-closing proxy over the lent connection, or ``None`` if none is set."""
    active = _ACTIVE_CONNECTION.get()
    return _BorrowedConnection(active) if active is not None else None


def _get_connection(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> Any:
    """Open a Snowflake connection using the standard auth resolution contract."""
    borrowed = _active_borrowed_connection()
    if borrowed is not None:
        return borrowed
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
            except Exception as exc:
                warnings.append(f"Could not describe Snowflake notebook {nb_name!r}: {sanitize_error(exc)}")

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

    borrowed = _active_borrowed_connection()
    if borrowed is not None:
        conn = borrowed
    else:
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

            for obj in direct_objects:
                obj_name = obj.get("objectName", "")
                obj_type = obj.get("objectDomain", "")
                col_list = [c.get("columnName", "") for c in obj.get("columns", []) if c.get("columnName")]
                if not obj_name:
                    continue

                records.append(
                    AccessRecord(
                        query_id=query_id,
                        user_name=user_name,
                        role_name=role_name,
                        query_start=query_start,
                        object_name=obj_name,
                        object_type=obj_type,
                        columns=col_list,
                        operation="READ",
                        is_write=False,
                        base_objects=base_names,
                        source_field="direct_objects_accessed",
                    )
                )

            # A query can read and write the same object. Keep those observations
            # separate, including their distinct column lists. These arrays do
            # not establish the SQL verb, rows changed, or current authorization.
            for obj in objects_modified:
                obj_name = obj.get("objectName", "")
                if not obj_name:
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
                        source_field="objects_modified",
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
            _record_snowflake_inventory_failure(
                exc=exc,
                resource_type=f"grants TO role {role_name!r}",
                inventory_key="live_role_grants",
                warnings=warnings_list,
            )
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
            _record_snowflake_inventory_failure(
                exc=exc,
                resource_type=f"grants OF role {role_name!r}",
                inventory_key="live_role_grants",
                warnings=warnings_list,
            )
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


def enrich_report_with_snowflake_estate(report: Any, *, conn: Any = None, account: str | None = None) -> None:
    """Run the Snowflake estate discoveries and attach their ``snowflake_*_data`` blocks.

    Mutates ``report`` in place, populating the ``snowflake_*_data`` fields the
    graph builder consumes (object graph, login anomalies, exfil graph, auth
    posture, services, pipeline, integrations, external data, governance,
    activity). Each discovery is best-effort: a connector raising never breaks
    the scan; that block is simply skipped.

    Unlike :func:`collect_cloud_inventory`, the Snowflake estate does not fit the
    single inventory-dict shape AWS / Azure / GCP contribute — it produces
    distinct ``snowflake_*_data`` blocks — so this parallel helper is the shared
    entry point for the ``--snowflake`` CLI path, the gated
    ``AGENT_BOM_SNOWFLAKE_INVENTORY`` enrichment path, and the brokered
    cloud-connection scan. Callers decide *whether* to run it; this function owns
    *what* it runs so every surface stays identical.

    Args:
        conn: Optional already-open Snowflake connection (e.g. brokered from a
            stored read-only connection). When supplied it is lent to every
            estate discovery for the duration of this call — they reuse it
            instead of building their own from env, and it is **not** closed here
            (the caller owns its lifecycle). This gives brokered cloud-connection
            scans the same estate sweep the AWS/Azure/GCP paths get, running
            against the per-tenant read-only credentials.
        account: Optional Snowflake account label. Estate discoveries gate on a
            resolvable account (``SNOWFLAKE_ACCOUNT`` env by default); pass it
            explicitly for the brokered path where the account rides on the
            stored connection rather than process env.
    """
    with contextlib.ExitStack() as _estate_stack:
        if conn is not None:
            _estate_stack.enter_context(_borrowed_connection(conn))
        # Object + dependency graph: tables/views → DATA_STORE nodes,
        # OBJECT_DEPENDENCIES → DEPENDS_ON lineage edges. Best-effort.
        #
        # The object graph's grants/memberships come from ACCOUNT_USAGE, which lags
        # 45min–2h, so a freshly-created role hierarchy is invisible. Overlay
        # zero-latency SHOW-based identity (current state) and prefer it over the
        # lagged rows so new users/roles/grants graph immediately. Best-effort.
        try:
            _sf_object_graph = discover_object_dependencies(account=account)
            try:
                _sf_live_identity = discover_identity_live(account=account)
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
            _sf_login_anomalies = discover_login_anomalies(account=account)
            if _sf_login_anomalies.get("status") == "ok" and _sf_login_anomalies.get("findings"):
                report.snowflake_login_anomalies_data = _sf_login_anomalies
        except Exception:  # noqa: BLE001 — anomaly detection is supplementary; never fail the scan
            pass
        # Exfil graph: outbound shares, external stages, sensitivity-tagged objects. Best-effort.
        try:
            _sf_exfil = discover_data_exfil(account=account)
            if _sf_exfil.get("status") == "ok" and (
                _sf_exfil.get("outbound_shares") or _sf_exfil.get("external_stages") or _sf_exfil.get("sensitive_objects")
            ):
                report.snowflake_exfil_graph_data = _sf_exfil
        except Exception:  # noqa: BLE001 — exfil graph is supplementary; never fail the scan
            pass
        # Auth posture: per-user MFA/key-pair/password matrix + network policies. Best-effort.
        try:
            _sf_auth = discover_auth_posture(account=account)
            if _sf_auth.get("status") == "ok" and (_sf_auth.get("users") or _sf_auth.get("network_policies")):
                report.snowflake_auth_posture_data = _sf_auth
        except Exception:  # noqa: BLE001 — auth posture is supplementary; never fail the scan
            pass
        # Services: warehouses (compute) + database/schema containment hierarchy. Best-effort.
        try:
            _sf_services = discover_snowflake_services(account=account)
            # Organization → Accounts roll-up (opt-in, ORGADMIN-gated). Carried on the
            # services payload under ``organization`` so the graph builder can parent
            # the account node(s) under the org without a new top-level report field.
            # A single account / missing ORGADMIN no-ops cleanly (non-ok status).
            try:
                _sf_org = discover_organization(account=account)
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
            _sf_pipeline = discover_snowflake_pipeline(account=account)
            if _sf_pipeline.get("status") == "ok" and (
                _sf_pipeline.get("tasks") or _sf_pipeline.get("streams") or _sf_pipeline.get("pipes")
            ):
                report.snowflake_pipeline_data = _sf_pipeline
        except Exception:  # noqa: BLE001 — pipeline inventory is supplementary; never fail the scan
            pass
        # Integrations: storage/API/external-access/security/notification/catalog. Best-effort.
        try:
            _sf_integrations = discover_snowflake_integrations(account=account)
            if _sf_integrations.get("status") == "ok" and _sf_integrations.get("integrations"):
                report.snowflake_integrations_data = _sf_integrations
        except Exception:  # noqa: BLE001 — integration inventory is supplementary; never fail the scan
            pass
        # External data: iceberg + external tables (open-table-format / query-in-place). Best-effort.
        try:
            _sf_external = discover_snowflake_external_data(account=account)
            if _sf_external.get("status") == "ok" and (_sf_external.get("iceberg_tables") or _sf_external.get("external_tables")):
                report.snowflake_external_data_data = _sf_external
        except Exception:  # noqa: BLE001 — external-data inventory is supplementary; never fail the scan
            pass
        # Governance: ACCESS_HISTORY reads + Cortex agent telemetry + derived risk
        # findings. De-duplicated against object-dependency and exfil discoveries.
        # Best-effort.
        try:
            _sf_governance = discover_governance(account=account).to_dict()
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
            _sf_activity = discover_activity(account=account).to_dict()
            if (
                (_sf_activity.get("summary") or {}).get("total_queries")
                or _sf_activity.get("query_history")
                or _sf_activity.get("observability_events")
            ):
                _sf_activity["status"] = "ok"
                report.snowflake_activity_data = _sf_activity
        except Exception:  # noqa: BLE001 — activity timeline is supplementary; never fail the scan
            pass
