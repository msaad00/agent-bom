"""Snowflake object dependency graph and live identity (roles, users, grants) discovery."""

from __future__ import annotations

import logging
from typing import Any

from agent_bom.security import sanitize_error

from .base import CloudDiscoveryError
from .snowflake_common import _env_or_value, _record_snowflake_inventory_failure, _sf, _sf_truthy

# Log under the façade's logger so existing log routing and filters keep applying.
logger = logging.getLogger("agent_bom.cloud.snowflake")


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


def _grant_object_fqn(name: str, database: str, schema: str) -> str:
    """Retain qualified grant names; only add missing namespace components.

    Dots inside a quoted identifier belong to that identifier. Counting only
    unquoted separators also handles doubled quotes without splitting the name
    or changing its case/escaping. Metadata is never used as executable SQL.
    """
    quoted = False
    separators = 0
    for character in name:
        if character == '"':
            quoted = not quoted
        elif character == "." and not quoted:
            separators += 1
    if separators >= 2:
        return name
    prefix = (database,) if separators == 1 else (database, schema)
    return ".".join(part for part in (*prefix, name) if part)


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
            db, sch, nm = str(r.get("table_catalog") or ""), str(r.get("table_schema") or ""), str(r.get("name") or "")
            if not role or not nm:
                continue
            grants.append(
                {
                    "role": role,
                    "privilege": str(r.get("privilege", "")),
                    "object_fqn": _grant_object_fqn(nm, db, sch),
                    "object_type": str(r.get("granted_on", "")).lower(),
                }
            )
    except Exception as exc:  # noqa: BLE001
        _record_snowflake_inventory_failure(
            exc=exc,
            resource_type="GRANTS_TO_ROLES",
            inventory_key="grants_to_roles",
            warnings=warnings,
        )
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
        _record_snowflake_inventory_failure(
            exc=exc,
            resource_type="GRANTS_TO_USERS",
            inventory_key="grants_to_users",
            warnings=warnings,
        )
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
        conn = _sf()._get_connection(account, user, authenticator, database, schema)
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
        conn = _sf()._get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings_list.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        roles = _sf()._live_show_roles(conn, warnings_list)
        result["roles"] = roles
        result["users"] = _live_show_users(conn, warnings_list)
        grants, memberships = _sf()._live_role_grants(conn, [r["name"] for r in roles], warnings_list)
        result["grants"] = grants
        result["role_memberships"] = memberships
        result["status"] = "ok"
    finally:
        conn.close()
    return result


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
