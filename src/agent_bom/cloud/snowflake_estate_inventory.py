"""Snowflake estate inventory: compute, containers, pipelines, integrations and external data (read-only)."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any

from agent_bom.security import sanitize_error, sanitize_sensitive_payload

from .base import CloudDiscoveryError
from .normalization import coerce_bool_or_none
from .snowflake_common import _coerce_int_or_none, _env_or_value, _sf, _sf_truthy

# Log under the façade's logger so existing log routing and filters keep applying.
logger = logging.getLogger("agent_bom.cloud.snowflake")

_SF_INTEGRATION_EGRESS = {"EXTERNAL_ACCESS", "API", "NOTIFICATION", "STORAGE", "CATALOG"}
_SF_EXTERNAL_SCHEMES = {"s3": "aws", "s3gov": "aws", "azure": "azure", "gcs": "gcp"}


def _split_fqn_parts(name: str, database: str, schema: str) -> str:
    """Build a DB.SCHEMA.NAME fqn from SHOW-command columns, tolerating blanks."""
    parts = [p for p in (database, schema, name) if p]
    return ".".join(parts)


def _parse_external_location(url: str) -> tuple[str, str]:
    """Return (cloud_provider, bucket) for an s3:// / azure:// / gcs:// path, else ('','')."""
    if "://" not in (url or ""):
        return "", ""
    scheme, rest = url.split("://", 1)
    cloud = _SF_EXTERNAL_SCHEMES.get(scheme.lower(), "")
    if not cloud:
        return "", ""
    return cloud, rest.split("/", 1)[0]


def _estate_result(account: str | None, *collections: str) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "disabled", "account": _env_or_value(account, "SNOWFLAKE_ACCOUNT")}
    for key in collections:
        result[key] = []
    result["findings"] = []
    result["warnings"] = []
    return result


def _open_estate_connection(
    result: dict[str, Any],
    account: str | None,
    user: str | None,
    authenticator: str | None,
    database: str | None,
    schema: str | None,
) -> Any | None:
    """Connect for an estate read, or record why not and return ``None``."""
    warnings: list[str] = result["warnings"]
    if not result["account"]:
        result["status"] = "no_account"
        warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return None
    try:
        return _sf()._get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return None


def _collect_show_rows(
    conn: Any,
    sql: str,
    label: str,
    warnings: list[str],
    into: list[dict[str, Any]],
    build: Callable[[dict[str, Any]], dict[str, Any] | None],
) -> None:
    """Run one SHOW command, appending each built row; a failure becomes a warning."""
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        keys = [d[0].lower() for d in cursor.description] if cursor.description else []
        for row in cursor.fetchall():
            item = build(dict(zip(keys, row)))
            if item is not None:
                into.append(item)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list {label}: {sanitize_error(exc)}")
    finally:
        cursor.close()


def _named_fqn(r: dict[str, Any]) -> tuple[str, str] | None:
    name = str(r.get("name", ""))
    db = str(r.get("database_name", "") or "")
    sch = str(r.get("schema_name", "") or "")
    if not name:
        return None
    return name, _split_fqn_parts(name, db, sch)


def _require_connector(surface: str) -> None:
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            f"snowflake-connector-python is required for Snowflake {surface} discovery. Install with: pip install 'agent-bom[snowflake]'"
        )


# ── Pipelines: tasks, streams, pipes ─────────────────────────────────────────


def _task_row(r: dict[str, Any]) -> dict[str, Any] | None:
    named = _named_fqn(r)
    if named is None:
        return None
    return {
        "name": named[0],
        "fqn": named[1],
        "warehouse": str(r.get("warehouse", "") or ""),
        "schedule": str(r.get("schedule", "") or ""),
        "state": str(r.get("state", "") or ""),
        "owner": str(r.get("owner", "") or ""),
    }


def _stream_row(r: dict[str, Any]) -> dict[str, Any] | None:
    named = _named_fqn(r)
    if named is None:
        return None
    return {
        "name": named[0],
        "fqn": named[1],
        "source_fqn": str(r.get("table_name", "") or ""),
        "stale": _sf_truthy(r.get("stale")),
        "type": str(r.get("type", "") or ""),
    }


def _pipe_row(r: dict[str, Any]) -> dict[str, Any] | None:
    named = _named_fqn(r)
    if named is None:
        return None
    # The COPY INTO definition references the source stage (@db.schema.stage).
    definition = str(r.get("definition", "") or "")
    stage = ""
    m = re.search(r"FROM\s+@([A-Za-z0-9_$.\"]+)", definition, re.IGNORECASE)
    if m:
        stage = m.group(1).replace('"', "")
    return {
        "name": named[0],
        "fqn": named[1],
        "stage": stage,
        "auto_ingest": bool(str(r.get("notification_channel", "") or "") or str(r.get("integration", "") or "")),
        "integration": str(r.get("integration", "") or ""),
    }


def _pipeline_findings(result: dict[str, Any]) -> None:
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
    _require_connector("pipeline")
    result = _estate_result(account, "tasks", "streams", "pipes")
    conn = _open_estate_connection(result, account, user, authenticator, database, schema)
    if conn is None:
        return result
    warnings: list[str] = result["warnings"]
    try:
        _collect_show_rows(conn, "SHOW TASKS IN ACCOUNT", "tasks", warnings, result["tasks"], _task_row)
        _collect_show_rows(conn, "SHOW STREAMS IN ACCOUNT", "streams", warnings, result["streams"], _stream_row)
        _collect_show_rows(conn, "SHOW PIPES IN ACCOUNT", "pipes", warnings, result["pipes"], _pipe_row)
        _pipeline_findings(result)
        result["status"] = "ok"
    finally:
        conn.close()
    return result


# ── Integrations ─────────────────────────────────────────────────────────────


def _integration_row(r: dict[str, Any]) -> dict[str, Any] | None:
    name = str(r.get("name", ""))
    if not name:
        return None
    # SHOW INTEGRATIONS returns a high-level "category"
    # (SECURITY / STORAGE / API / EXTERNAL_ACCESS / NOTIFICATION /
    # CATALOG) plus a "type" subtype (SAML2, EXTERNAL_OAUTH, S3, …).
    # Prefer the category column; fall back to the type prefix.
    itype = str(r.get("type", "") or "").upper()
    category = str(r.get("category", "") or "").upper().replace(" ", "_")
    if not category:
        category = itype.split("-")[0].split(" ")[0].strip()
    return {
        "name": name,
        "type": itype,
        "category": category,
        "enabled": coerce_bool_or_none(r.get("enabled")),
        "enabled_evidence": {
            "source": "SHOW INTEGRATIONS",
            "recorded": "enabled" in r,
            "value": sanitize_sensitive_payload(r.get("enabled")),
        },
        "comment": str(r.get("comment", "") or "")[:200],
    }


def _integration_findings(result: dict[str, Any]) -> None:
    enabled_egress = [i for i in result["integrations"] if i["enabled"] and i["category"] in _SF_INTEGRATION_EGRESS]
    ext_access = [i["name"] for i in enabled_egress if i["category"] == "EXTERNAL_ACCESS"]
    if ext_access:
        result["findings"].append(
            {
                "severity": "medium",
                "title": "External-access integrations enabled",
                "detail": (
                    f"{len(ext_access)} external-access integration(s) configure outbound connections for UDFs/procedures. "
                    "Effective permissions, network rules and successful calls require separate evidence."
                ),
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
    _require_connector("integration")
    result = _estate_result(account, "integrations")
    conn = _open_estate_connection(result, account, user, authenticator, database, schema)
    if conn is None:
        return result
    try:
        _collect_show_rows(conn, "SHOW INTEGRATIONS", "integrations", result["warnings"], result["integrations"], _integration_row)
        _integration_findings(result)
        result["status"] = "ok"
    finally:
        conn.close()
    return result


# ── External data: Iceberg + external tables ─────────────────────────────────


def _iceberg_row(r: dict[str, Any]) -> dict[str, Any] | None:
    named = _named_fqn(r)
    if named is None:
        return None
    base_location = str(r.get("base_location", "") or r.get("external_volume", "") or "")
    cloud, bucket = _parse_external_location(base_location)
    return {
        "name": named[0],
        "fqn": named[1],
        "catalog": str(r.get("catalog", "") or ""),
        "catalog_source": str(r.get("catalog_source", "") or ""),
        "base_location": base_location,
        "cloud_provider": cloud,
        "bucket": bucket,
    }


def _external_table_row(r: dict[str, Any]) -> dict[str, Any] | None:
    named = _named_fqn(r)
    if named is None:
        return None
    location = str(r.get("location", "") or "")
    # location is typically @db.schema.stage/path — capture the stage.
    stage = ""
    if location.startswith("@"):
        stage = location[1:].split("/", 1)[0]
    return {
        "name": named[0],
        "fqn": named[1],
        "location": location,
        "stage": stage,
        "file_format": str(r.get("file_format_name", "") or r.get("file_format_type", "") or ""),
    }


def _external_data_findings(result: dict[str, Any]) -> None:
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
    _require_connector("external-data")
    result = _estate_result(account, "iceberg_tables", "external_tables")
    conn = _open_estate_connection(result, account, user, authenticator, database, schema)
    if conn is None:
        return result
    warnings: list[str] = result["warnings"]
    try:
        _collect_show_rows(conn, "SHOW ICEBERG TABLES IN ACCOUNT", "Iceberg tables", warnings, result["iceberg_tables"], _iceberg_row)
        _collect_show_rows(
            conn, "SHOW EXTERNAL TABLES IN ACCOUNT", "external tables", warnings, result["external_tables"], _external_table_row
        )
        _external_data_findings(result)
        result["status"] = "ok"
    finally:
        conn.close()
    return result


# ── Services: warehouses + database/schema containment ───────────────────────


def _warehouse_row(r: dict[str, Any]) -> dict[str, Any] | None:
    name = str(r.get("name", ""))
    if not name:
        return None
    return {
        "name": name,
        "size": str(r.get("size", "") or ""),
        "state": str(r.get("state", "") or ""),
        "auto_suspend": _coerce_int_or_none(r.get("auto_suspend")),
        "type": str(r.get("type", "") or "STANDARD"),
    }


def _database_row(r: dict[str, Any]) -> dict[str, Any] | None:
    name = str(r.get("name", ""))
    if not name:
        return None
    return {
        "name": name,
        "owner": str(r.get("owner", "") or ""),
        "retention_time": _coerce_int_or_none(r.get("retention_time")),
        "is_default": str(r.get("is_default", "") or "").upper() in ("Y", "YES", "TRUE"),
    }


def _schema_row(r: dict[str, Any]) -> dict[str, Any] | None:
    name = str(r.get("name", ""))
    db = str(r.get("database_name", "") or "")
    if not name or not db:
        return None
    if name in ("INFORMATION_SCHEMA",):
        return None
    return {"name": name, "database_name": db, "fqn": f"{db}.{name}", "owner": str(r.get("owner", "") or "")}


def _services_findings(result: dict[str, Any]) -> None:
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
    _require_connector("service")
    result = _estate_result(account, "warehouses", "databases", "schemas")
    conn = _open_estate_connection(result, account, user, authenticator, database, schema)
    if conn is None:
        return result
    warnings: list[str] = result["warnings"]
    try:
        _collect_show_rows(conn, "SHOW WAREHOUSES", "warehouses", warnings, result["warehouses"], _warehouse_row)
        _collect_show_rows(conn, "SHOW DATABASES", "databases", warnings, result["databases"], _database_row)
        _collect_show_rows(conn, "SHOW SCHEMAS IN ACCOUNT", "schemas", warnings, result["schemas"], _schema_row)
        _services_findings(result)
        result["status"] = "ok"
    finally:
        conn.close()
    return result
