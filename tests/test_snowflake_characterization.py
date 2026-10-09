"""Characterization golden for ``agent_bom.cloud.snowflake`` discovery.

Drives every public Snowflake discovery entrypoint against a SQL-routing fake
connector (no live account) across rich / empty / description-less / denied /
missing-object / generic-error / connect-failure / missing-SDK scenarios and
pins the complete output, the executed SQL sequence, connector kwargs, log
records, coverage warnings and Python warnings.

Only ``discovered_at`` stamps (wall-clock ``datetime.now``) are normalized.
Sets are rendered sorted because their iteration order is not part of the
contract.

Regenerate with ``UPDATE_CLOUD_GOLDEN=1 pytest tests/test_snowflake_characterization.py``.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import sys
import types
import warnings
from enum import Enum
from pathlib import Path
from typing import Any, Callable

import pytest

from agent_bom.cloud import snowflake as sf
from agent_bom.cloud.base import CloudDiscoveryError
from agent_bom.scanners.state import consume_coverage_warnings

GOLDEN = Path(__file__).parent / "fixtures" / "cloud_characterization" / "snowflake.json"
UPDATE = os.environ.get("UPDATE_CLOUD_GOLDEN") == "1"

_SPEC_YAML = """
tools:
  - name: run_sql
    type: SYSTEM_EXECUTE_SQL
    description: arbitrary sql
  - name: my_execute_sql_helper
    description: helper
  - name: search_docs
    type: CORTEX_SEARCH_SERVICE_QUERY
    description: search
"""


def _access_rows() -> list[tuple]:
    many = json.dumps([{"objectName": f"DB.S.W{i}", "objectDomain": "Table"} for i in range(6)])
    return [
        (
            "q1",
            "ALICE",
            "ANALYST",
            "2026-01-01",
            json.dumps(
                [
                    {"objectName": "DB.S.CUSTOMERS", "objectDomain": "Table", "columns": [{"columnName": "EMAIL"}, {"x": 1}]},
                    {"objectName": "", "objectDomain": "Table"},
                    {"objectName": "DB.S.ORDERS", "objectDomain": "View"},
                ]
            ),
            [{"objectName": "DB.S.BASE"}, {"objectDomain": "Table"}],
            json.dumps([{"objectName": "DB.S.CUSTOMERS", "objectDomain": "Table", "columns": [{"columnName": "NAME"}]}]),
        ),
        ("q2", "BOB", None, "2026-01-02", [{"objectName": "DB.S.FINANCE", "objectDomain": "Table"}], None, "not-json"),
        ("q3", "", "", "2026-01-03", "{}", "[]", many),
        ("", "", "", "2026-01-04", [{"objectName": "DB.S.CUSTOMERS"}], 42, [{"objectName": ""}, {"objectName": "DB.S.T9"}]),
        ("", "", "", "2026-01-05", [], [], [{"objectName": "DB.S.T10"}]),
    ]


def _usage_rows() -> list[tuple]:
    rows: list[tuple] = []
    for i in range(7):
        status = "SUCCESS" if i < 3 else "FAILED"
        meta = {"input_tokens": 10, "output_tokens": 5, "model_name": "m1", "tool_calls": 100, "status": status}
        rows.append(("AGENT_HOT", "DB", "S", "ALICE", f"t{i}", f"e{i}", f"r{i}", 400_000, 0.5, json.dumps(meta)))
    rows.append(("AGENT_COLD", "DB", "S", "BOB", "t9", "e9", "r9", None, None, {"inputTokens": 3, "model": "m2", "toolCalls": 1}))
    rows.append(("AGENT_COLD", "DB", "S", "BOB", "t10", "e10", "r10", 5, 0.1, "not-json"))
    return rows


def _describe_notebook(sql: str) -> Any:
    if "NB_FAIL" in sql:
        raise RuntimeError("describe failed for NB_FAIL")
    return (
        ["property", "value"],
        [
            ("packages", "openai==1.2.0, pandas=2.0, ,torch,Sentence-Transformers==2"),
            ("query_text", "select snowflake.cortex.complete('m', 'x'), CORTEX.EMBED(1)"),
            ("comment", "plain"),
        ],
    )


def _describe_mcp(sql: str) -> Any:
    if "MCP_LIST" in sql:
        return (["property", "property_value"], [("spec", "- a\n- b")])
    return (
        ["name", "value"],
        [("spec", _SPEC_YAML), ("definition", "tools: [unclosed"), ("owner", "SYSADMIN")],
    )


def _grants_to_role(sql: str) -> Any:
    if '"BROKEN"' in sql:
        raise RuntimeError("Insufficient privileges; permission denied on role")
    return (
        ["privilege", "granted_on", "name"],
        [
            ("USAGE", "ROLE", "PARENT_ROLE"),
            ("USAGE", "ROLE", "PARENT_ROLE"),
            ("SELECT", "TABLE", "DB.S.T1"),
            ("SELECT", "TABLE", "DB.S.T1"),
            ("OWNERSHIP", "VIEW", "DB.S.V1"),
            ("USAGE", "DATABASE", "DB"),
            ("SELECT", "TABLE", ""),
        ],
    )


def _grants_of_role(sql: str) -> Any:
    if '"BROKEN"' in sql:
        raise RuntimeError("network timeout on grants of role")
    return (
        ["granted_to", "grantee_name"],
        [("USER", "ALICE"), ("USER", "ALICE"), ("ROLE", "CHILD_ROLE"), ("ROLE", "ANALYST"), ("USER", ""), ("SHARE", "X")],
    )


# Ordered: the first matching substring wins (several statements share view names).
RICH_ROUTES: list[tuple[str, Any]] = [
    ("SHOW CORTEX SEARCH SERVICES", (["name", "database_name", "schema_name"], [("svc_a", "DB1", "S1"), ("svc_b", "DB2", "S2")])),
    (
        "SHOW AGENTS IN ACCOUNT",
        (
            ["name", "database_name", "schema_name", "profile"],
            [("agent_a", "DB1", "S1", '{"display_name": "Agent A"}'), ("agent_b", "DB1", "S1", "not-json"), ("agent_c", "DB1", "S1", "")],
        ),
    ),
    (
        "SHOW MCP SERVERS IN ACCOUNT",
        (["name", "database_name", "schema_name"], [("mcp_ok", "DB1", "S1"), ("bad name", "DB1", "S1"), ("MCP_LIST", "", "")]),
    ),
    ("DESCRIBE MCP SERVER", _describe_mcp),
    (
        "INFORMATION_SCHEMA.QUERY_HISTORY()",
        (
            ["query_text", "user_name", "start_time"],
            [
                ("CREATE AGENT shadow_agent FROM SPEC", "ALICE", "t1"),
                ('CREATE OR REPLACE MCP SERVER IF NOT EXISTS db.sch."shadow_mcp" FROM x', "BOB", "t2"),
                ("create agent shadow_agent", "ALICE", "t3"),
                ("SELECT 1", "ALICE", "t4"),
            ],
        ),
    ),
    (
        "INFORMATION_SCHEMA.FUNCTIONS",
        (
            ["function_name", "argument_signature", "data_type", "function_language"],
            [("PY_UDF", "(X NUMBER)", "NUMBER", "PYTHON"), ("SQL_UDF", "()", "VARCHAR", "SQL"), ("SHORT_UDF",)],
        ),
    ),
    (
        "INFORMATION_SCHEMA.PROCEDURES",
        (
            ["procedure_name", "argument_signature", "data_type", "procedure_language"],
            [("JS_PROC", "()", "VARCHAR", "JAVASCRIPT"), ("SHORT_PROC", "(A)")],
        ),
    ),
    ("INFORMATION_SCHEMA.PACKAGES", (["package_name", "version"], [("numpy", "1.26"), ("NumPy", "1.27"), ("torch", "2.1")])),
    ("SHOW STREAMLITS IN ACCOUNT", (["name", "database_name", "schema_name"], [("app1", "DB1", "S1")])),
    (
        "SHOW NOTEBOOKS IN ACCOUNT",
        (
            ["name", "database_name", "schema_name", "owner", "comment"],
            [("NB_ONE", "DB1", "S1", "ALICE", "c1"), ("NB\x01BAD", "DB1", "S1", "", ""), ("NB_FAIL", "DB1", "S1", "BOB", "")],
        ),
    ),
    ("DESCRIBE NOTEBOOK", _describe_notebook),
    (
        "ACCOUNT_USAGE.ACCESS_HISTORY",
        (
            [
                "query_id",
                "user_name",
                "role_name",
                "query_start_time",
                "direct_objects_accessed",
                "base_objects_accessed",
                "objects_modified",
            ],
            _access_rows(),
        ),
    ),
    (
        "table_catalog, table_schema FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES",
        (
            ["grantee_name", "privilege", "granted_on", "name", "table_catalog", "table_schema"],
            [
                ("ANALYST", "SELECT", "TABLE", "CUSTOMERS", "DB", "S"),
                ("ANALYST", "SELECT", "VIEW", 'S2."a.b"', "DB", None),
                ("ANALYST", "SELECT", "TABLE", "DB3.S3.T3", "DB", "S"),
                ("", "SELECT", "TABLE", "X", "DB", "S"),
                ("ANALYST", "SELECT", "TABLE", None, "DB", "S"),
            ],
        ),
    ),
    (
        "ACCOUNT_USAGE.GRANTS_TO_ROLES",
        (
            ["grantee_name", "privilege", "granted_on", "name", "granted_by", "grant_option"],
            [
                ("ADMIN_ROLE", "OWNERSHIP", "TABLE", "DB.S.T1", "SYSADMIN", True),
                ("ADMIN_ROLE", "SELECT", "TABLE", "DB.S.T2", "SYSADMIN", False),
                ("OPS_ROLE", "monitor", "WAREHOUSE", "WH", "SYSADMIN", None),
                ("OPS_ROLE", "CREATE USER", "ACCOUNT", "ACCT", "SYSADMIN", 1),
                ("READER", "SELECT", "TABLE", "DB.S.T1", "SYSADMIN", False),
            ],
        ),
    ),
    ("ACCOUNT_USAGE.GRANTS_TO_USERS", (["grantee_name", "role"], [("ALICE", "ANALYST"), ("BOB", ""), ("", "X")])),
    (
        "COUNT(DISTINCT tag_name)",
        (
            ["object_database", "object_schema", "object_name", "tags", "cols"],
            [("DB", "S", "CUSTOMERS", 2, 3), ("DB", "S", "PAYMENTS", None, 1)],
        ),
    ),
    (
        "ACCOUNT_USAGE.TAG_REFERENCES",
        (
            ["tag_name", "tag_value", "object_database", "object_schema", "object_name", "column_name", "domain"],
            [
                ("PII", "EMAIL", "DB", "S", "CUSTOMERS", "EMAIL", "COLUMN"),
                ("CONFIDENTIAL", "YES", "DB", "S", "FINANCE", None, "TABLE"),
                ("PHI_TAG", "X", "", "", "DB.S.T9", None, "TABLE"),
                ("FINANCIAL", "Y", "DB", "S", "W0", None, "TABLE"),
            ],
        ),
    ),
    (
        "CORTEX_AGENT_USAGE_HISTORY",
        (
            [
                "agent_name",
                "agent_database_name",
                "agent_schema_name",
                "user_name",
                "start_time",
                "end_time",
                "request_id",
                "tokens",
                "token_credits",
                "metadata",
            ],
            _usage_rows(),
        ),
    ),
    (
        "ACCOUNT_USAGE.QUERY_HISTORY",
        (
            [
                "query_id",
                "query_text",
                "user_name",
                "role_name",
                "start_time",
                "end_time",
                "execution_status",
                "warehouse_name",
                "database_name",
                "schema_name",
                "query_type",
                "rows_produced",
                "bytes_scanned",
                "total_elapsed_time",
            ],
            [
                ("h1", "CREATE OR REPLACE AGENT a1", "ALICE", "R", "s", "e", "SUCCESS", "WH", "DB", "S", "CREATE", 0, 10, 5),
                (
                    "h2",
                    "select snowflake.cortex.complete('x')",
                    "BOB",
                    "R",
                    "s",
                    "e",
                    "SUCCESS",
                    "WH",
                    "DB",
                    "S",
                    "SELECT",
                    None,
                    None,
                    None,
                ),
                ("h3", "select 'mcp server listing'", "BOB", "R", "s", "e", "FAIL", "WH", "DB", "S", "SELECT", 1, 1, 1),
                ("h4", "CALL SYSTEM$EXECUTE_SQL('x')", "EVE", "R", "s", "e", "SUCCESS", "WH", "DB", "S", "CALL", 2, 2, 2),
            ],
        ),
    ),
    (
        "AI_OBSERVABILITY_EVENTS",
        (
            [
                "event_id",
                "event_type",
                "agent_name",
                "timestamp",
                "duration_ms",
                "status",
                "model_name",
                "input_tokens",
                "output_tokens",
                "tool_name",
                "tool_input",
                "tool_output_summary",
                "user_feedback",
                "trace_id",
                "parent_event_id",
            ],
            [
                ("ev1", "TOOL_CALL", "AGENT_HOT", "ts1", 12, "OK", "m1", 1, 2, "search", "x" * 600, "y" * 700, "", "tr1", ""),
                ("ev2", "LLM", "AGENT_HOT", "ts2", None, "ERR", "m1", None, None, "", "", "", "thumbs_down", "tr1", "ev1"),
            ],
        ),
    ),
    (
        "ACCOUNT_USAGE.TABLES",
        (
            ["table_catalog", "table_schema", "table_name", "row_count", "bytes"],
            [("DB", "S", "CUSTOMERS", 10, 2048), ("DB", "S", "EMPTY", None, None), ("DB", "S", "", 1, 1)],
        ),
    ),
    ("ACCOUNT_USAGE.VIEWS", (["table_catalog", "table_schema", "table_name"], [("DB", "S", "ORDERS_V")])),
    (
        "OBJECT_DEPENDENCIES",
        (
            [
                "referencing_database",
                "referencing_schema",
                "referencing_object_name",
                "referencing_object_domain",
                "referenced_database",
                "referenced_schema",
                "referenced_object_name",
                "referenced_object_domain",
                "dependency_type",
            ],
            [
                ("DB", "S", "ORDERS_V", "VIEW", "DB", "S", "CUSTOMERS", "TABLE", "BY_NAME"),
                ("DB", "S", "", "VIEW", "DB", "S", "CUSTOMERS", "TABLE", "BY_NAME"),
            ],
        ),
    ),
    (
        "SHOW ROLES",
        (
            ["name", "owner", "comment"],
            [("ANALYST", "SECURITYADMIN", "c"), ("", "x", "y"), ("BROKEN", None, None), ("BAD\x02ROLE", "", "")],
        ),
    ),
    (
        "SHOW USERS",
        (["name", "default_role", "disabled"], [("ALICE", "ANALYST", "false"), ("SVC", None, "true"), ("", "", "")]),
    ),
    ("SHOW GRANTS TO ROLE", _grants_to_role),
    ("SHOW GRANTS OF ROLE", _grants_of_role),
    (
        "SHOW SHARES",
        (
            ["name", "kind", "database_name", "to", "listing_global_name"],
            [
                ("PARTNER_SHARE", "OUTBOUND", "DB", "ORG2.ACCT9, ORG3.ACCT1", ""),
                ("PUBLIC_LISTING", "outbound", "DB", None, "GLOBAL.LISTING"),
                ("INBOUND_FROM_VENDOR", "INBOUND", "VDB", "", ""),
            ],
        ),
    ),
    (
        "SHOW STAGES IN ACCOUNT",
        (
            ["name", "database_name", "schema_name", "url"],
            [
                ("EXPORT_STAGE", "DB", "S", "s3://test-exports/dump/"),
                ("AZ_STAGE", "DB", "S", "azure://acct.blob.core.windows.net/c"),
                ("FTP_STAGE", "DB", "S", "ftp://example/x"),
                ("INTERNAL_STAGE", "DB", "S", None),
            ],
        ),
    ),
    (
        "POLICY_REFERENCES",
        (["ref_database_name", "ref_schema_name", "ref_entity_name"], [("db", "s", "payments")]),
    ),
    (
        "WITH ordered",
        (["user_name", "rapid_switches"], [("ALICE", 3), ("BOB", None)]),
    ),
    (
        "LOGIN_HISTORY",
        (
            ["user_name", "distinct_ips", "logins", "failed"],
            [("ALICE", 25, 40, 7), ("BOB", 2, None, None), ("EVE", 21, 3, 5)],
        ),
    ),
    ("SHOW PARAMETERS LIKE 'NETWORK_POLICY'", (["key", "value"], [("NETWORK_POLICY", ""), ("NETWORK_POLICY", "CORP_ONLY")])),
    (
        "SHOW NETWORK POLICIES",
        (["name", "entries_in_allowed_ip_list", "entries_in_blocked_ip_list"], [("CORP_ONLY", 3, None)]),
    ),
    (
        "ACCOUNT_USAGE.USERS",
        (
            ["name", "disabled", "has_password", "has_rsa_public_key", "ext_authn_duo", "default_role", "type", "has_mfa"],
            [
                ("ALICE", "false", "true", "false", "false", "ANALYST", "PERSON", None),
                ("BOB", "false", "true", "true", "true", "", None, None),
                ("SVC", "false", "true", "false", "false", "", "SERVICE", None),
                ("OLD", "true", "true", "false", "false", "", "PERSON", None),
                ("FED", "false", "false", "false", "false", "", "", "true"),
                ("", "false", "true", "false", "false", "", "", None),
            ],
        ),
    ),
    (
        "SHOW WAREHOUSES",
        (
            ["name", "size", "state", "auto_suspend", "type"],
            [
                ("WH_A", "XSMALL", "STARTED", 60, "STANDARD"),
                ("WH_B", None, None, 0, None),
                ("WH_C", "L", "S", None, ""),
                ("", "", "", 1, ""),
            ],
        ),
    ),
    (
        "SHOW DATABASES",
        (
            ["name", "owner", "retention_time", "is_default"],
            [("DB", "SYSADMIN", 1, "Y"), ("SCRATCH", None, 0, "N"), ("", "", 1, "")],
        ),
    ),
    (
        "SHOW SCHEMAS IN ACCOUNT",
        (
            ["name", "database_name", "owner"],
            [("S", "DB", "SYSADMIN"), ("INFORMATION_SCHEMA", "DB", ""), ("ORPHAN", "", ""), ("", "DB", "")],
        ),
    ),
    (
        "SHOW ORGANIZATION ACCOUNTS",
        (
            ["account_locator", "account_name", "organization_name", "snowflake_region", "edition", "is_org_admin"],
            [
                ("LOC1", "PROD", "TESTORG", "aws_us_west_2", "ENTERPRISE", "false"),
                ("", "DEV", "", "", "STANDARD", "YES"),
                ("", "", "", "", "", ""),
                ("LOC3", "", "OTHERORG", "", "", None),
            ],
        ),
    ),
    (
        "SHOW TASKS IN ACCOUNT",
        (
            ["name", "database_name", "schema_name", "warehouse", "schedule", "state", "owner"],
            [
                ("T1", "DB", "S", "WH", "1 MINUTE", "suspended", "SYSADMIN"),
                ("T2", None, None, None, None, "started", None),
                ("", "", "", "", "", "", ""),
            ],
        ),
    ),
    (
        "SHOW STREAMS IN ACCOUNT",
        (
            ["name", "database_name", "schema_name", "table_name", "stale", "type"],
            [("ST1", "DB", "S", "DB.S.CUSTOMERS", "true", "DELTA"), ("ST2", "DB", "", None, "false", None), ("", "", "", "", "", "")],
        ),
    ),
    (
        "SHOW PIPES IN ACCOUNT",
        (
            ["name", "database_name", "schema_name", "definition", "notification_channel", "integration"],
            [
                ("P1", "DB", "S", 'COPY INTO t FROM @DB.S."LANDING"/x', "arn:test:sqs", None),
                ("P2", "DB", "S", "COPY INTO t FROM (select 1)", None, "NOTIFY_INT"),
                ("P3", "DB", "S", None, None, None),
                ("", "", "", "", "", ""),
            ],
        ),
    ),
    (
        "SHOW INTEGRATIONS",
        (
            ["name", "type", "category", "enabled", "comment"],
            [
                ("EXT_ACCESS", "EXTERNAL_ACCESS", "EXTERNAL ACCESS", "true", "c" * 250),
                ("OKTA", "SAML2", "SECURITY", True, None),
                ("S3_INT", "EXTERNAL_STAGE", "STORAGE", "false", ""),
                ("API_INT", "API - AWS", None, "true", ""),
                ("", "X", "Y", "true", ""),
            ],
        ),
    ),
    (
        "SHOW ICEBERG TABLES IN ACCOUNT",
        (
            ["name", "database_name", "schema_name", "catalog", "catalog_source", "base_location", "external_volume"],
            [
                ("ICE1", "DB", "S", "POLARIS", "OPEN_CATALOG", "s3://test-lake/ice1", None),
                ("ICE2", "DB", "S", "SNOWFLAKE", "SNOWFLAKE", None, "gcs://vol/path"),
                ("ICE3", None, None, None, None, None, None),
                ("", "", "", "", "", "", ""),
            ],
        ),
    ),
    (
        "SHOW EXTERNAL TABLES IN ACCOUNT",
        (
            ["name", "database_name", "schema_name", "location", "file_format_name", "file_format_type"],
            [
                ("EXT1", "DB", "S", "@DB.S.LANDING/raw/", None, "PARQUET"),
                ("EXT2", "DB", "S", "s3://x/y", "FF", ""),
                ("", "", "", "", "", ""),
            ],
        ),
    ),
]


class _Cursor:
    def __init__(self, conn: "_Conn") -> None:
        self._conn = conn
        self.description: Any = None
        self._rows: list = []

    def execute(self, sql: str, *_a: Any, **_k: Any) -> None:
        normalized = " ".join(sql.split())
        self._conn.sql.append(normalized)
        self.description, self._rows = self._conn.respond(normalized)

    def fetchall(self) -> list:
        return list(self._rows)

    def close(self) -> None:
        self._conn.cursor_closes += 1


class _Conn:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.sql: list[str] = []
        self.cursor_closes = 0
        self.closed = 0

    def cursor(self) -> _Cursor:
        return _Cursor(self)

    def close(self) -> None:
        self.closed += 1

    def respond(self, sql: str) -> tuple[Any, list]:
        if self.mode == "denied":
            raise RuntimeError("SQL access control error: Insufficient privileges; permission denied for test-object")
        if self.mode == "missing":
            raise RuntimeError(f"SQL compilation error: [{sql[:160]}] does not exist or syntax error")
        if self.mode == "generic":
            raise RuntimeError("network timeout contacting test endpoint")
        for needle, route in RICH_ROUTES:
            if needle in sql:
                columns, rows = route(sql) if callable(route) else route
                break
        else:
            columns, rows = ["name"], []
        if self.mode == "empty":
            return [(c,) for c in columns], []
        if self.mode == "nodesc":
            return None, rows
        return [(c,) for c in columns], rows


class _DatabaseError(Exception):
    pass


def _install_connector(monkeypatch: pytest.MonkeyPatch, state: dict[str, Any]) -> None:
    pkg = types.ModuleType("snowflake")
    connector = types.ModuleType("snowflake.connector")
    errors = types.ModuleType("snowflake.connector.errors")
    errors.DatabaseError = _DatabaseError  # type: ignore[attr-defined]

    def connect(**kwargs: Any) -> _Conn:
        state["connects"].append(dict(sorted(kwargs.items())))
        failure = state.get("connect_error")
        if failure is not None:
            raise failure
        conn = _Conn(state["mode"])
        state["conns"].append(conn)
        return conn

    connector.connect = connect  # type: ignore[attr-defined]
    connector.errors = errors  # type: ignore[attr-defined]
    pkg.connector = connector  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "snowflake", pkg)
    monkeypatch.setitem(sys.modules, "snowflake.connector", connector)
    monkeypatch.setitem(sys.modules, "snowflake.connector.errors", errors)


def _ser(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _ser(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): ("<now>" if k == "discovered_at" and v else _ser(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_ser(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(json.dumps(_ser(v), sort_keys=True) for v in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "to_dict"):
        return _ser(value.to_dict())
    return repr(value)


def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith(("SNOWFLAKE_", "AGENT_BOM_SNOWFLAKE_")):
            monkeypatch.delenv(key, raising=False)


def _run(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    call: Callable[[], Any],
    *,
    mode: str = "rich",
    env: dict[str, str] | None = None,
    connect_error: BaseException | None = None,
    sdk_missing: bool = False,
) -> dict[str, Any]:
    _clean_env(monkeypatch)
    for key, value in (env if env is not None else {"SNOWFLAKE_ACCOUNT": "test-acct", "SNOWFLAKE_USER": "test-user"}).items():
        monkeypatch.setenv(key, value)
    state: dict[str, Any] = {"mode": mode, "connects": [], "conns": [], "connect_error": connect_error}
    _install_connector(monkeypatch, state)
    if sdk_missing:
        for name in ("snowflake", "snowflake.connector", "snowflake.connector.errors"):
            monkeypatch.setitem(sys.modules, name, None)
    consume_coverage_warnings()
    caplog.clear()
    out: dict[str, Any] = {}
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            out["result"] = _ser(call())
        except Exception as exc:  # noqa: BLE001 — the raised contract is pinned too
            out["raised"] = [type(exc).__name__, str(exc)]
    out["connects"] = state["connects"]
    out["sql"] = [c.sql for c in state["conns"]]
    out["closes"] = [[c.cursor_closes, c.closed] for c in state["conns"]]
    out["logs"] = [[r.levelname, r.name, r.getMessage()] for r in caplog.records if r.name.startswith("agent_bom")]
    out["coverage"] = consume_coverage_warnings()
    out["py_warnings"] = [[w.category.__name__, str(w.message)] for w in caught if "agent_bom" in w.filename]
    return out


ENTRYPOINTS: dict[str, Callable[[], Any]] = {
    "discover": lambda: sf.discover(database="DB1", schema="S1"),
    "discover_governance": lambda: sf.discover_governance(days=7),
    "discover_activity": lambda: sf.discover_activity(days=999),
    "discover_object_dependencies": lambda: sf.discover_object_dependencies(),
    "discover_identity_live": lambda: sf.discover_identity_live(),
    "discover_data_exfil": lambda: sf.discover_data_exfil(),
    "discover_login_anomalies": lambda: sf.discover_login_anomalies(days=3),
    "discover_auth_posture": lambda: sf.discover_auth_posture(),
    "discover_snowflake_services": lambda: sf.discover_snowflake_services(),
    "discover_organization": lambda: sf.discover_organization(force=True, now="2026-01-01T00:00:00Z"),
    "discover_snowflake_pipeline": lambda: sf.discover_snowflake_pipeline(),
    "discover_snowflake_integrations": lambda: sf.discover_snowflake_integrations(),
    "discover_snowflake_external_data": lambda: sf.discover_snowflake_external_data(),
}
MODES = ("rich", "empty", "nodesc", "denied", "missing", "generic")


def _enrich(conn: Any = None, account: str | None = None) -> dict[str, Any]:
    report = types.SimpleNamespace()
    sf.enrich_report_with_snowflake_estate(report, conn=conn, account=account)
    return dict(sorted(vars(report).items()))


def _enrich_borrowed() -> dict[str, Any]:
    lent = _Conn("rich")
    payload = _enrich(conn=lent, account="lent-acct")
    return {"report": payload, "sql": lent.sql, "closes": [lent.cursor_closes, lent.closed]}


def _helpers() -> dict[str, Any]:
    def attempt(fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            return ["raised", type(exc).__name__, str(exc)]

    graph = {
        "grants": [{"role": "R", "privilege": "SELECT", "object_fqn": "A", "src": "lag"}, "junk"],
        "role_memberships": [
            {"user": "U", "role": "R", "src": "lag"},
            {"role": "C", "parent": "P", "src": "lag"},
            "junk",
        ],
        "users": [{"name": "U0"}],
    }
    live = {
        "status": "ok",
        "grants": [{"role": "R", "privilege": "SELECT", "object_fqn": "A", "src": "live"}, {"role": "R2"}, 3],
        "role_memberships": [{"user": "U", "role": "R", "src": "live"}, {"role": "C", "parent": "P", "member_type": "role"}, 7],
        "users": [{"name": "U0"}, {"name": "U1"}, {"name": "U1"}, "junk"],
    }
    return {
        "merge_ok": sf.merge_live_identity_into_object_graph(json.loads(json.dumps(graph)), live),
        "merge_no_users": sf.merge_live_identity_into_object_graph({"grants": None}, {"status": "ok"}),
        "merge_not_ok": sf.merge_live_identity_into_object_graph({"grants": [1]}, {"status": "error"}),
        "merge_live_not_dict": sf.merge_live_identity_into_object_graph({"grants": [1]}, None),  # type: ignore[arg-type]
        "merge_graph_not_dict": sf.merge_live_identity_into_object_graph(None, live),  # type: ignore[arg-type]
        "parse_create": [
            sf._parse_create_statement_name(q)
            for q in ("CREATE AGENT a.b.c", 'create or replace mcp server  if not exists "X"', "DROP AGENT z", "")
        ],
        "classify": [sf._classify_agent_query(q) for q in ("ALTER AGENT x", "select snowflake.ml.forecast()", "select 1")],
        "days": [attempt(lambda d=d: sf._coerce_snowflake_days(d, max_days=30)) for d in (5, "40", 0, "x", None)],
        "validate": [attempt(lambda n=n: sf._validate_sf_identifier(n)) for n in ("OK_1.$x", "bad name", "1abc")],
        "quote": [attempt(lambda n=n: sf._quote_sf_identifier(n)) for n in ('a"b c', "", "x\ny", 5)],
        "grant_fqn": [
            sf._grant_object_fqn(*args)
            for args in (("T", "DB", "S"), ("S.T", "DB", "S"), ("DB.S.T", "X", "Y"), ('"a.b"', "DB", "S"), ("T", "", ""))
        ],
        "external_location": [sf._parse_external_location(u) for u in ("s3://b/k", "S3GOV://b", "http://x", "", "gcs://only")],
        "json_field": [sf._parse_json_field(v) for v in (None, [1], "[2]", "{}", "bad", 5)],
    }


def _auth_matrix(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    cases = [
        ({}, None),
        ({}, "oauth"),
        ({"SNOWFLAKE_AUTHENTICATOR": "SNOWFLAKE_JWT", "SNOWFLAKE_PRIVATE_KEY_PATH": "/tmp/test-key.p8"}, None),
        ({"SNOWFLAKE_AUTHENTICATOR": "snowflake_jwt"}, None),
        ({"SNOWFLAKE_PRIVATE_KEY_PATH": "/tmp/test-key.p8", "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE": "test-pass"}, None),
        ({"SNOWFLAKE_PASSWORD": "test-password"}, None),
    ]
    out = []
    for env, authenticator in cases:
        _clean_env(monkeypatch)
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        kwargs: dict[str, Any] = {"account": "a"}
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            sf._resolve_snowflake_auth(kwargs, authenticator)
        out.append([sorted(kwargs.items()), [[w.category.__name__, str(w.message)] for w in caught]])
    return out


def _build_cases(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    caplog.set_level(logging.DEBUG)
    cases: dict[str, Any] = {}
    for name, call in ENTRYPOINTS.items():
        for mode in MODES:
            cases[f"{name}/{mode}"] = _run(monkeypatch, caplog, call, mode=mode)
        cases[f"{name}/no_account"] = _run(monkeypatch, caplog, call, env={})
        cases[f"{name}/connect_error"] = _run(monkeypatch, caplog, call, connect_error=RuntimeError("connect refused for test-acct"))
        cases[f"{name}/connect_cloud_error"] = _run(monkeypatch, caplog, call, connect_error=CloudDiscoveryError("broker unavailable"))
        cases[f"{name}/sdk_missing"] = _run(monkeypatch, caplog, call, sdk_missing=True)
        cases[f"{name}/password_env"] = _run(
            monkeypatch,
            caplog,
            call,
            mode="empty",
            env={"SNOWFLAKE_ACCOUNT": "test-acct", "SNOWFLAKE_PASSWORD": "test-password"},
        )
    cases["discover_organization/flag_off"] = _run(monkeypatch, caplog, lambda: sf.discover_organization())
    cases["discover_organization/flag_on"] = _run(
        monkeypatch, caplog, lambda: sf.discover_organization(), env={"SNOWFLAKE_ACCOUNT": "LOC1", "AGENT_BOM_SNOWFLAKE_ORG": "yes"}
    )
    cases["discover_identity_live/max_roles_1"] = _run(
        monkeypatch, caplog, sf.discover_identity_live, env={"SNOWFLAKE_ACCOUNT": "a", "AGENT_BOM_SNOWFLAKE_MAX_ROLES": "1"}
    )
    cases["discover_identity_live/max_roles_bad"] = _run(
        monkeypatch, caplog, sf.discover_identity_live, env={"SNOWFLAKE_ACCOUNT": "a", "AGENT_BOM_SNOWFLAKE_MAX_ROLES": "abc"}
    )
    cases["discover/explicit_args"] = _run(
        monkeypatch, caplog, lambda: sf.discover(account="arg-acct", user="u", authenticator="oauth"), mode="empty", env={}
    )
    for mode in MODES:
        cases[f"enrich/{mode}"] = _run(
            monkeypatch, caplog, _enrich, mode=mode, env={"SNOWFLAKE_ACCOUNT": "test-acct", "AGENT_BOM_SNOWFLAKE_ORG": "1"}
        )
    cases["enrich/org_off"] = _run(monkeypatch, caplog, _enrich)
    cases["enrich/no_account"] = _run(monkeypatch, caplog, _enrich, env={})
    cases["enrich/connect_cloud_error"] = _run(monkeypatch, caplog, _enrich, connect_error=CloudDiscoveryError("broker unavailable"))
    cases["enrich/borrowed"] = _run(monkeypatch, caplog, _enrich_borrowed, env={"AGENT_BOM_SNOWFLAKE_ORG": "1"})
    cases["helpers"] = _run(monkeypatch, caplog, _helpers)
    cases["auth_matrix"] = _auth_matrix(monkeypatch)
    return cases


_WALL_CLOCK_KEYS = frozenset({"discovered_at", "first_seen", "last_seen", "captured_at"})


def _scrub_wall_clock(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("<now>" if k in _WALL_CLOCK_KEYS and v else _scrub_wall_clock(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_wall_clock(v) for v in value]
    return value


def test_snowflake_discovery_matches_golden(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    actual = _scrub_wall_clock(json.loads(json.dumps(_build_cases(monkeypatch, caplog), sort_keys=False, default=repr)))
    if UPDATE:
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(actual, indent=1, ensure_ascii=True) + "\n")
    expected = json.loads(GOLDEN.read_text())
    assert list(actual) == list(expected)
    for key in expected:
        assert actual[key] == expected[key], key


def _raise(*_a: Any, **_k: Any) -> Any:
    raise RuntimeError("patched-sentinel")


# Façade attributes tests patch whose readers may live outside the façade.
PATCH_POINTS: list[tuple[str, Callable[[], Any], str]] = [
    ("_get_connection", sf.discover_object_dependencies, "patched-sentinel"),
    ("_get_connection", sf.discover_identity_live, "patched-sentinel"),
    ("_get_connection", sf.discover_data_exfil, "patched-sentinel"),
    ("_get_connection", sf.discover_login_anomalies, "patched-sentinel"),
    ("_get_connection", sf.discover_auth_posture, "patched-sentinel"),
    ("_get_connection", sf.discover_snowflake_services, "patched-sentinel"),
    ("_get_connection", lambda: sf.discover_organization(force=True), "patched-sentinel"),
    ("_get_connection", sf.discover_snowflake_pipeline, "patched-sentinel"),
    ("_get_connection", sf.discover_snowflake_integrations, "patched-sentinel"),
    ("_get_connection", sf.discover_snowflake_external_data, "patched-sentinel"),
]


@pytest.mark.parametrize(("name", "call", "needle"), PATCH_POINTS)
def test_facade_patch_points_steer_discovery(monkeypatch: pytest.MonkeyPatch, name: str, call: Callable[[], Any], needle: str) -> None:
    _clean_env(monkeypatch)
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "test-acct")
    _install_connector(monkeypatch, {"mode": "rich", "connects": [], "conns": []})
    monkeypatch.setattr(sf, name, _raise)
    result = call()
    assert any(needle in w for w in result["warnings"]), result["warnings"]


@pytest.mark.parametrize(
    "name",
    [
        "discover_object_dependencies",
        "discover_identity_live",
        "discover_login_anomalies",
        "discover_data_exfil",
        "discover_auth_posture",
        "discover_snowflake_services",
        "discover_organization",
        "discover_snowflake_pipeline",
        "discover_snowflake_integrations",
        "discover_snowflake_external_data",
        "discover_governance",
        "discover_activity",
    ],
)
def test_facade_patch_points_steer_estate_enrichment(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    calls: list[str] = []

    def fake(*_a: Any, **_k: Any) -> Any:
        calls.append(name)
        raise RuntimeError("skip")

    for other in (
        "discover_object_dependencies",
        "discover_identity_live",
        "discover_login_anomalies",
        "discover_data_exfil",
        "discover_auth_posture",
        "discover_snowflake_services",
        "discover_organization",
        "discover_snowflake_pipeline",
        "discover_snowflake_integrations",
        "discover_snowflake_external_data",
        "discover_governance",
        "discover_activity",
    ):
        monkeypatch.setattr(sf, other, fake if other == name else (lambda *_a, **_k: {"status": "disabled"}))
    sf.enrich_report_with_snowflake_estate(types.SimpleNamespace())
    assert calls == [name]


def test_facade_patch_point_org_account_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "test-acct")
    _install_connector(monkeypatch, {"mode": "rich", "connects": [], "conns": []})
    monkeypatch.setattr(sf, "_MAX_ORG_ACCOUNTS", 1)
    result = sf.discover_organization(force=True)
    assert [a["locator"] for a in result["accounts"]] == ["LOC1"]
    assert any("capped at 1 accounts" in w for w in result["warnings"])


def test_facade_patch_point_org_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    monkeypatch.setattr(sf, "org_enabled", lambda: True)
    assert sf.discover_organization()["status"] != "disabled"


def test_facade_patch_point_borrowed_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "test-acct")
    state: dict[str, Any] = {"mode": "rich", "connects": [], "conns": []}
    _install_connector(monkeypatch, state)
    lent = _Conn("empty")
    monkeypatch.setattr(sf, "_active_borrowed_connection", lambda: lent)
    sf.discover_governance()
    sf.discover_activity()
    assert state["connects"] == [] and lent.closed == 2
