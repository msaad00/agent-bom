"""Bounded, read-only, multi-table DSPM database content scan (issue #4157).

These exercise the orchestration that connects the redacted db_data_classifier to
real read-only database discovery: metadata-derived bounded table enumeration,
per-table bounded sampling, EXPLICIT coverage states (executed/partial/skipped/
unevaluable/failed), and redacted-only evidence. A live PostgreSQL run (gated on
``AGENT_BOM_POSTGRES_URL``) is the real-DB proof.
"""

from __future__ import annotations

import os
import uuid

import pytest

from agent_bom.cloud.db_content_scan import (
    STATE_EXECUTED,
    STATE_SKIPPED,
    STATE_UNEVALUABLE,
    DatabaseScanClassification,
    scan_database_content,
)

# ── Fake DB-API doubles ───────────────────────────────────────────────────────


class _FakeCursor:
    def __init__(self, tables, table_rows, denied):
        self._tables = tables
        self._table_rows = table_rows
        self._denied = denied
        self.description = None
        self._rows: list = []
        self.executed: list[str] = []

    def execute(self, query, params=None):  # noqa: ANN001
        self.executed.append(query)
        q = query.lower()
        if "information_schema.tables" in q:
            self.description = (("table_schema",), ("table_name",))
            self._rows = [(s, t) for (s, t) in self._tables]
            return
        # A per-table sample: SELECT * FROM "schema"."table" LIMIT n
        for schema, table in self._tables:
            needle = f'"{schema}"."{table}"'
            if needle in query:
                if (schema, table) in self._denied:
                    raise RuntimeError(f"permission denied for table {table}")
                cols, rows = self._table_rows[(schema, table)]
                self.description = tuple((c,) for c in cols)
                self._rows = list(rows)
                return
        raise RuntimeError("unexpected query")

    def fetchmany(self, size):  # noqa: ANN001
        out = self._rows[:size]
        self._rows = self._rows[size:]
        return out

    def close(self):  # noqa: D401
        pass


class _FakeConn:
    def __init__(self, tables, table_rows, denied=()):  # noqa: ANN001
        self._tables = tables
        self._table_rows = table_rows
        self._denied = set(denied)

    def cursor(self):
        return _FakeCursor(self._tables, self._table_rows, self._denied)


def _build_conn():
    tables = [
        ("app", "customers"),
        ("app", "audit_log"),
        ("app", "secrets"),
        ("app", "metrics"),
    ]
    table_rows = {
        ("app", "customers"): (
            ["email", "ssn", "note"],
            [("alice@example.com", "123-45-6789", "vip"), ("bob@example.com", "234-56-7890", "n/a")],
        ),
        ("app", "audit_log"): (["action", "at"], [("login", "2026-07-18"), ("logout", "2026-07-18")]),
        ("app", "secrets"): (["name", "value"], [("stripe", "api_key=abcdef0123456789abcdef0123")]),
        ("app", "metrics"): (["metric", "value"], [("cpu", "0.5"), ("mem", "0.7")]),
    }
    return _FakeConn(tables, table_rows), tables, table_rows


# ── Unit behaviour ────────────────────────────────────────────────────────────


def test_scan_classifies_sensitive_tables_with_redacted_evidence():
    conn, _tables, _rows = _build_conn()

    result = scan_database_content(conn, source="postgres://acct/app", max_rows=10)
    payload = result.to_dict()

    assert payload["schema_version"] == "agent-bom.dspm.database_scan.v1"
    assert payload["status"] == "ok"
    assert payload["data_sensitivity"] == "sensitive"
    # customers (email+ssn) and secrets (api key) are sensitive; audit_log/metrics clean
    assert payload["findings_by_type"].get("ssn") == 2
    assert payload["findings_by_type"].get("email") == 2
    assert any(k.startswith("secret:") for k in payload["findings_by_type"])
    # Redaction: no raw value anywhere in the serialized evidence.
    text = repr(payload)
    assert "alice@example.com" not in text
    assert "123-45-6789" not in text
    assert "api_key=abcdef0123456789abcdef0123" not in text
    assert payload["redaction"] == "raw row values and matched values are not stored"


def test_clean_table_is_executed_not_flagged_sensitive():
    conn, _tables, _rows = _build_conn()

    result = scan_database_content(conn, source="postgres://acct/app", max_rows=10)
    by_table = {(t.schema, t.table): t for t in result.tables}

    metrics = by_table[("app", "metrics")]
    assert metrics.state == STATE_EXECUTED
    assert metrics.total_findings == 0
    assert metrics.data_sensitivity == "none"


def test_denied_table_is_unevaluable_not_clean():
    conn_ok, tables, table_rows = _build_conn()
    conn = _FakeConn(tables, table_rows, denied=[("app", "secrets")])

    result = scan_database_content(conn, source="postgres://acct/app", max_rows=10)
    by_table = {(t.schema, t.table): t for t in result.tables}

    secrets = by_table[("app", "secrets")]
    assert secrets.state == STATE_UNEVALUABLE
    assert secrets.total_findings == 0
    # Honesty: an unreadable table never claims "none/clean".
    assert secrets.data_sensitivity == "unevaluable"
    # Scan status downgrades from ok when any table could not be evaluated.
    assert result.to_dict()["status"] == "partial"
    assert result.to_dict()["tables_by_state"][STATE_UNEVALUABLE] == 1


def test_scope_marks_out_of_scope_tables_skipped_not_silently_dropped():
    conn, _tables, _rows = _build_conn()

    result = scan_database_content(
        conn,
        source="postgres://acct/app",
        include_tables=["app.customers"],
        max_rows=10,
    )
    by_table = {(t.schema, t.table): t for t in result.tables}

    assert by_table[("app", "customers")].state == STATE_EXECUTED
    assert by_table[("app", "secrets")].state == STATE_SKIPPED
    assert by_table[("app", "metrics")].state == STATE_SKIPPED
    # Skipped tables carry no sensitivity verdict (not evaluated).
    assert by_table[("app", "secrets")].data_sensitivity == "skipped"


def test_enumeration_failure_is_failed_not_clean():
    class _Boom:
        def cursor(self):
            class _C:
                description = None

                def execute(self, *a, **k):  # noqa: ANN002, ANN003
                    raise RuntimeError("password=hunter2 could not list tables")

                def fetchmany(self, size):  # noqa: ANN001
                    return []

                def close(self):
                    pass

            return _C()

    result = scan_database_content(_Boom(), source="postgres://acct/app")
    payload = result.to_dict()

    assert payload["status"] == "failed"
    assert payload["tables_total"] == 0
    assert payload["data_sensitivity"] == "unevaluable"
    # Secret in the driver error is sanitized out of persisted evidence.
    assert "hunter2" not in repr(payload)


def test_max_tables_budget_is_enforced():
    conn, _tables, _rows = _build_conn()

    result = scan_database_content(conn, source="postgres://acct/app", max_tables=2, max_rows=10)

    assert result.tables_total == 2
    assert len(result.tables) == 2


# ── Live PostgreSQL proof (real-DB, read-only) ────────────────────────────────

_PG_URL = os.environ.get("AGENT_BOM_DSPM_TEST_POSTGRES_URL") or os.environ.get("AGENT_BOM_POSTGRES_URL", "")


@pytest.mark.skipif(not _PG_URL, reason="AGENT_BOM_POSTGRES_URL not set")
def test_live_postgres_scan_is_read_only_redacted_and_honest():
    import psycopg

    schema = f"dspm_test_{uuid.uuid4().hex[:8]}"
    reader_role = f"{schema}_reader"
    with psycopg.connect(_PG_URL, autocommit=True) as admin:
        with admin.cursor() as cur:
            cur.execute(f'CREATE SCHEMA "{schema}"')
            cur.execute(f'CREATE TABLE "{schema}"."customers" (email text, ssn text, pan text)')
            cur.execute(
                f"INSERT INTO \"{schema}\".\"customers\" VALUES "
                "('alice@example.com','123-45-6789','4111111111111111'),"
                "('bob@example.com','234-56-7890','5500005555555559')"
            )
            cur.execute(f'CREATE TABLE "{schema}"."api_secrets" (name text, token text)')
            cur.execute(
                f"INSERT INTO \"{schema}\".\"api_secrets\" VALUES "
                "('stripe','api_key=abcdef0123456789abcdef0123456789')"
            )
            cur.execute(f'CREATE TABLE "{schema}"."metrics" (metric text, value double precision)')
            cur.execute(f"INSERT INTO \"{schema}\".\"metrics\" VALUES ('cpu',0.5),('mem',0.7)")
            cur.execute(f'CREATE TABLE "{schema}"."locked" (email text)')
            cur.execute(f"INSERT INTO \"{schema}\".\"locked\" VALUES ('carol@example.com')")
            # A least-privilege reader that is DENIED the locked table → unevaluable.
            cur.execute(f'DROP ROLE IF EXISTS "{reader_role}"')
            cur.execute(f'CREATE ROLE "{reader_role}" LOGIN PASSWORD \'readpw\'')
            cur.execute(f'GRANT USAGE ON SCHEMA "{schema}" TO "{reader_role}"')
            cur.execute(
                f'GRANT SELECT ON "{schema}"."customers","{schema}"."api_secrets",'
                f'"{schema}"."metrics" TO "{reader_role}"'
            )
            # "locked" is visible in the catalog (a non-SELECT privilege) but
            # SELECT is withheld → sampling is DENIED → the table is unevaluable,
            # never silently "clean".
            cur.execute(f'GRANT INSERT ON "{schema}"."locked" TO "{reader_role}"')

    try:
        reader_url = _PG_URL.replace("postgres:abom@", f"{reader_role}:readpw@")
        with psycopg.connect(
            reader_url, autocommit=True, options="-c default_transaction_read_only=on"
        ) as reader:
            result = scan_database_content(reader, source=f"postgres://abom/{schema}", schemas=[schema], max_rows=50)
            payload = result.to_dict()

            by_table = {t.table: t for t in result.tables}
            assert by_table["customers"].state == STATE_EXECUTED
            assert by_table["customers"].data_sensitivity == "sensitive"
            assert by_table["api_secrets"].data_sensitivity == "sensitive"
            assert by_table["metrics"].state == STATE_EXECUTED
            assert by_table["metrics"].data_sensitivity == "none"
            # Denied table is unevaluable, never "clean".
            assert by_table["locked"].state == STATE_UNEVALUABLE
            assert by_table["locked"].data_sensitivity == "unevaluable"
            assert payload["status"] == "partial"

            # Sensitive data types identified; raw values never persisted.
            assert payload["findings_by_type"].get("ssn") == 2
            assert payload["findings_by_type"].get("email") >= 2
            assert payload["findings_by_type"].get("credit_card") == 2
            text = repr(payload)
            for raw in ("alice@example.com", "123-45-6789", "4111111111111111", "api_key=abcdef0123456789abcdef0123456789"):
                assert raw not in text

            # Read-only enforced: a write must fail on the brokered session.
            with pytest.raises(Exception):
                with reader.cursor() as wcur:
                    wcur.execute(f'INSERT INTO "{schema}"."metrics" VALUES (\'x\', 1.0)')
    finally:
        with psycopg.connect(_PG_URL, autocommit=True) as admin:
            with admin.cursor() as cur:
                cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
                cur.execute(f'DROP ROLE IF EXISTS "{reader_role}"')


def test_result_type_is_stable_dataclass():
    conn, _t, _r = _build_conn()
    result = scan_database_content(conn, source="postgres://acct/app")
    assert isinstance(result, DatabaseScanClassification)
