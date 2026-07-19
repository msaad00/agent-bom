"""Bounded, read-only, multi-table DSPM database content scan (issue #4157).

The redacted :mod:`agent_bom.cloud.db_data_classifier` samples one query result.
This module connects that classifier to *real read-only database discovery*: it
takes a brokered read-only DB-API connection (see
:func:`agent_bom.cloud.connection_broker.broker_session` for the connect-once,
stored-credential path — never a per-action secret), enumerates the caller-scoped
tables via metadata-derived bounded selects, samples a bounded number of rows per
table, and aggregates a redacted DSPM classification.

Honesty constraints (issue #4157):

- **Redacted evidence only.** Raw rows, cell values, and matched values never
  cross the boundary — output is data-type + count + location (schema.table).
- **Explicit coverage states.** Every table carries one of ``executed`` /
  ``partial`` / ``skipped`` / ``unevaluable`` / ``failed``. A denied, timed-out,
  or otherwise unreadable table is ``unevaluable`` — *never* "clean / no
  sensitive data". Absence of a finding from an unreadable source is not
  evidence of absence.
- **Read-only.** Only ``SELECT ... LIMIT`` is issued and the brokered
  connection is opened read-only; no table is mutated.

The output dict (``schema_version = agent-bom.dspm.database_scan.v1``) reuses the
key names the CNAPP/DSPM graph overlay already reads (``data_sensitivity``,
``findings_by_type``, ``rows_sampled``, ``columns_sampled``, ``tables_sampled``)
so a database store promotes to a crown jewel through the same path as S3/GCS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from agent_bom import config
from agent_bom.cloud.db_data_classifier import DatabaseContentClassification, classify_database_query
from agent_bom.cloud.normalization import sanitize_discovery_warning

# Coverage states — explicit, never collapsed into a silent "clean".
STATE_EXECUTED = "executed"
STATE_PARTIAL = "partial"
STATE_SKIPPED = "skipped"
STATE_UNEVALUABLE = "unevaluable"
STATE_FAILED = "failed"

_ALL_STATES = (STATE_EXECUTED, STATE_PARTIAL, STATE_SKIPPED, STATE_UNEVALUABLE, STATE_FAILED)
_EVALUATED_STATES = frozenset({STATE_EXECUTED, STATE_PARTIAL})

# Schemas never sampled — engine catalog / metadata, not customer data.
_SYSTEM_SCHEMAS = frozenset({"information_schema", "pg_catalog", "pg_toast", "pg_temp_1", "pg_toast_temp_1", "sys"})

_HIGH_SENSITIVITY_TYPES = frozenset({"ssn", "credit_card", "iban", "passport", "nhs_number"})
_MEDIUM_SENSITIVITY_TYPES = frozenset({"email", "phone", "date_of_birth", "drivers_license", "medical_record_keyword"})


def _quote_ident(name: str) -> str:
    """ANSI-quote a SQL identifier so a schema/table name is inert in a query."""
    return '"' + str(name).replace('"', '""') + '"'


def _sensitivity(findings_by_type: dict[str, int]) -> tuple[int, str]:
    """Return (score, label) from redacted finding types — shared with the classifier."""
    if not findings_by_type:
        return 0, "none"
    if any(k in _HIGH_SENSITIVITY_TYPES or k.startswith("secret:") for k in findings_by_type):
        return 90, "sensitive"
    if any(k in _MEDIUM_SENSITIVITY_TYPES for k in findings_by_type):
        return 60, "sensitive"
    return 30, "review"


@dataclass
class TableCoverage:
    """Redacted per-table coverage + classification for one scanned table."""

    source: str
    schema: str
    table: str
    state: str
    rows_sampled: int = 0
    columns_sampled: int = 0
    total_findings: int = 0
    findings_by_type: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def data_sensitivity(self) -> str:
        # A not-evaluated table never claims a data verdict.
        if self.state == STATE_UNEVALUABLE:
            return "unevaluable"
        if self.state == STATE_SKIPPED:
            return "skipped"
        if self.state == STATE_FAILED:
            return "unevaluable"
        return _sensitivity(self.findings_by_type)[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "schema": self.schema,
            "table": self.table,
            "state": self.state,
            "rows_sampled": self.rows_sampled,
            "columns_sampled": self.columns_sampled,
            "total_findings": self.total_findings,
            "findings_by_type": dict(self.findings_by_type),
            "data_sensitivity": self.data_sensitivity,
            "warnings": list(self.warnings),
        }


@dataclass
class DatabaseScanClassification:
    """Redacted, coverage-honest DSPM classification for one database scan."""

    source: str
    status: str = "ok"
    tables_total: int = 0
    tables_sampled: int = 0
    rows_sampled: int = 0
    columns_sampled: int = 0
    total_findings: int = 0
    findings_by_type: dict[str, int] = field(default_factory=dict)
    tables: list[TableCoverage] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def tables_by_state(self) -> dict[str, int]:
        counts = {state: 0 for state in _ALL_STATES}
        for table in self.tables:
            counts[table.state] = counts.get(table.state, 0) + 1
        return counts

    @property
    def sensitivity_score(self) -> int:
        return _sensitivity(self.findings_by_type)[0]

    @property
    def data_sensitivity(self) -> str:
        # No evaluated-table finding does NOT mean "clean" when the scan failed or
        # nothing could be read — surface ``unevaluable`` so absence is honest.
        if not self.findings_by_type:
            evaluated = any(t.state in _EVALUATED_STATES for t in self.tables)
            if self.status == "failed" or not evaluated:
                return "unevaluable"
        return _sensitivity(self.findings_by_type)[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "agent-bom.dspm.database_scan.v1",
            "source": self.source,
            "status": self.status,
            "tables_total": self.tables_total,
            "tables_sampled": self.tables_sampled,
            "rows_sampled": self.rows_sampled,
            "columns_sampled": self.columns_sampled,
            "total_findings": self.total_findings,
            "findings_by_type": dict(self.findings_by_type),
            "sensitivity_score": self.sensitivity_score,
            "data_sensitivity": self.data_sensitivity,
            "tables_by_state": self.tables_by_state,
            "tables": [t.to_dict() for t in self.tables],
            "warnings": list(self.warnings),
            "coverage_note": (
                "Coverage states are explicit; an unevaluable/failed table is NOT "
                "clean — absence of a finding from an unreadable source is not "
                "evidence of no sensitive data."
            ),
            "redaction": "raw row values and matched values are not stored",
        }


def list_scoped_tables(
    conn: Any,
    *,
    max_tables: int,
) -> list[tuple[str, str]]:
    """Enumerate base tables via ``information_schema`` (read-only, bounded).

    Returns ``(schema, table)`` pairs excluding engine system schemas, ordered
    deterministically and capped at ``max_tables``. Raises on enumeration failure
    so the caller can record a ``failed`` scan rather than an empty "clean" one.
    """
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_type = 'BASE TABLE' ORDER BY table_schema, table_name"
        )
        # Fetch a bounded superset so system-schema filtering still yields up to
        # ``max_tables`` real tables without an unbounded read.
        fetch = max(1, max_tables) * 8
        rows = cursor.fetchmany(fetch) if hasattr(cursor, "fetchmany") else []
    finally:
        _close_quietly(cursor)

    out: list[tuple[str, str]] = []
    for row in rows:
        schema = str(row[0] if not isinstance(row, dict) else row.get("table_schema") or "").strip()
        table = str(row[1] if not isinstance(row, dict) else row.get("table_name") or "").strip()
        if not schema or not table or schema.lower() in _SYSTEM_SCHEMAS:
            continue
        out.append((schema, table))
        if len(out) >= max_tables:
            break
    return out


def scan_database_content(
    conn: Any,
    *,
    source: str,
    schemas: Sequence[str] | None = None,
    include_tables: Sequence[str] | None = None,
    max_tables: int | None = None,
    max_rows: int | None = None,
    max_cell_chars: int | None = None,
) -> DatabaseScanClassification:
    """Scan a bounded, read-only sample of a database's tables into redacted DSPM evidence.

    ``schemas`` restricts sampling to those schemas (others are marked
    ``skipped``, not silently dropped). ``include_tables`` (``"schema.table"``)
    is an explicit allowlist; enumerated tables outside it are ``skipped``.
    """
    max_tables = max(1, int(max_tables if max_tables is not None else config.DSPM_DB_MAX_TABLES))
    max_rows = max(1, int(max_rows if max_rows is not None else config.DSPM_DB_MAX_ROWS_PER_TABLE))
    max_cell_chars = max(1, int(max_cell_chars if max_cell_chars is not None else config.DSPM_DB_MAX_CELL_CHARS))

    result = DatabaseScanClassification(source=source, status="ok")

    try:
        tables = list_scoped_tables(conn, max_tables=max_tables)
    except Exception as exc:  # noqa: BLE001 — enumeration failure must not look "clean".
        result.status = "failed"
        result.warnings.append(f"Could not enumerate tables for {source}: {sanitize_discovery_warning(exc)}")
        return result

    result.tables_total = len(tables)
    schema_scope = {s.strip().lower() for s in schemas} if schemas else None
    table_scope = {t.strip().lower() for t in include_tables} if include_tables else None

    saw_gap = False
    for schema, table in tables:
        table_source = f"{source}/{schema}.{table}"
        in_scope = True
        if schema_scope is not None and schema.lower() not in schema_scope:
            in_scope = False
        if table_scope is not None and f"{schema}.{table}".lower() not in table_scope:
            in_scope = False
        if not in_scope:
            result.tables.append(TableCoverage(source=table_source, schema=schema, table=table, state=STATE_SKIPPED))
            continue

        coverage = _sample_one_table(
            conn,
            schema=schema,
            table=table,
            source=table_source,
            max_rows=max_rows,
            max_cell_chars=max_cell_chars,
        )
        result.tables.append(coverage)
        if coverage.state in _EVALUATED_STATES:
            result.tables_sampled += 1
            result.rows_sampled += coverage.rows_sampled
            result.columns_sampled += coverage.columns_sampled
            result.total_findings += coverage.total_findings
            for kind, count in coverage.findings_by_type.items():
                result.findings_by_type[kind] = result.findings_by_type.get(kind, 0) + count
        if coverage.state in (STATE_UNEVALUABLE, STATE_FAILED, STATE_PARTIAL):
            saw_gap = True

    if saw_gap and result.status == "ok":
        result.status = "partial"
    return result


def _sample_one_table(
    conn: Any,
    *,
    schema: str,
    table: str,
    source: str,
    max_rows: int,
    max_cell_chars: int,
) -> TableCoverage:
    """Sample one table read-only and map the classifier result to a coverage state."""
    query = f"SELECT * FROM {_quote_ident(schema)}.{_quote_ident(table)} LIMIT {max_rows}"
    try:
        cursor = conn.cursor()
    except Exception as exc:  # noqa: BLE001 — cannot even open a cursor for this table.
        return TableCoverage(
            source=source,
            schema=schema,
            table=table,
            state=STATE_FAILED,
            warnings=[f"Could not open a cursor for {source}: {sanitize_discovery_warning(exc)}"],
        )
    try:
        classification: DatabaseContentClassification = classify_database_query(
            cursor,
            source=source,
            query=query,
            max_rows=max_rows,
            max_cell_chars=max_cell_chars,
        )
    finally:
        _close_quietly(cursor)

    if classification.status != "ok":
        # Denied / timed-out / unreadable → unevaluable (never "clean").
        return TableCoverage(
            source=source,
            schema=schema,
            table=table,
            state=STATE_UNEVALUABLE,
            warnings=list(classification.warnings),
        )

    state = STATE_EXECUTED
    if classification.rows_sampled >= max_rows:
        # Hit the row cap — sampling is bounded and may not be exhaustive.
        state = STATE_PARTIAL
    return TableCoverage(
        source=source,
        schema=schema,
        table=table,
        state=state,
        rows_sampled=classification.rows_sampled,
        columns_sampled=classification.columns_sampled,
        total_findings=classification.total_findings,
        findings_by_type=dict(classification.findings_by_type),
        warnings=list(classification.warnings),
    )


def _close_quietly(cursor: Any) -> None:
    close = getattr(cursor, "close", None)
    if callable(close):
        try:
            close()
        except Exception:  # noqa: BLE001 — cursor close is best-effort.
            pass
