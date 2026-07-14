"""Opt-in database / warehouse content classification for DSPM evidence.

This module accepts an already-authenticated read-only DB-API cursor and samples
bounded rows from a caller-provided query. It never stores raw cell values or
matched values; output is limited to row/column counts, finding types, redacted
markers, and warnings. Native connectors can reuse this for RDS/Postgres/MySQL,
Snowflake, BigQuery result rows, or customer-provided warehouse adapters.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from agent_bom import config
from agent_bom.cloud.normalization import sanitize_discovery_warning
from agent_bom.parsers.dataset_pii_scanner import DatasetPiiResult, PiiFinding, _aggregate, _scan_cell

DSPM_DB_SAMPLING_ENV_VAR = "AGENT_BOM_DSPM_DB_SAMPLING"


def db_sampling_enabled() -> bool:
    """Return whether bounded database content sampling is explicitly enabled."""
    return os.environ.get(DSPM_DB_SAMPLING_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class DatabaseContentClassification:
    """Redacted classification result for one table/query sample."""

    source: str
    status: str
    rows_sampled: int = 0
    columns_sampled: int = 0
    total_findings: int = 0
    findings_by_type: dict[str, int] = field(default_factory=dict)
    top_findings: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def sensitivity_score(self) -> int:
        if not self.total_findings:
            return 0
        high = sum(
            count
            for kind, count in self.findings_by_type.items()
            if kind in {"ssn", "credit_card", "iban", "passport", "nhs_number"} or kind.startswith("secret:")
        )
        if high:
            return 90
        if any(kind in self.findings_by_type for kind in {"email", "phone", "date_of_birth", "drivers_license", "medical_record_keyword"}):
            return 60
        return 30

    @property
    def data_sensitivity(self) -> str:
        if self.sensitivity_score >= 60:
            return "sensitive"
        if self.sensitivity_score > 0:
            return "review"
        return "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "agent-bom.dspm.database_classification.v1",
            "source": self.source,
            "status": self.status,
            "rows_sampled": self.rows_sampled,
            "columns_sampled": self.columns_sampled,
            "total_findings": self.total_findings,
            "findings_by_type": dict(self.findings_by_type),
            "sensitivity_score": self.sensitivity_score,
            "data_sensitivity": self.data_sensitivity,
            "top_findings": list(self.top_findings),
            "warnings": list(self.warnings),
            "redaction": "raw row values and matched values are not stored",
        }


def classify_database_rows(
    rows: Iterable[Mapping[str, Any] | Sequence[Any]],
    *,
    columns: Sequence[str] | None = None,
    source: str,
    max_rows: int | None = None,
    max_cell_chars: int | None = None,
) -> DatabaseContentClassification:
    """Classify an iterable of DB rows without storing raw values."""

    max_rows = max(1, int(max_rows if max_rows is not None else config.DSPM_DB_MAX_ROWS_PER_TABLE))
    max_cell_chars = max(1, int(max_cell_chars if max_cell_chars is not None else config.DSPM_DB_MAX_CELL_CHARS))
    result = DatabaseContentClassification(source=source, status="ok")
    findings: list[PiiFinding] = []
    seen_columns: set[str] = set()

    for row_index, row in enumerate(rows):
        if row_index >= max_rows:
            break
        result.rows_sampled += 1
        items = _row_items(row, columns)
        for column, value in items:
            if not isinstance(value, (str, int, float)):
                continue
            seen_columns.add(column)
            sample = str(value)[:max_cell_chars]
            findings.extend(_scan_cell(sample, row_index, column, source))

    result.columns_sampled = len(seen_columns)
    aggregate = DatasetPiiResult(file_path=source, rows_sampled=result.rows_sampled, total_findings=0)
    _aggregate(aggregate, findings)
    result.total_findings = aggregate.total_findings
    result.findings_by_type = dict(aggregate.findings_by_type)
    result.top_findings = [
        {
            "row_index": finding.row_index,
            "column": finding.column,
            "pii_type": finding.pii_type,
            "severity": finding.severity,
            "sample": finding.sample,
        }
        for finding in aggregate.top_findings
    ]
    return result


def classify_database_query(
    cursor: Any,
    *,
    source: str,
    query: str | None = None,
    max_rows: int | None = None,
    max_cell_chars: int | None = None,
) -> DatabaseContentClassification:
    """Execute/read a bounded query result through a DB-API-like cursor."""

    max_rows = max(1, int(max_rows if max_rows is not None else config.DSPM_DB_MAX_ROWS_PER_TABLE))
    try:
        if query:
            cursor.execute(query)
        description = getattr(cursor, "description", None) or []
        columns = [str(item[0]) for item in description if item]
        rows = cursor.fetchmany(max_rows) if hasattr(cursor, "fetchmany") else []
    except Exception as exc:  # noqa: BLE001
        return DatabaseContentClassification(
            source=source,
            status="query_failed",
            warnings=[f"Could not sample database content for {source}: {sanitize_discovery_warning(exc)}"],
        )
    result = classify_database_rows(
        rows,
        columns=columns,
        source=source,
        max_rows=max_rows,
        max_cell_chars=max_cell_chars,
    )
    if not columns and result.rows_sampled:
        result.warnings.append("Cursor did not expose column metadata; sampled positional columns.")
    return result


def _row_items(row: Mapping[str, Any] | Sequence[Any], columns: Sequence[str] | None) -> list[tuple[str, Any]]:
    if isinstance(row, Mapping):
        return [(str(key), value) for key, value in row.items()]
    names = [str(name) for name in (columns or [])]
    if not names:
        names = [f"column_{index + 1}" for index in range(len(row))]
    return [(names[index] if index < len(names) else f"column_{index + 1}", value) for index, value in enumerate(row)]
