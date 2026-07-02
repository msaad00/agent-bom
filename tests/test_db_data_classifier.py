"""Tests for opt-in database / warehouse content classification."""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.db_data_classifier import classify_database_query, classify_database_rows, db_sampling_enabled


class _Cursor:
    description = (("email",), ("ssn",), ("notes",))

    def __init__(self) -> None:
        self.executed: list[str] = []
        self.rows = [
            ("alice@example.com", "123-45-6789", "patient id present"),
            ("bob@example.com", "000-00-0000", "plain"),
            ("ignored@example.com", "111-22-3333", "not sampled"),
        ]

    def execute(self, query: str) -> None:
        self.executed.append(query)

    def fetchmany(self, size: int) -> list[tuple[str, str, str]]:
        return self.rows[:size]


def test_db_sampling_flag_is_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_DSPM_DB_SAMPLING", raising=False)

    assert db_sampling_enabled() is False


def test_database_query_classifier_is_bounded_and_redacted() -> None:
    cursor = _Cursor()

    result = classify_database_query(
        cursor,
        source="postgres://inventory/customers",
        query="SELECT email, ssn, notes FROM customers LIMIT 2",
        max_rows=2,
        max_cell_chars=64,
    )
    payload = result.to_dict()

    assert cursor.executed == ["SELECT email, ssn, notes FROM customers LIMIT 2"]
    assert payload["schema_version"] == "agent-bom.dspm.database_classification.v1"
    assert payload["rows_sampled"] == 2
    assert payload["columns_sampled"] == 3
    assert payload["data_sensitivity"] == "sensitive"
    assert payload["redaction"] == "raw row values and matched values are not stored"
    assert "alice@example.com" not in repr(payload)
    assert "123-45-6789" not in repr(payload)
    assert "[email:REDACTED]" in repr(payload)
    assert "[ssn:REDACTED]" in repr(payload)


def test_database_row_classifier_supports_mapping_rows() -> None:
    rows: list[dict[str, Any]] = [
        {"name": "Alice", "email": "alice@example.com", "comment": "plain"},
        {"name": "Bob", "email": "bob@example.com", "comment": "plain"},
    ]

    result = classify_database_rows(rows, source="bigquery://project.dataset.table", max_rows=1)
    payload = result.to_dict()

    assert payload["rows_sampled"] == 1
    assert payload["findings_by_type"] == {"email": 1}
    assert payload["data_sensitivity"] == "sensitive"
    assert "alice@example.com" not in repr(payload)


def test_database_query_classifier_fails_closed_without_raw_exception() -> None:
    class _BadCursor:
        def execute(self, _query: str) -> None:
            raise RuntimeError("password=super-secret could not connect")

    result = classify_database_query(_BadCursor(), source="rds://customers", query="SELECT * FROM customers")
    payload = result.to_dict()

    assert payload["status"] == "query_failed"
    assert payload["rows_sampled"] == 0
    assert "super-secret" not in repr(payload)
