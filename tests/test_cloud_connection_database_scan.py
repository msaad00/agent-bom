"""End-to-end database DSPM connection scan through the broker (issue #4157).

Proves the connection-scan runner resolves a stored read-only connection, runs
bounded content sampling only when explicitly enabled, and returns a redacted,
coverage-honest summary. Live PostgreSQL run gated on ``AGENT_BOM_POSTGRES_URL``.
"""

from __future__ import annotations

import os
import uuid

import pytest

from agent_bom.cloud.connection_request import ephemeral_connection_record

_PG_URL = os.environ.get("AGENT_BOM_DSPM_TEST_POSTGRES_URL") or os.environ.get("AGENT_BOM_POSTGRES_URL", "")


def test_sampling_disabled_does_not_claim_clean(monkeypatch):
    from agent_bom.api.routes.cloud_connections import _run_database_connection_scan

    monkeypatch.delenv("AGENT_BOM_DSPM_DB_SAMPLING", raising=False)
    with ephemeral_connection_record(
        provider="database",
        display_name="prod-db",
        role_ref="postgresql://localhost/db",
        external_id="postgresql://u:p@localhost/db",
    ) as record:
        summary = _run_database_connection_scan(record, tenant_id="t1")

    assert summary["provider"] == "database"
    dspm = summary["dspm"]
    assert dspm["sampling_enabled"] is False
    # Honesty: no content read ⇒ unevaluable, never clean.
    assert dspm["data_sensitivity"] == "unevaluable"
    assert dspm["scan_status"] == "skipped"
    assert "opt-in" in dspm["note"].lower()


@pytest.mark.skipif(not _PG_URL, reason="AGENT_BOM_POSTGRES_URL not set")
def test_live_database_connection_scan_is_redacted_and_honest(monkeypatch):
    import psycopg

    from agent_bom.api.routes.cloud_connections import _run_database_connection_scan

    schema = f"dspm_conn_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(_PG_URL, autocommit=True) as admin, admin.cursor() as cur:
        cur.execute(f'CREATE SCHEMA "{schema}"')
        cur.execute(f'CREATE TABLE "{schema}".people (email text, ssn text)')
        cur.execute(
            f"INSERT INTO \"{schema}\".people VALUES ('dave@example.com','123-45-6789'),('erin@example.com','234-56-7890')"
        )
        cur.execute(f'CREATE TABLE "{schema}".metrics (name text, value double precision)')
        cur.execute(f"INSERT INTO \"{schema}\".metrics VALUES ('cpu',0.9)")

    monkeypatch.setenv("AGENT_BOM_DSPM_DB_SAMPLING", "1")
    try:
        with ephemeral_connection_record(
            provider="database",
            display_name="prod-analytics",
            role_ref="postgresql://localhost:5433/abom",
            external_id=_PG_URL,
            auth_params={"engine": "postgres", "schemas": schema, "publicly_accessible": "true"},
        ) as record:
            summary = _run_database_connection_scan(record, tenant_id="tenant-a")
    finally:
        with psycopg.connect(_PG_URL, autocommit=True) as admin, admin.cursor() as cur:
            cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')

    dspm = summary["dspm"]
    assert dspm["sampling_enabled"] is True
    assert dspm["data_sensitivity"] == "sensitive"
    assert dspm["findings_by_type"].get("ssn") == 2
    assert dspm["findings_by_type"].get("email") == 2
    assert dspm["tables_by_state"]["executed"] == 2
    assert summary["audit_metadata"]["read_only"] is True
    # No raw value / DSN leaks anywhere in the returned envelope.
    text = repr(summary)
    for raw in ("dave@example.com", "123-45-6789", _PG_URL):
        assert raw not in text
