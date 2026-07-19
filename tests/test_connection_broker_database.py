"""Broker a stored database connection into a read-only session (issue #4157).

The DSPM database content scan must resolve its connection from a stored, scoped,
revocable connection (connect-once) — never a per-action secret. These prove the
``database`` provider brokers a read-only ``psycopg`` connection and that the
session is genuinely read-only. A live PostgreSQL run is gated on
``AGENT_BOM_POSTGRES_URL``.
"""

from __future__ import annotations

import os

import pytest

from agent_bom.cloud.connection_broker import ConnectionBrokerError, broker_session
from agent_bom.cloud.connection_request import ephemeral_connection_record

_PG_URL = os.environ.get("AGENT_BOM_DSPM_TEST_POSTGRES_URL") or os.environ.get("AGENT_BOM_POSTGRES_URL", "")


def test_unknown_provider_still_raises_value_error():
    with ephemeral_connection_record(
        provider="frobnicator",
        display_name="x",
        role_ref="x",
        external_id="x",
    ) as record:
        with pytest.raises(ValueError):
            broker_session(record)


@pytest.mark.skipif(not _PG_URL, reason="AGENT_BOM_POSTGRES_URL not set")
def test_database_provider_brokers_readonly_connection():
    # The connection string (with password) is the single encrypted secret; the
    # role_ref is a non-secret display DSN.
    with ephemeral_connection_record(
        provider="database",
        display_name="prod-analytics",
        role_ref="postgresql://localhost:5433/abom",
        external_id=_PG_URL,
        auth_params={"engine": "postgres"},
    ) as record:
        conn = broker_session(record)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                assert cur.fetchone()[0] == 1
            # Read-only session: a write must fail closed at the server.
            with pytest.raises(Exception):
                with conn.cursor() as cur:
                    cur.execute("CREATE TEMP TABLE _abom_ro_probe (x int)")
        finally:
            conn.close()


@pytest.mark.skipif(not _PG_URL, reason="AGENT_BOM_POSTGRES_URL not set")
def test_database_broker_failure_is_sanitized():
    # A bad host secret must fail closed without leaking the DSN/password.
    with ephemeral_connection_record(
        provider="postgres",
        display_name="broken",
        role_ref="postgresql://badhost/db",
        external_id="postgresql://sneaky:topsecret@127.0.0.1:1/nope",
    ) as record:
        with pytest.raises(ConnectionBrokerError) as excinfo:
            broker_session(record)
        assert "topsecret" not in str(excinfo.value)
