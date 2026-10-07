"""Restricted application roles recognize migration-owned audit safeguards."""

import logging
import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="Requires isolated real Postgres",
)


def test_migrated_fork_guard_does_not_warn_for_restricted_application_role(caplog):
    from agent_bom.api import postgres_common
    from agent_bom.api.postgres_audit import PostgresAuditLog

    postgres_common.reset_pool()
    try:
        with postgres_common._get_pool().connection() as conn:
            assert conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone() == (False, False)
            assert conn.execute("SELECT to_regclass('audit_log_team_prevsig_uniq')").fetchone()[0] is not None
        with caplog.at_level(logging.WARNING, logger="agent_bom.api.postgres_audit"):
            PostgresAuditLog()
        assert "fork-guard" not in caplog.text
    finally:
        postgres_common.reset_pool()


@pytest.mark.parametrize("invalid_index", [None, "non_unique", "wrong_columns"])
def test_fork_guard_bootstrap_and_invalid_index_are_distinguished(caplog, invalid_index):
    from contextlib import contextmanager

    from agent_bom.api.postgres_audit import PostgresAuditLog
    from agent_bom.api.postgres_common import _new_application_pool

    pool = _new_application_pool(min_size=1, max_size=1)
    try:
        with pool.connection() as conn:
            conn.execute("CREATE TEMP TABLE audit_log (team_id TEXT NOT NULL, prev_signature TEXT NOT NULL)")
            if invalid_index == "non_unique":
                conn.execute("CREATE INDEX audit_log_team_prevsig_uniq ON audit_log (team_id, prev_signature)")
            elif invalid_index == "wrong_columns":
                conn.execute("CREATE UNIQUE INDEX audit_log_team_prevsig_uniq ON audit_log (team_id)")
            conn.commit()

            class BorrowedConnection:
                @contextmanager
                def connection(self):
                    yield conn

            store = object.__new__(PostgresAuditLog)
            store._pool = BorrowedConnection()
            with caplog.at_level(logging.WARNING, logger="agent_bom.api.postgres_audit"):
                store._ensure_fork_guard_index()
            if invalid_index:
                assert "does not enforce the required chain uniqueness" in caplog.text
            else:
                row = conn.execute(
                    "SELECT indisunique FROM pg_index WHERE indexrelid = to_regclass('pg_temp.audit_log_team_prevsig_uniq')"
                ).fetchone()
                assert row == (True,)
                assert "fork-guard" not in caplog.text
            conn.execute("DROP TABLE pg_temp.audit_log")
            conn.commit()
    finally:
        pool.close()
