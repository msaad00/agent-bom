"""Catalog verification and bootstrap for the per-tenant audit chain guard."""

import logging

from agent_bom.api.postgres_common import ConnectionPool

AUDIT_FORK_GUARD_INDEX = "audit_log_team_prevsig_uniq"


def ensure_audit_fork_guard(pool: ConnectionPool, logger: logging.Logger) -> None:
    """Recognize migrated guards without DDL privileges; warn on invalid guards.

    Legacy bootstrap can create a missing guard. A failure remains visible and
    never authorizes rewriting existing audit events or checkpoints.
    """
    try:
        with pool.connection() as conn:
            guard = conn.execute(
                """
                SELECT i.indisunique AND i.indisvalid AND i.indisready
                       AND i.indpred IS NULL AND i.indexprs IS NULL
                       AND i.indnatts = 2 AND i.indrelid = to_regclass('audit_log')
                       AND ARRAY(
                           SELECT a.attname::text
                           FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum, position)
                           JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                           ORDER BY k.position
                       ) = ARRAY['team_id', 'prev_signature']
                FROM pg_index i
                JOIN pg_class idx ON idx.oid = i.indexrelid
                WHERE i.indrelid = to_regclass('audit_log') AND idx.relname = %s
                """,
                (AUDIT_FORK_GUARD_INDEX,),
            ).fetchone()
            if guard is not None:
                if guard[0]:
                    return
                logger.warning(
                    "Audit fork-guard index %s exists but does not enforce the required chain uniqueness; "
                    "apply the audit schema migration before relying on concurrent chain integrity",
                    AUDIT_FORK_GUARD_INDEX,
                )
                return
            conn.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS {AUDIT_FORK_GUARD_INDEX} ON audit_log (team_id, prev_signature)")
            conn.commit()
    except Exception:
        logger.warning(
            "Could not verify or create audit_log fork-guard unique index %s; "
            "check audit schema migrations and database privileges before relying on concurrent chain integrity",
            AUDIT_FORK_GUARD_INDEX,
            exc_info=False,
        )
