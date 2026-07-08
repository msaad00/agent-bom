"""Generic Postgres RANGE-partition maintenance + retention rollover (#3463).

This generalises the proven ``hub_observations_partition`` approach so any
append-only, time-series control-plane table can be range-partitioned by month
and aged out on a configurable window. It is deliberately conservative:

* **Postgres-only.** Every helper that touches a connection reads ``pg_class`` /
  ``pg_inherits`` / ``information_schema``; SQLite never reaches these because
  :func:`run_partition_retention` short-circuits when no ``AGENT_BOM_POSTGRES_URL``
  is configured. SQLite deployments keep their existing TTL / per-tenant caps.
* **Safe on existing data.** The maintenance runner only *ensures ahead* and
  *rolls over expired* partitions on tables that are already declarative RANGE
  parents (detected at runtime via ``relkind = 'p'``). An unpartitioned legacy
  table is left completely untouched — nothing is created, detached, or dropped.
* **Idempotent.** Child-partition creation is ``CREATE TABLE IF NOT EXISTS``;
  ensure/rollover are safe to run every cleanup tick.
* **Opt-in adoption.** Converting a live table to partitioned is a maintenance
  operation, never done automatically at bootstrap — see
  :func:`partitioned_parent_ddl` / :func:`migrate_table_to_partitioned`.

Partition-key / dedup note: Postgres requires the partition key to be part of
every unique constraint (including the primary key). A table can only be safely
partitioned by ``time_column`` if its dedup/primary key already includes that
column (as ``hub_findings_current_observations`` does). Tables whose idempotency
key does *not* include the time column (e.g. ``llm_costs`` keyed on
``(tenant_id, call_id)``) must not be blindly partitioned — doing so would drop
the cross-partition uniqueness guarantee and regress ingest idempotency. Such
tables are registered here as ``partition_safe=False`` and are excluded from the
default maintenance registry until their key is redesigned.
"""

from __future__ import annotations

import logging
import os
import re
from calendar import monthrange
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ── Pure partition-name / calendar math ──────────────────────────────────────


def partition_table_name(table: str, year: int, month: int) -> str:
    """Return the monthly child partition relation name for *table*."""
    return f"{table}_y{year}m{month:02d}"


def _partition_name_re(table: str) -> re.Pattern[str]:
    return re.compile(rf"^{re.escape(table)}_y(\d{{4}})m(\d{{2}})$")


def month_range_bounds(year: int, month: int) -> tuple[date, date]:
    """Return half-open ``[start, end)`` calendar bounds for a monthly partition."""
    start = date(year, month, 1)
    if month == 12:
        end = date(year + 1, 1, 1)
    else:
        end = date(year, month + 1, 1)
    return start, end


def days_in_month(year: int, month: int) -> int:
    """Return the number of days in a calendar month (test helper)."""
    return monthrange(year, month)[1]


def _iter_months(center: date, *, behind: int, ahead: int) -> list[tuple[int, int]]:
    months: list[tuple[int, int]] = []
    cursor = date(center.year, center.month, 1)
    for offset in range(-behind, ahead + 1):
        year = cursor.year + ((cursor.month - 1 + offset) // 12)
        month = ((cursor.month - 1 + offset) % 12) + 1
        months.append((year, month))
    return months


def partition_end_date(table: str, partition_name: str) -> date | None:
    """Return the half-open end bound encoded in a child partition name, or ``None``."""
    match = _partition_name_re(table).match(partition_name)
    if not match:
        return None
    _, end = month_range_bounds(int(match.group(1)), int(match.group(2)))
    return end


def partition_is_expired(
    table: str,
    partition_name: str,
    *,
    retention_days: int,
    now: date | None = None,
) -> bool:
    """Whether a partition falls wholly before the retention window (pure helper)."""
    if retention_days <= 0:
        return False
    end = partition_end_date(table, partition_name)
    if end is None:
        return False
    anchor = now or datetime.now(timezone.utc).date()
    cutoff = anchor - timedelta(days=retention_days)
    return end <= cutoff


def retained_partition_months(retention_days: int, *, now: date | None = None) -> list[tuple[int, int]]:
    """Return ``(year, month)`` tuples that fall inside the retention window."""
    if retention_days <= 0:
        return []
    anchor = now or datetime.now(timezone.utc).date()
    oldest = anchor - timedelta(days=retention_days)
    months: list[tuple[int, int]] = []
    cursor = date(oldest.year, oldest.month, 1)
    end = date(anchor.year, anchor.month, 1)
    while cursor <= end:
        months.append((cursor.year, cursor.month))
        cursor = date(cursor.year + 1, 1, 1) if cursor.month == 12 else date(cursor.year, cursor.month + 1, 1)
    return months


# ── Partition spec + registry ────────────────────────────────────────────────


@dataclass(frozen=True)
class PartitionSpec:
    """Declarative-partitioning contract for one append-only control-plane table."""

    table: str
    time_column: str
    retention_env: str
    default_retention_days: int = 0
    months_ahead: int = 2
    months_behind: int = 1
    partition_safe: bool = True

    def retention_days(self) -> int:
        """Resolve the retention window (env override → config default). ``<=0`` disables."""
        raw = os.environ.get(self.retention_env)
        if raw is not None:
            try:
                return int(raw)
            except ValueError:
                logger.warning("invalid %s=%r; falling back to default", self.retention_env, raw)
        try:
            from agent_bom import config

            return int(getattr(config, self.retention_env.removeprefix("AGENT_BOM_"), self.default_retention_days))
        except (ImportError, TypeError, ValueError):
            return self.default_retention_days


# Registry of tables whose dedup/primary key already includes the time column,
# so range-partitioning by time is safe. ``hub_findings_current_observations``
# keeps its own dedicated module (``hub_observations_partition``) and is not
# double-maintained here. ``audit_log`` is append-only with a UUID entry_id PK;
# operators adopting partitioning add ``timestamp`` to the PK during migration.
DEFAULT_PARTITION_SPECS: tuple[PartitionSpec, ...] = (
    PartitionSpec(
        table="audit_log",
        time_column="timestamp",
        retention_env="AGENT_BOM_AUDIT_LOG_RETENTION_DAYS",
        default_retention_days=0,
    ),
)

# Registered but excluded from default maintenance: idempotency key does not
# include the time column, so partitioning would regress ingest dedup. Kept here
# so the risk is documented and a future key redesign can flip ``partition_safe``.
UNSAFE_PARTITION_SPECS: tuple[PartitionSpec, ...] = (
    PartitionSpec(
        table="llm_costs",
        time_column="observed_at",
        retention_env="AGENT_BOM_LLM_COSTS_RETENTION_DAYS",
        default_retention_days=0,
        partition_safe=False,
    ),
    PartitionSpec(
        table="runtime_observations",
        time_column="observed_at",
        retention_env="AGENT_BOM_RUNTIME_OBSERVATIONS_RETENTION_DAYS",
        default_retention_days=0,
        partition_safe=False,
    ),
)


# ── Connection-level catalog probes ──────────────────────────────────────────


def table_exists(conn: Any, table: str) -> bool:
    row = conn.execute(
        """
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = current_schema() AND table_name = %s
        """,
        (table,),
    ).fetchone()
    return row is not None


def is_partitioned(conn: Any, table: str) -> bool:
    """Return whether *table* is a declarative RANGE partition parent (relkind='p')."""
    row = conn.execute(
        """
        SELECT c.relkind FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relname = %s
        """,
        (table,),
    ).fetchone()
    return row is not None and str(row[0]) == "p"


def child_partition_exists(conn: Any, child: str) -> bool:
    return (
        conn.execute(
            """
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = current_schema() AND c.relname = %s
            """,
            (child,),
        ).fetchone()
        is not None
    )


def list_partition_names(conn: Any, table: str) -> list[str]:
    rows = conn.execute(
        """
        SELECT child.relname FROM pg_inherits inh
        JOIN pg_class parent ON parent.oid = inh.inhparent
        JOIN pg_class child ON child.oid = inh.inhrelid
        JOIN pg_namespace n ON n.oid = parent.relnamespace
        WHERE n.nspname = current_schema() AND parent.relname = %s
        ORDER BY child.relname
        """,
        (table,),
    ).fetchall()
    return [str(row[0]) for row in rows]


# ── DDL builders ─────────────────────────────────────────────────────────────


def partitioned_parent_ddl(table: str, columns_sql: str, primary_key_sql: str, time_column: str) -> str:
    """Build a fresh partitioned-parent DDL (no child partitions).

    ``primary_key_sql`` MUST include *time_column* (Postgres requires the
    partition key in every unique/primary constraint). Callers own the exact
    column list so per-table types (e.g. ``TIMESTAMPTZ``) stay authoritative.
    """
    if time_column not in primary_key_sql:
        raise ValueError(f"primary key {primary_key_sql!r} must include partition key {time_column!r}")
    return (
        f"CREATE TABLE IF NOT EXISTS {table} (\n    {columns_sql},\n    "
        f"PRIMARY KEY {primary_key_sql}\n) PARTITION BY RANGE ({time_column});"
    )


def create_partition_ddl(table: str, year: int, month: int) -> str:
    """Return idempotent DDL for one monthly child partition of *table*."""
    start, end = month_range_bounds(year, month)
    child = partition_table_name(table, year, month)
    return (
        f"CREATE TABLE IF NOT EXISTS {child} PARTITION OF {table} "
        f"FOR VALUES FROM ('{start.isoformat()}') TO ('{end.isoformat()}');"
    )


# ── Ensure-ahead + rollover engine ───────────────────────────────────────────


def ensure_partitions(
    conn: Any,
    spec: PartitionSpec,
    *,
    now: datetime | None = None,
) -> int:
    """Create missing monthly child partitions around *now*. Returns count created.

    No-op (returns 0) unless *table* is already a partitioned parent, so this is
    always safe to call on legacy/unpartitioned tables and never mutates them.
    """
    if not is_partitioned(conn, spec.table):
        return 0
    anchor = (now or datetime.now(timezone.utc)).date()
    created = 0
    for year, month in _iter_months(anchor, behind=spec.months_behind, ahead=spec.months_ahead):
        child = partition_table_name(spec.table, year, month)
        if child_partition_exists(conn, child):
            continue
        conn.execute(create_partition_ddl(spec.table, year, month))
        created += 1
    return created


def rollover_partitions(
    conn: Any,
    spec: PartitionSpec,
    *,
    retention_days: int | None = None,
    now: datetime | None = None,
) -> int:
    """Detach + drop child partitions wholly older than the retention window.

    Returns the number of partitions dropped. No-op when retention is disabled
    (``<= 0``) or the table is not a partitioned parent.
    """
    days = spec.retention_days() if retention_days is None else retention_days
    if days <= 0 or not is_partitioned(conn, spec.table):
        return 0
    anchor = now or datetime.now(timezone.utc)
    cutoff = (anchor - timedelta(days=days)).date()
    dropped = 0
    for name in list_partition_names(conn, spec.table):
        end = partition_end_date(spec.table, name)
        if end is None or end > cutoff:
            continue
        conn.execute(f"ALTER TABLE {spec.table} DETACH PARTITION {name}")  # nosec B608 — name from pg_catalog
        conn.execute(f"DROP TABLE IF EXISTS {name}")  # nosec B608 — name from pg_catalog
        dropped += 1
        logger.info(
            "partition retention dropped expired partition #%d (end=%s cutoff=%s)",
            dropped,
            end.isoformat(),
            cutoff.isoformat(),
        )
    return dropped


def maintain_partitions(
    conn: Any,
    spec: PartitionSpec,
    *,
    now: datetime | None = None,
) -> tuple[int, int]:
    """Ensure ahead + roll over expired for one spec. Returns ``(created, dropped)``."""
    created = ensure_partitions(conn, spec, now=now)
    dropped = rollover_partitions(conn, spec, now=now)
    return created, dropped


# ── Opt-in migration (maintenance-window only) ───────────────────────────────


def migrate_table_to_partitioned(
    conn: Any,
    spec: PartitionSpec,
    *,
    columns_sql: str,
    primary_key_sql: str,
    copy_columns: str,
    cast_time_to_timestamptz: bool = False,
) -> bool:
    """One-shot rename → partitioned-parent → backfill migration for one table.

    Never invoked at bootstrap. Returns ``True`` when a migration ran, ``False``
    when the table is absent or already partitioned. The caller supplies the
    authoritative column list and PK (which must include the partition key).
    """
    if not spec.partition_safe:
        raise ValueError(f"refusing to partition {spec.table!r}: dedup key excludes {spec.time_column!r}")
    if not table_exists(conn, spec.table):
        return False
    if is_partitioned(conn, spec.table):
        return False

    legacy = f"{spec.table}_pre_partition"
    conn.execute(f"ALTER TABLE {spec.table} RENAME TO {legacy}")  # nosec B608 — internal migration table
    conn.execute(partitioned_parent_ddl(spec.table, columns_sql, primary_key_sql, spec.time_column))

    time_expr = f"{spec.time_column}::timestamptz" if cast_time_to_timestamptz else spec.time_column
    bounds = conn.execute(
        f"""
        SELECT date_trunc('month', MIN({time_expr}))::date,
               date_trunc('month', MAX({time_expr}))::date
        FROM {legacy}
        """  # nosec B608 — internal migration table + validated column
    ).fetchone()
    min_month = bounds[0] if bounds and bounds[0] else date.today().replace(day=1)
    max_month = bounds[1] if bounds and bounds[1] else min_month

    cursor = date(min_month.year, min_month.month, 1)
    end_cursor = date(max_month.year, max_month.month, 1)
    while cursor <= end_cursor:
        conn.execute(create_partition_ddl(spec.table, cursor.year, cursor.month))
        cursor = date(cursor.year + 1, 1, 1) if cursor.month == 12 else date(cursor.year, cursor.month + 1, 1)

    ensure_partitions(conn, spec, now=datetime.now(timezone.utc))
    conn.execute(f"INSERT INTO {spec.table} ({copy_columns}) SELECT {copy_columns} FROM {legacy}")  # nosec B608
    conn.execute(f"DROP TABLE {legacy}")  # nosec B608 — internal migration table
    return True


# ── Retention runner (wired into the API cleanup loop) ───────────────────────


def _postgres_configured() -> bool:
    return bool(os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip())


def run_partition_retention(
    *,
    specs: tuple[PartitionSpec, ...] | None = None,
    now: datetime | None = None,
) -> dict[str, tuple[int, int]]:
    """Ensure-ahead + roll-over every registered partitioned table.

    Postgres-only and fail-open per-spec so one backend hiccup never stops the
    cleanup loop. Returns ``{table: (created, dropped)}`` for tables that were
    actually partitioned parents (others are silently skipped). No-op on SQLite
    and on any deployment without ``AGENT_BOM_POSTGRES_URL``.
    """
    active = DEFAULT_PARTITION_SPECS if specs is None else specs
    if not active or not _postgres_configured():
        return {}
    results: dict[str, tuple[int, int]] = {}
    try:
        from agent_bom.api.postgres_common import _get_pool, _tenant_connection, bypass_tenant_rls
    except Exception:  # noqa: BLE001 — no Postgres driver available
        logger.debug("partition retention skipped: postgres_common unavailable", exc_info=True)
        return {}

    for spec in active:
        try:
            with bypass_tenant_rls(audit=False), _tenant_connection(_get_pool()) as conn:
                created, dropped = maintain_partitions(conn, spec, now=now)
                conn.commit()
                if created or dropped:
                    results[spec.table] = (created, dropped)
        except Exception:  # noqa: BLE001 — retention must stay fail-open
            logger.debug("partition retention skipped for %s", spec.table, exc_info=True)
    return results
