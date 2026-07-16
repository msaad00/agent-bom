"""Monthly RANGE partitioning for ``hub_findings_current_observations`` (#3463).

New Postgres installs create a partitioned parent keyed on ``observed_at``.
Existing unpartitioned tables are left untouched until an operator runs the
documented migration helper (Alembic revision or
``migrate_observations_to_partitioned``). SQLite keeps the legacy single-table
DDL unchanged.

Postgres requires the primary key to include the partition key, so the
partitioned schema uses ``PRIMARY KEY (tenant_id, canonical_id, scan_id,
observed_at)`` with ``observed_at`` as ``TIMESTAMPTZ``. Dedup semantics stay
the same: ``ON CONFLICT DO NOTHING`` on the scan sighting key.
"""

from __future__ import annotations

import logging
import re
from calendar import monthrange
from datetime import date, datetime, timedelta, timezone
from typing import Any

from agent_bom.config import HUB_OBSERVATIONS_RETENTION_DAYS

logger = logging.getLogger(__name__)

OBSERVATIONS_TABLE = "hub_findings_current_observations"
_PARTITION_NAME_RE = re.compile(r"^hub_findings_current_observations_y(\d{4})m(\d{2})$")


# SQLSTATEs raised when a concurrent worker already created the child partition
# between our existence probe and our ``CREATE TABLE ... PARTITION OF``:
# duplicate_table (42P07), duplicate_object (42710), and the unique_violation
# (23505) Postgres can raise on the pg_class/pg_type catalog under the race.
_DUPLICATE_PARTITION_SQLSTATES = frozenset({"42P07", "42710", "23505"})


def _is_duplicate_partition_error(exc: BaseException) -> bool:
    """Whether *exc* means the partition already exists (concurrent creation)."""
    sqlstate = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)
    if sqlstate in _DUPLICATE_PARTITION_SQLSTATES:
        return True
    return "already exists" in str(exc).lower()


def _create_observation_partition(conn: Any, year: int, month: int) -> None:
    """Create one monthly child partition, tolerating a concurrent creator.

    Two API workers ingesting the same not-yet-existing month can both pass the
    existence probe and both issue ``CREATE TABLE ... PARTITION OF``; the loser
    of the Postgres catalog race would raise duplicate_table/duplicate_object ->
    500. Since the partition now exists either way, that is treated as success.
    """
    try:
        conn.execute(create_observation_partition_ddl(year, month))
    except Exception as exc:  # noqa: BLE001 — narrowed by _is_duplicate_partition_error
        if _is_duplicate_partition_error(exc):
            logger.debug(
                "observation partition y%dm%02d already created concurrently; treating as success",
                year,
                month,
            )
            return
        raise


def partition_table_name(year: int, month: int) -> str:
    """Return the child partition relation name for *year*/*month*."""
    return f"{OBSERVATIONS_TABLE}_y{year}m{month:02d}"


def month_range_bounds(year: int, month: int) -> tuple[date, date]:
    """Return half-open ``[start, end)`` calendar bounds for a monthly partition."""
    start = date(year, month, 1)
    if month == 12:
        end = date(year + 1, 1, 1)
    else:
        end = date(year, month + 1, 1)
    return start, end


def partitioned_observations_parent_ddl() -> str:
    """DDL for a fresh partitioned observations parent (no child partitions)."""
    return f"""
CREATE TABLE IF NOT EXISTS {OBSERVATIONS_TABLE} (
    tenant_id TEXT NOT NULL,
    canonical_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, canonical_id, scan_id, observed_at)
) PARTITION BY RANGE (observed_at);
"""


def create_observation_partition_ddl(year: int, month: int) -> str:
    """Return idempotent DDL for one monthly child partition."""
    start, end = month_range_bounds(year, month)
    child = partition_table_name(year, month)
    return f"""
CREATE TABLE IF NOT EXISTS {child}
    PARTITION OF {OBSERVATIONS_TABLE}
    FOR VALUES FROM ('{start.isoformat()}') TO ('{end.isoformat()}');
"""


def observations_table_exists(conn: Any) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = current_schema()
          AND table_name = %s
        """,
        (OBSERVATIONS_TABLE,),
    ).fetchone()
    return row is not None


def is_observations_partitioned(conn: Any) -> bool:
    """Return whether the observations table is a declarative RANGE parent."""
    row = conn.execute(
        """
        SELECT c.relkind
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema()
          AND c.relname = %s
        """,
        (OBSERVATIONS_TABLE,),
    ).fetchone()
    if row is None:
        return False
    return str(row[0]) == "p"


def _iter_months(center: date, *, behind: int, ahead: int) -> list[tuple[int, int]]:
    months: list[tuple[int, int]] = []
    cursor = date(center.year, center.month, 1)
    start_offset = -behind
    for offset in range(start_offset, ahead + 1):
        year = cursor.year + ((cursor.month - 1 + offset) // 12)
        month = ((cursor.month - 1 + offset) % 12) + 1
        months.append((year, month))
    return months


def ensure_observation_partitions(
    conn: Any,
    *,
    now: datetime | None = None,
    months_ahead: int = 2,
    months_behind: int = 1,
) -> int:
    """Create missing monthly child partitions around *now*. Returns partitions created."""
    if not is_observations_partitioned(conn):
        return 0
    anchor = (now or datetime.now(timezone.utc)).date()
    created = 0
    for year, month in _iter_months(anchor, behind=months_behind, ahead=months_ahead):
        child = partition_table_name(year, month)
        exists = conn.execute(
            """
            SELECT 1
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = current_schema()
              AND c.relname = %s
            """,
            (child,),
        ).fetchone()
        if exists:
            continue
        _create_observation_partition(conn, year, month)
        created += 1
    return created


# Guard against absurd backdating (bad data / clock skew) creating unbounded
# partition sprawl while still allowing legitimate historical backfills.
_MAX_OBSERVATION_MONTHS_BEHIND = 120  # ~10 years


class ObservationPartitionRangeError(ValueError):
    """``observed_at`` is outside the window for which a partition may be created."""

    def __init__(self, observed_at: str, *, months_ahead: int, months_behind: int) -> None:
        self.observed_at = observed_at
        self.months_ahead = months_ahead
        self.months_behind = months_behind
        super().__init__(
            f"observed_at {observed_at!r} is outside the supported partition window "
            f"({months_behind} months in the past to {months_ahead} months in the future)"
        )


def _month_index(value: date) -> int:
    return value.year * 12 + (value.month - 1)


def _parse_observed_at_month(observed_at: str) -> date | None:
    text = (observed_at or "").strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text[:10])
        except ValueError:
            return None
    return date(parsed.year, parsed.month, 1)


def ensure_observation_partition_for(
    conn: Any,
    observed_at: str,
    *,
    now: datetime | None = None,
    months_ahead: int = 2,
    months_behind: int = _MAX_OBSERVATION_MONTHS_BEHIND,
) -> bool:
    """Ensure the monthly partition covering *observed_at* exists.

    Returns ``True`` when a partition was created. Bulk/connector ingest with an
    ``observed_at`` older than the pre-provisioned window (behind=1) previously
    raised a raw ``CheckViolation`` -> 500. This creates the covering partition
    on demand within a bounded window so historical backfills succeed, and raises
    :class:`ObservationPartitionRangeError` (mapped to 4xx by the route) for
    values so far past/future they are almost certainly bad data. Unparseable or
    non-partitioned tables are a no-op (the legacy single table has no partition
    constraint, and downstream normalisation owns bad timestamps).
    """
    if not is_observations_partitioned(conn):
        return False
    month = _parse_observed_at_month(observed_at)
    if month is None:
        return False
    anchor = (now or datetime.now(timezone.utc)).date().replace(day=1)
    delta_months = _month_index(month) - _month_index(anchor)
    if delta_months > months_ahead or delta_months < -months_behind:
        raise ObservationPartitionRangeError(observed_at, months_ahead=months_ahead, months_behind=months_behind)
    child = partition_table_name(month.year, month.month)
    exists = conn.execute(
        """
        SELECT 1
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema()
          AND c.relname = %s
        """,
        (child,),
    ).fetchone()
    if exists:
        return False
    _create_observation_partition(conn, month.year, month.month)
    return True


def _partition_end_date(partition_name: str) -> date | None:
    match = _PARTITION_NAME_RE.match(partition_name)
    if not match:
        return None
    year = int(match.group(1))
    month = int(match.group(2))
    _, end = month_range_bounds(year, month)
    return end


def list_observation_partition_names(conn: Any) -> list[str]:
    rows = conn.execute(
        """
        SELECT child.relname
        FROM pg_inherits inh
        JOIN pg_class parent ON parent.oid = inh.inhparent
        JOIN pg_class child ON child.oid = inh.inhrelid
        JOIN pg_namespace n ON n.oid = parent.relnamespace
        WHERE n.nspname = current_schema()
          AND parent.relname = %s
        ORDER BY child.relname
        """,
        (OBSERVATIONS_TABLE,),
    ).fetchall()
    return [str(row[0]) for row in rows]


def rollover_observation_partitions(
    conn: Any,
    *,
    retention_days: int,
    now: datetime | None = None,
) -> int:
    """Detach and drop monthly partitions wholly older than *retention_days*."""
    if retention_days <= 0 or not is_observations_partitioned(conn):
        return 0
    anchor = now or datetime.now(timezone.utc)
    cutoff = (anchor - timedelta(days=retention_days)).date()
    dropped = 0
    for partition_name in list_observation_partition_names(conn):
        partition_end = _partition_end_date(partition_name)
        if partition_end is None or partition_end > cutoff:
            continue
        conn.execute(f"ALTER TABLE {OBSERVATIONS_TABLE} DETACH PARTITION {partition_name}")  # nosec B608 — partition_name parsed from pg_catalog
        conn.execute(f"DROP TABLE IF EXISTS {partition_name}")  # nosec B608
        dropped += 1
        logger.info(
            "hub observations retention dropped expired partition #%d (end=%s cutoff=%s)",
            dropped,
            partition_end.isoformat(),
            cutoff.isoformat(),
        )
    return dropped


def migrate_observations_to_partitioned(conn: Any) -> bool:
    """One-shot migration from legacy unpartitioned observations to partitioned.

    Returns ``True`` when a migration ran, ``False`` when already partitioned or
    the table is absent. Intended for maintenance windows / Alembic — not run
    automatically on API bootstrap.
    """
    if not observations_table_exists(conn):
        return False
    if is_observations_partitioned(conn):
        return False

    conn.execute(f"ALTER TABLE {OBSERVATIONS_TABLE} RENAME TO {OBSERVATIONS_TABLE}_pre_partition")
    conn.execute(partitioned_observations_parent_ddl())

    bounds = conn.execute(
        f"""
        SELECT
            date_trunc('month', MIN(observed_at::timestamptz))::date AS min_month,
            date_trunc('month', MAX(observed_at::timestamptz))::date AS max_month
        FROM {OBSERVATIONS_TABLE}_pre_partition
        """  # nosec B608 — table name is a static internal migration table
    ).fetchone()
    min_month = bounds[0] if bounds and bounds[0] else date.today().replace(day=1)
    max_month = bounds[1] if bounds and bounds[1] else min_month

    cursor = date(min_month.year, min_month.month, 1)
    end_cursor = date(max_month.year, max_month.month, 1)
    while cursor <= end_cursor:
        conn.execute(create_observation_partition_ddl(cursor.year, cursor.month))
        if cursor.month == 12:
            cursor = date(cursor.year + 1, 1, 1)
        else:
            cursor = date(cursor.year, cursor.month + 1, 1)

    ensure_observation_partitions(conn, now=datetime.now(timezone.utc), months_ahead=2, months_behind=0)

    conn.execute(
        f"""
        INSERT INTO {OBSERVATIONS_TABLE}
            (tenant_id, canonical_id, scan_id, observed_at)
        SELECT tenant_id, canonical_id, scan_id, observed_at::timestamptz
        FROM {OBSERVATIONS_TABLE}_pre_partition
        """  # nosec B608 — table names are static internal migration tables
    )
    conn.execute(f"DROP TABLE {OBSERVATIONS_TABLE}_pre_partition")
    return True


def run_hub_observations_retention(*, retention_days: int | None = None) -> int:
    """Postgres-only retention rollover; no-op for SQLite and legacy tables."""
    days = HUB_OBSERVATIONS_RETENTION_DAYS if retention_days is None else retention_days
    if days <= 0:
        return 0
    if not _postgres_configured():
        return 0
    try:
        from agent_bom.api.postgres_common import _get_pool, _tenant_connection, bypass_tenant_rls

        with bypass_tenant_rls(audit=False), _tenant_connection(_get_pool()) as conn:
            ensure_observation_partitions(conn)
            dropped = rollover_observation_partitions(conn, retention_days=days)
            conn.commit()
            return dropped
    except Exception:  # noqa: BLE001 — cleanup loop must stay fail-open
        logger.debug("hub observations retention skipped", exc_info=True)
        return 0


def _postgres_configured() -> bool:
    import os

    return bool(os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip())


def partition_months_for_retention(retention_days: int, *, now: date | None = None) -> list[tuple[int, int]]:
    """Return ``(year, month)`` tuples that should be retained for *retention_days*."""
    anchor = now or datetime.now(timezone.utc).date()
    oldest = anchor - timedelta(days=retention_days)
    months: list[tuple[int, int]] = []
    cursor = date(oldest.year, oldest.month, 1)
    end = date(anchor.year, anchor.month, 1)
    while cursor <= end:
        months.append((cursor.year, cursor.month))
        if cursor.month == 12:
            cursor = date(cursor.year + 1, 1, 1)
        else:
            cursor = date(cursor.year, cursor.month + 1, 1)
    return months


def partition_is_expired(partition_name: str, *, retention_days: int, now: date | None = None) -> bool:
    """Pure helper: whether a partition name falls wholly before the retention window."""
    if retention_days <= 0:
        return False
    partition_end = _partition_end_date(partition_name)
    if partition_end is None:
        return False
    anchor = now or datetime.now(timezone.utc).date()
    cutoff = anchor - timedelta(days=retention_days)
    return partition_end <= cutoff


def days_in_month(year: int, month: int) -> int:
    """Return the number of days in a calendar month (test helper)."""
    return monthrange(year, month)[1]
