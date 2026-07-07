"""Generic partition-maintenance engine + retention rollover (#3463)."""

from __future__ import annotations

from datetime import date, datetime, timezone
from unittest.mock import MagicMock

import pytest

from agent_bom.api.partition_maintenance import (
    DEFAULT_PARTITION_SPECS,
    UNSAFE_PARTITION_SPECS,
    PartitionSpec,
    create_partition_ddl,
    ensure_partitions,
    is_partitioned,
    list_partition_names,
    maintain_partitions,
    migrate_table_to_partitioned,
    month_range_bounds,
    partition_end_date,
    partition_is_expired,
    partition_table_name,
    partitioned_parent_ddl,
    retained_partition_months,
    rollover_partitions,
    run_partition_retention,
    table_exists,
)

_AUDIT = PartitionSpec(
    table="audit_log",
    time_column="timestamp",
    retention_env="AGENT_BOM_AUDIT_LOG_RETENTION_DAYS",
    default_retention_days=0,
)


# ── Pure math ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("year", "month", "expected"),
    [
        (2026, 1, "audit_log_y2026m01"),
        (2026, 12, "audit_log_y2026m12"),
    ],
)
def test_partition_table_name_slug(year: int, month: int, expected: str) -> None:
    assert partition_table_name("audit_log", year, month) == expected


def test_month_range_bounds_half_open_and_year_wrap() -> None:
    assert month_range_bounds(2026, 2) == (date(2026, 2, 1), date(2026, 3, 1))
    assert month_range_bounds(2026, 12) == (date(2026, 12, 1), date(2027, 1, 1))


def test_create_partition_ddl_bounds() -> None:
    ddl = create_partition_ddl("audit_log", 2026, 7)
    assert "audit_log_y2026m07 PARTITION OF audit_log" in ddl
    assert "FROM ('2026-07-01') TO ('2026-08-01')" in ddl
    assert "FROM ('2026-12-01') TO ('2027-01-01')" in create_partition_ddl("audit_log", 2026, 12)


def test_partition_end_date_parses_only_matching_table() -> None:
    assert partition_end_date("audit_log", "audit_log_y2026m07") == date(2026, 8, 1)
    assert partition_end_date("audit_log", "llm_costs_y2026m07") is None
    assert partition_end_date("audit_log", "audit_log_backup") is None


def test_partition_is_expired_uses_partition_end() -> None:
    now = date(2026, 7, 15)
    assert partition_is_expired("audit_log", partition_table_name("audit_log", 2025, 6), retention_days=30, now=now)
    # Current month is inside the window.
    assert not partition_is_expired("audit_log", partition_table_name("audit_log", 2026, 7), retention_days=30, now=now)
    # Prior month's end (2026-07-01) is not yet past the 30-day cutoff (2026-06-15).
    assert not partition_is_expired("audit_log", partition_table_name("audit_log", 2026, 6), retention_days=30, now=now)
    # Retention disabled never expires.
    assert not partition_is_expired("audit_log", partition_table_name("audit_log", 2000, 1), retention_days=0, now=now)


def test_retained_partition_months_covers_window() -> None:
    months = retained_partition_months(70, now=date(2026, 7, 15))
    assert months == [(2026, 5), (2026, 6), (2026, 7)]  # 70 days back = 2026-05-06
    assert retained_partition_months(0) == []


# ── DDL builders ─────────────────────────────────────────────────────────────


def test_partitioned_parent_ddl_requires_time_key_in_pk() -> None:
    ddl = partitioned_parent_ddl(
        "audit_log",
        "entry_id TEXT NOT NULL, timestamp TIMESTAMPTZ NOT NULL",
        "(entry_id, timestamp)",
        "timestamp",
    )
    assert "PARTITION BY RANGE (timestamp)" in ddl
    assert "PRIMARY KEY (entry_id, timestamp)" in ddl
    with pytest.raises(ValueError, match="must include partition key"):
        partitioned_parent_ddl("audit_log", "entry_id TEXT", "(entry_id)", "timestamp")


# ── Ensure-ahead ─────────────────────────────────────────────────────────────


def test_ensure_partitions_creates_missing_children() -> None:
    conn = MagicMock()
    conn.execute.side_effect = [
        MagicMock(fetchone=MagicMock(return_value=("p",))),  # is_partitioned
        MagicMock(fetchone=MagicMock(return_value=None)),  # y2026m06 missing
        MagicMock(),  # create
        MagicMock(fetchone=MagicMock(return_value=("child",))),  # y2026m07 exists
        MagicMock(fetchone=MagicMock(return_value=None)),  # y2026m08 missing
        MagicMock(),  # create
        MagicMock(fetchone=MagicMock(return_value=None)),  # y2026m09 missing
        MagicMock(),  # create
    ]
    created = ensure_partitions(conn, _AUDIT, now=datetime(2026, 7, 5, tzinfo=timezone.utc))
    assert created == 3
    executed = [str(call.args[0]) for call in conn.execute.call_args_list]
    assert any("audit_log_y2026m06 PARTITION OF audit_log" in sql for sql in executed)
    assert any("audit_log_y2026m08 PARTITION OF audit_log" in sql for sql in executed)


def test_ensure_partitions_noop_when_not_partitioned() -> None:
    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = ("r",)  # relkind ordinary table
    assert ensure_partitions(conn, _AUDIT) == 0
    conn.execute.assert_called_once()  # only the is_partitioned probe


# ── Rollover ─────────────────────────────────────────────────────────────────


def test_rollover_drops_only_expired_partitions() -> None:
    conn = MagicMock()
    conn.execute.side_effect = [
        MagicMock(fetchone=MagicMock(return_value=("p",))),  # is_partitioned
        MagicMock(
            fetchall=MagicMock(
                return_value=[
                    ("audit_log_y2025m05",),
                    ("audit_log_y2026m06",),
                    ("audit_log_y2026m07",),
                ]
            )
        ),
        MagicMock(),  # detach
        MagicMock(),  # drop
    ]
    dropped = rollover_partitions(conn, _AUDIT, retention_days=30, now=datetime(2026, 7, 5, tzinfo=timezone.utc))
    assert dropped == 1
    detach_sql = str(conn.execute.call_args_list[2].args[0])
    drop_sql = str(conn.execute.call_args_list[3].args[0])
    assert "DETACH PARTITION audit_log_y2025m05" in detach_sql
    assert "DROP TABLE IF EXISTS audit_log_y2025m05" in drop_sql


def test_rollover_disabled_when_retention_non_positive() -> None:
    conn = MagicMock()
    assert rollover_partitions(conn, _AUDIT, retention_days=0) == 0
    conn.execute.assert_not_called()


def test_rollover_noop_when_not_partitioned() -> None:
    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = ("r",)
    assert rollover_partitions(conn, _AUDIT, retention_days=30) == 0
    conn.execute.assert_called_once()  # only the is_partitioned probe


def test_maintain_partitions_combines_ensure_and_rollover() -> None:
    conn = MagicMock()
    # is_partitioned False → both halves no-op quickly.
    conn.execute.return_value.fetchone.return_value = ("r",)
    assert maintain_partitions(conn, _AUDIT) == (0, 0)


# ── Catalog probes ───────────────────────────────────────────────────────────


def test_table_exists_and_is_partitioned() -> None:
    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = None
    assert table_exists(conn, "audit_log") is False
    conn.execute.return_value.fetchone.return_value = ("p",)
    assert is_partitioned(conn, "audit_log") is True
    conn.execute.return_value.fetchone.return_value = ("r",)
    assert is_partitioned(conn, "audit_log") is False


def test_list_partition_names_returns_children() -> None:
    conn = MagicMock()
    conn.execute.return_value.fetchall.return_value = [("audit_log_y2026m06",), ("audit_log_y2026m07",)]
    assert list_partition_names(conn, "audit_log") == ["audit_log_y2026m06", "audit_log_y2026m07"]


# ── Migration (opt-in) ───────────────────────────────────────────────────────


def test_migrate_table_renames_copies_and_drops() -> None:
    conn = MagicMock()
    fetchone_queue = [
        (1,),  # table_exists
        ("r",),  # is_partitioned (legacy)
        (date(2026, 6, 1), date(2026, 7, 1)),  # min/max month bounds
        ("p",),  # ensure_partitions: parent is partitioned
    ]
    conn.execute.return_value.fetchone.side_effect = lambda: fetchone_queue.pop(0) if fetchone_queue else None

    migrated = migrate_table_to_partitioned(
        conn,
        _AUDIT,
        columns_sql="entry_id TEXT NOT NULL, timestamp TIMESTAMPTZ NOT NULL",
        primary_key_sql="(entry_id, timestamp)",
        copy_columns="entry_id, timestamp",
        cast_time_to_timestamptz=True,
    )
    assert migrated is True
    executed = " ".join(str(call.args[0]) for call in conn.execute.call_args_list)
    assert "RENAME TO audit_log_pre_partition" in executed
    assert "INSERT INTO audit_log (entry_id, timestamp)" in executed
    assert "DROP TABLE audit_log_pre_partition" in executed


def test_migrate_noop_when_already_partitioned() -> None:
    conn = MagicMock()
    conn.execute.side_effect = [
        MagicMock(fetchone=MagicMock(return_value=(1,))),  # table_exists
        MagicMock(fetchone=MagicMock(return_value=("p",))),  # is_partitioned
    ]
    assert (
        migrate_table_to_partitioned(
            conn,
            _AUDIT,
            columns_sql="entry_id TEXT NOT NULL, timestamp TIMESTAMPTZ NOT NULL",
            primary_key_sql="(entry_id, timestamp)",
            copy_columns="entry_id, timestamp",
        )
        is False
    )


def test_migrate_refuses_partition_unsafe_table() -> None:
    unsafe = UNSAFE_PARTITION_SPECS[0]
    assert unsafe.partition_safe is False
    with pytest.raises(ValueError, match="refusing to partition"):
        migrate_table_to_partitioned(
            MagicMock(),
            unsafe,
            columns_sql="tenant_id TEXT, observed_at TIMESTAMPTZ",
            primary_key_sql="(tenant_id, observed_at)",
            copy_columns="tenant_id, observed_at",
        )


# ── Retention runner / config ────────────────────────────────────────────────


def test_run_partition_retention_noop_without_postgres(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    assert run_partition_retention() == {}


def test_run_partition_retention_noop_with_empty_specs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://x/y")
    assert run_partition_retention(specs=()) == {}


def test_run_partition_retention_fail_open(monkeypatch: pytest.MonkeyPatch) -> None:
    # Postgres configured but the pool import path raises → fail-open empty dict.
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://x/y")
    import agent_bom.api.postgres_common as pc

    monkeypatch.setattr(pc, "_get_pool", MagicMock(side_effect=RuntimeError("no pool")), raising=False)
    assert run_partition_retention() == {}


def test_retention_days_reads_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_AUDIT_LOG_RETENTION_DAYS", "45")
    assert _AUDIT.retention_days() == 45
    monkeypatch.setenv("AGENT_BOM_AUDIT_LOG_RETENTION_DAYS", "not-an-int")
    assert _AUDIT.retention_days() == 0  # invalid → default


def test_default_registry_is_partition_safe_only() -> None:
    assert all(spec.partition_safe for spec in DEFAULT_PARTITION_SPECS)
    assert {spec.table for spec in DEFAULT_PARTITION_SPECS} == {"audit_log"}
    assert all(not spec.partition_safe for spec in UNSAFE_PARTITION_SPECS)
