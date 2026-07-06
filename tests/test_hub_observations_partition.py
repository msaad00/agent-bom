"""Hub observations partition DDL and retention helpers (#3463)."""

from __future__ import annotations

from datetime import date, datetime, timezone
from unittest.mock import MagicMock

import pytest

from agent_bom.api.hub_observations_partition import (
    create_observation_partition_ddl,
    ensure_observation_partitions,
    is_observations_partitioned,
    list_observation_partition_names,
    migrate_observations_to_partitioned,
    month_range_bounds,
    observations_table_exists,
    partition_is_expired,
    partition_table_name,
    partitioned_observations_parent_ddl,
    rollover_observation_partitions,
)


def test_partitioned_parent_ddl_includes_partition_key_in_pk() -> None:
    ddl = partitioned_observations_parent_ddl()
    assert "PARTITION BY RANGE (observed_at)" in ddl
    assert "observed_at TIMESTAMPTZ NOT NULL" in ddl
    assert "PRIMARY KEY (tenant_id, canonical_id, scan_id, observed_at)" in ddl


def test_create_partition_ddl_monthly_bounds() -> None:
    ddl = create_observation_partition_ddl(2026, 7)
    assert "hub_findings_current_observations_y2026m07" in ddl
    assert "FROM ('2026-07-01') TO ('2026-08-01')" in ddl

    dec_ddl = create_observation_partition_ddl(2026, 12)
    assert "FROM ('2026-12-01') TO ('2027-01-01')" in dec_ddl


def test_month_range_bounds_half_open() -> None:
    start, end = month_range_bounds(2026, 2)
    assert start == date(2026, 2, 1)
    assert end == date(2026, 3, 1)


def test_partition_is_expired_uses_partition_end() -> None:
    now = date(2026, 7, 15)
    assert partition_is_expired(
        partition_table_name(2025, 6),
        retention_days=30,
        now=now,
    )
    assert not partition_is_expired(
        partition_table_name(2026, 7),
        retention_days=30,
        now=now,
    )
    assert not partition_is_expired(
        partition_table_name(2026, 6),
        retention_days=30,
        now=now,
    )


def test_ensure_observation_partitions_creates_missing_children() -> None:
    conn = MagicMock()
    conn.execute.side_effect = [
        MagicMock(fetchone=MagicMock(return_value=("p",))),  # is_observations_partitioned
        MagicMock(fetchone=MagicMock(return_value=None)),  # y2026m06 missing
        MagicMock(),
        MagicMock(fetchone=MagicMock(return_value=("child",))),  # y2026m07 exists
        MagicMock(fetchone=MagicMock(return_value=None)),  # y2026m08 missing
        MagicMock(),
        MagicMock(fetchone=MagicMock(return_value=None)),  # y2026m09 missing
        MagicMock(),
    ]

    created = ensure_observation_partitions(
        conn,
        now=datetime(2026, 7, 5, tzinfo=timezone.utc),
        months_ahead=2,
        months_behind=1,
    )

    assert created == 3
    executed = [str(call.args[0]).strip() for call in conn.execute.call_args_list]
    assert any("CREATE TABLE IF NOT EXISTS hub_findings_current_observations_y2026m06" in sql for sql in executed)
    assert any("CREATE TABLE IF NOT EXISTS hub_findings_current_observations_y2026m08" in sql for sql in executed)


def test_ensure_observation_partitions_noop_when_not_partitioned() -> None:
    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = ("r",)
    assert ensure_observation_partitions(conn) == 0
    conn.execute.assert_called_once()


def test_rollover_drops_only_expired_partitions() -> None:
    conn = MagicMock()
    conn.execute.side_effect = [
        MagicMock(fetchone=MagicMock(return_value=("p",))),  # is_observations_partitioned
        MagicMock(
            fetchall=MagicMock(
                return_value=[
                    ("hub_findings_current_observations_y2025m05",),
                    ("hub_findings_current_observations_y2026m06",),
                    ("hub_findings_current_observations_y2026m07",),
                ]
            )
        ),
        MagicMock(),
        MagicMock(),
    ]

    dropped = rollover_observation_partitions(
        conn,
        retention_days=30,
        now=datetime(2026, 7, 5, tzinfo=timezone.utc),
    )

    assert dropped == 1
    detach_sql = str(conn.execute.call_args_list[2].args[0])
    drop_sql = str(conn.execute.call_args_list[3].args[0])
    assert "DETACH PARTITION hub_findings_current_observations_y2025m05" in detach_sql
    assert "DROP TABLE IF EXISTS hub_findings_current_observations_y2025m05" in drop_sql


def test_rollover_disabled_when_retention_non_positive() -> None:
    conn = MagicMock()
    assert rollover_observation_partitions(conn, retention_days=0) == 0
    conn.execute.assert_not_called()


def test_migrate_observations_to_partitioned_renames_and_copies() -> None:
    conn = MagicMock()
    fetchone_queue = [
        (1,),  # observations_table_exists
        ("r",),  # is_observations_partitioned (legacy)
        (date(2026, 6, 1), date(2026, 7, 1)),  # min/max month
        ("p",),  # ensure_observation_partitions: parent is partitioned
    ]

    def _fetchone() -> object | None:
        if fetchone_queue:
            return fetchone_queue.pop(0)
        return None

    conn.execute.return_value.fetchone.side_effect = _fetchone

    migrated = migrate_observations_to_partitioned(conn)

    assert migrated is True
    executed = " ".join(str(call.args[0]) for call in conn.execute.call_args_list)
    assert "RENAME TO hub_findings_current_observations_pre_partition" in executed
    assert "INSERT INTO hub_findings_current_observations" in executed
    assert "DROP TABLE hub_findings_current_observations_pre_partition" in executed


def test_migrate_observations_noop_when_already_partitioned() -> None:
    conn = MagicMock()
    conn.execute.side_effect = [
        MagicMock(fetchone=MagicMock(return_value=(1,))),
        MagicMock(fetchone=MagicMock(return_value=("p",))),
    ]
    assert migrate_observations_to_partitioned(conn) is False


def test_observations_table_exists_and_partition_detection() -> None:
    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = None
    assert observations_table_exists(conn) is False

    conn.execute.return_value.fetchone.return_value = ("p",)
    assert is_observations_partitioned(conn) is True


def test_list_observation_partition_names_returns_child_relations() -> None:
    conn = MagicMock()
    conn.execute.return_value.fetchall.return_value = [
        ("hub_findings_current_observations_y2026m06",),
        ("hub_findings_current_observations_y2026m07",),
    ]
    assert list_observation_partition_names(conn) == [
        "hub_findings_current_observations_y2026m06",
        "hub_findings_current_observations_y2026m07",
    ]


@pytest.mark.parametrize(
    ("year", "month", "expected"),
    [
        (2026, 1, "hub_findings_current_observations_y2026m01"),
        (2026, 12, "hub_findings_current_observations_y2026m12"),
    ],
)
def test_partition_table_name_slug(year: int, month: int, expected: str) -> None:
    assert partition_table_name(year, month) == expected
