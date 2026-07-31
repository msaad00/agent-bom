"""Partition runway provisioning for ``hub_findings_current_observations``.

The observations parent is monthly RANGE-partitioned and the runtime Postgres
roles are deliberately DML-only, so no runtime code path can create a child
partition. Provisioning is therefore migration/deploy-owned, and the guard that
matters is *how far past today* the provisioned runway reaches — not merely
"a partition exists". These tests freeze the clock so they assert a real runway
rather than tracking the calendar.
"""

from __future__ import annotations

import logging
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any

import pytest

from agent_bom.api import hub_observations_partition as partitions
from agent_bom.api.hub_observations_partition import (
    OBSERVATION_PARTITION_RUNWAY_ALERT_MONTHS,
    OBSERVATION_PARTITION_RUNWAY_MONTHS,
    month_range_bounds,
    observation_runway_end,
    observation_runway_months_remaining,
    partition_table_name,
    provision_observation_partition_runway,
    run_hub_observations_retention,
)

_CREATE_RE = re.compile(r"CREATE TABLE IF NOT EXISTS hub_findings_current_observations_y(\d{4})m(\d{2})")


class _Result:
    def __init__(self, one: Any = None, many: list[Any] | None = None) -> None:
        self._one = one
        self._many = many or []

    def fetchone(self) -> Any:
        return self._one

    def fetchall(self) -> list[Any]:
        return self._many


class _FakePartitionedConn:
    """Minimal psycopg-shaped stand-in for the partitioned observations parent."""

    def __init__(self, existing: set[str] | None = None, *, partitioned: bool = True) -> None:
        self.statements: list[str] = []
        self.existing = set(existing or ())
        self.partitioned = partitioned
        self.commits = 0

    def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> _Result:
        self.statements.append(sql.strip())
        if "c.relkind" in sql:
            return _Result(("p",) if self.partitioned else ("r",))
        if "pg_inherits" in sql:
            return _Result(many=[(name,) for name in sorted(self.existing)])
        if "pg_class" in sql and params:
            name = str(params[0])
            return _Result((1,) if name in self.existing else None)
        if "information_schema.tables" in sql:
            return _Result((1,))
        match = _CREATE_RE.search(sql)
        if match:
            self.existing.add(partition_table_name(int(match.group(1)), int(match.group(2))))
        return _Result()

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:  # pragma: no cover - exercised only on the failure path
        pass

    def created_months(self) -> list[tuple[int, int]]:
        months = [(int(m.group(1)), int(m.group(2))) for m in (_CREATE_RE.search(s) for s in self.statements) if m]
        return sorted(months)


def _runway_end_of(months: list[tuple[int, int]]) -> date:
    return max(month_range_bounds(year, month)[1] for year, month in months)


# ── The runway guard: months past *today*, not "a partition exists" ──────────


def test_provisioned_runway_reaches_at_least_twelve_months_past_today(monkeypatch) -> None:
    """The provisioned runway must outlast a full year of not deploying."""
    monkeypatch.setattr(partitions, "_ensure_observation_partition_rls", lambda *_a: None)
    frozen_now = datetime(2026, 7, 31, tzinfo=timezone.utc)
    conn = _FakePartitionedConn()

    provision_observation_partition_runway(conn, now=frozen_now)

    runway_end = _runway_end_of(conn.created_months())
    assert runway_end - frozen_now.date() >= timedelta(days=365), (
        f"runway ends {runway_end}, only {(runway_end - frozen_now.date()).days} days past {frozen_now.date()}"
    )
    assert OBSERVATION_PARTITION_RUNWAY_MONTHS >= 12


@pytest.mark.parametrize(
    "frozen_now",
    [
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 7, 31, tzinfo=timezone.utc),
        datetime(2026, 12, 31, tzinfo=timezone.utc),
        datetime(2027, 2, 28, tzinfo=timezone.utc),
    ],
)
def test_runway_crosses_year_boundaries_without_a_gap(monkeypatch, frozen_now: datetime) -> None:
    """Every month from today to the runway end is provisioned — no holes."""
    monkeypatch.setattr(partitions, "_ensure_observation_partition_rls", lambda *_a: None)
    conn = _FakePartitionedConn()

    provision_observation_partition_runway(conn, now=frozen_now)

    months = conn.created_months()
    assert months[0] == (frozen_now.year, frozen_now.month)
    indexes = [year * 12 + (month - 1) for year, month in months]
    assert indexes == list(range(indexes[0], indexes[0] + len(indexes))), "gap in the provisioned month sequence"
    assert _runway_end_of(months) - frozen_now.date() >= timedelta(days=365)


def test_runway_top_up_is_idempotent_and_only_fills_the_gap(monkeypatch) -> None:
    """A second deploy in the same month creates nothing; a later one tops up."""
    monkeypatch.setattr(partitions, "_ensure_observation_partition_rls", lambda *_a: None)
    frozen_now = datetime(2026, 7, 31, tzinfo=timezone.utc)
    conn = _FakePartitionedConn()
    first = provision_observation_partition_runway(conn, now=frozen_now)
    assert first == OBSERVATION_PARTITION_RUNWAY_MONTHS + 1

    conn.statements.clear()
    assert provision_observation_partition_runway(conn, now=frozen_now) == 0
    assert conn.created_months() == []

    conn.statements.clear()
    later = provision_observation_partition_runway(conn, now=datetime(2026, 10, 15, tzinfo=timezone.utc))
    assert later == 3
    assert _runway_end_of(conn.created_months()) == date(2027, 11, 1)


def test_every_new_partition_child_gets_forced_tenant_rls(monkeypatch) -> None:
    """New children do not inherit RLS; provisioning must apply it to each one."""
    protected: list[str] = []
    monkeypatch.setattr(partitions, "_ensure_observation_partition_rls", lambda _conn, child: protected.append(child))
    conn = _FakePartitionedConn()

    provision_observation_partition_runway(conn, now=datetime(2026, 7, 31, tzinfo=timezone.utc))

    assert protected == [partition_table_name(y, m) for y, m in conn.created_months()]
    assert len(protected) == OBSERVATION_PARTITION_RUNWAY_MONTHS + 1


def test_provisioning_is_a_noop_on_an_unpartitioned_table() -> None:
    conn = _FakePartitionedConn(partitioned=False)
    assert provision_observation_partition_runway(conn, now=datetime(2026, 7, 31, tzinfo=timezone.utc)) == 0
    assert conn.created_months() == []


# ── Runway introspection ────────────────────────────────────────────────────


def test_observation_runway_end_is_the_exclusive_upper_bound() -> None:
    """The last *covered* day is 2026-09-30; the reported bound is exclusive."""
    conn = _FakePartitionedConn({partition_table_name(2026, 6), partition_table_name(2026, 9)})
    assert observation_runway_end(conn) == date(2026, 10, 1)


def test_observation_runway_end_none_without_partitions() -> None:
    assert observation_runway_end(_FakePartitionedConn()) is None


def test_runway_months_remaining_counts_whole_months_ahead() -> None:
    conn = _FakePartitionedConn({partition_table_name(2026, m) for m in (6, 7, 8, 9)})
    assert observation_runway_months_remaining(conn, now=datetime(2026, 7, 15, tzinfo=timezone.utc)) == 2
    # Ingest is already failing once today is past the last provisioned month.
    assert observation_runway_months_remaining(conn, now=datetime(2026, 10, 1, tzinfo=timezone.utc)) == -1


# ── The retention tick must not swallow the provisioning failure ─────────────


class _FailingMaintenance:
    """Stands in for ``_maintenance_connection``'s DML-only Postgres role."""

    def __init__(self, existing: set[str], error: Exception) -> None:
        self.conn = _FakePartitionedConn(existing)
        self.error = error

    def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> _Result:
        if "CREATE TABLE IF NOT EXISTS" in sql or "ALTER TABLE" in sql or "CREATE OR REPLACE FUNCTION" in sql:
            raise self.error
        return self.conn.execute(sql, params)

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        pass


def _install_maintenance(monkeypatch, conn: Any, *, frozen_now: datetime) -> None:
    import contextlib

    @contextlib.contextmanager
    def _maintenance_connection(_pool: Any = None):
        yield conn

    @contextlib.contextmanager
    def _bypass(**_kwargs: Any):
        yield

    import agent_bom.api.postgres_common as postgres_common

    monkeypatch.setattr(postgres_common, "_maintenance_connection", _maintenance_connection)
    monkeypatch.setattr(postgres_common, "bypass_tenant_rls", _bypass)
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom_app@127.0.0.1:5432/agent_bom")
    # Freeze the clock and clear the hourly alert throttle so the assertion is
    # about behaviour, not about today's date or test execution order.
    monkeypatch.setattr(partitions, "_utc_now", lambda: frozen_now)
    monkeypatch.setattr(partitions, "_runway_alert_state", None)


def test_retention_failure_is_logged_at_error_naming_the_runway_end(monkeypatch, caplog) -> None:
    """The only job that would extend the runway must not fail silently."""

    class InsufficientPrivilegeError(Exception):
        """Stands in for psycopg's ``InsufficientPrivilege`` (SQLSTATE 42501)."""

    existing = {partition_table_name(2026, m) for m in (6, 7, 8, 9)}
    maintenance = _FailingMaintenance(existing, InsufficientPrivilegeError("permission denied for schema public"))
    _install_maintenance(monkeypatch, maintenance, frozen_now=datetime(2026, 8, 1, tzinfo=timezone.utc))

    with caplog.at_level(logging.DEBUG, logger=partitions.logger.name):
        assert run_hub_observations_retention(retention_days=365) == 0

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors, f"expected an ERROR record, got {[(r.levelname, r.getMessage()) for r in caplog.records]}"
    message = " ".join(r.getMessage() for r in errors)
    assert "2026-09-30" in message, f"runway end not named in operator alert: {message!r}"
    assert "hub_findings_current_observations" in message
    # The alert must carry the original privilege error, not just a bare string.
    assert any(r.exc_info and r.exc_info[0] is InsufficientPrivilegeError for r in errors)
    # Nothing may be reported at DEBUG-only any more.
    assert not any(r.levelno == logging.DEBUG and "retention skipped" in r.getMessage() for r in caplog.records)


def test_retention_alerts_while_the_runway_is_still_shrinking(monkeypatch, caplog) -> None:
    """Below the alert threshold an operator gets months of warning, not a cliff."""
    existing = {partition_table_name(2026, m) for m in (6, 7, 8, 9)}
    conn = _FakePartitionedConn(existing)
    _install_maintenance(monkeypatch, conn, frozen_now=datetime(2026, 8, 1, tzinfo=timezone.utc))
    monkeypatch.setattr(partitions, "_ensure_observation_partition_rls", lambda *_a: None)
    monkeypatch.setattr(partitions, "ensure_observation_partitions", lambda *_a, **_k: 0)
    monkeypatch.setattr(partitions, "ensure_observation_partition_children_rls", lambda *_a: 0)
    monkeypatch.setattr(partitions, "rollover_observation_partitions", lambda *_a, **_k: 0)

    with caplog.at_level(logging.DEBUG, logger=partitions.logger.name):
        run_hub_observations_retention(retention_days=365)

    alerts = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert alerts, f"expected a runway alert, got {[(r.levelname, r.getMessage()) for r in caplog.records]}"
    message = " ".join(r.getMessage() for r in alerts)
    assert "2026-09-30" in message
    assert OBSERVATION_PARTITION_RUNWAY_ALERT_MONTHS >= 1


def test_denied_top_up_with_a_healthy_runway_warns_instead_of_paging(monkeypatch, caplog) -> None:
    """The denial is the *expected* steady state under the DML-only role model.

    Provisioning is migration-owned, so the runtime top-up is denied on every
    healthy deployment. Reporting that at ERROR once an hour forever would train
    operators to filter the very message that must be seen near the cliff — so
    it stays visible at WARNING and escalates to ERROR only when it is urgent.
    """

    class InsufficientPrivilegeError(Exception):
        """Stands in for psycopg's ``InsufficientPrivilege`` (SQLSTATE 42501)."""

    existing = {partition_table_name(2027, m) for m in range(1, 13)} | {partition_table_name(2026, m) for m in range(7, 13)}
    maintenance = _FailingMaintenance(existing, InsufficientPrivilegeError("permission denied for schema public"))
    _install_maintenance(monkeypatch, maintenance, frozen_now=datetime(2026, 8, 1, tzinfo=timezone.utc))

    with caplog.at_level(logging.DEBUG, logger=partitions.logger.name):
        assert run_hub_observations_retention(retention_days=365) == 0

    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, f"the denied top-up must stay visible, got {[(r.levelname, r.getMessage()) for r in caplog.records]}"
    # Still names the runway end, so the operator can see the cliff approaching.
    assert "2027-12-31" in " ".join(r.getMessage() for r in warnings)


def test_legacy_unpartitioned_table_raises_no_runway_alert(monkeypatch, caplog) -> None:
    """A legacy single-table Postgres install has no runway to alert about."""
    conn = _FakePartitionedConn(partitioned=False)
    _install_maintenance(monkeypatch, conn, frozen_now=datetime(2026, 8, 1, tzinfo=timezone.utc))

    with caplog.at_level(logging.DEBUG, logger=partitions.logger.name):
        assert run_hub_observations_retention(retention_days=365) == 0

    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


def test_retention_stays_quiet_while_the_runway_is_healthy(monkeypatch, caplog) -> None:
    existing = {partition_table_name(2027, m) for m in range(1, 13)} | {partition_table_name(2026, m) for m in range(7, 13)}
    conn = _FakePartitionedConn(existing)
    _install_maintenance(monkeypatch, conn, frozen_now=datetime(2026, 8, 1, tzinfo=timezone.utc))
    monkeypatch.setattr(partitions, "_ensure_observation_partition_rls", lambda *_a: None)
    monkeypatch.setattr(partitions, "ensure_observation_partitions", lambda *_a, **_k: 0)
    monkeypatch.setattr(partitions, "ensure_observation_partition_children_rls", lambda *_a: 0)
    monkeypatch.setattr(partitions, "rollover_observation_partitions", lambda *_a, **_k: 0)

    with caplog.at_level(logging.DEBUG, logger=partitions.logger.name):
        run_hub_observations_retention(retention_days=365)

    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []
