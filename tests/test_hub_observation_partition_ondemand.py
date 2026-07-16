"""On-demand observation partition creation for backdated bulk ingest.

``hub_findings_current_observations`` pre-provisioned only ``months_behind=1``
partitions, so bulk/connector ingest with an ``observed_at`` older than ~1 month
raised a raw ``CheckViolation`` -> 500. The partition covering ``observed_at`` is
now created on demand within a bounded window; values far outside the window
raise :class:`ObservationPartitionRangeError` (mapped to a clean 4xx).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pytest

from agent_bom.api.hub_observations_partition import (
    ObservationPartitionRangeError,
    ensure_observation_partition_for,
)


@dataclass
class _FakeCursor:
    row: tuple[Any, ...] | None = None

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.row


@dataclass
class _PartitionSpy:
    """Reports the table as partitioned; the child partition is missing."""

    executed: list[str] = field(default_factory=list)

    def execute(self, sql: str, params: tuple | None = None) -> _FakeCursor:
        norm = " ".join(sql.split()).lower()
        self.executed.append(norm)
        if "from pg_class" in norm and "relkind" in norm:
            return _FakeCursor(row=("p",))  # partitioned parent
        if "from pg_class" in norm:
            return _FakeCursor(row=None)  # child partition absent
        return _FakeCursor(row=None)

    def _created_partition(self) -> bool:
        return any("partition of hub_findings_current_observations" in s for s in self.executed)


_NOW = datetime(2026, 7, 16, tzinfo=timezone.utc)


def test_backdated_observed_at_creates_partition_on_demand():
    spy = _PartitionSpy()
    created = ensure_observation_partition_for(spy, "2026-03-01T00:00:00Z", now=_NOW)
    assert created is True
    assert spy._created_partition(), "a covering partition must be created for a backdated observation"


def test_far_future_observed_at_raises_range_error():
    spy = _PartitionSpy()
    with pytest.raises(ObservationPartitionRangeError):
        ensure_observation_partition_for(spy, "2030-01-01T00:00:00Z", now=_NOW)


def test_far_past_observed_at_raises_range_error():
    spy = _PartitionSpy()
    with pytest.raises(ObservationPartitionRangeError):
        ensure_observation_partition_for(spy, "1990-01-01T00:00:00Z", now=_NOW)


def test_non_partitioned_table_is_noop():
    @dataclass
    class _Unpartitioned:
        def execute(self, sql: str, params: tuple | None = None) -> _FakeCursor:
            return _FakeCursor(row=None)  # relkind query -> not partitioned

    assert ensure_observation_partition_for(_Unpartitioned(), "2020-01-01T00:00:00Z", now=_NOW) is False


def test_current_month_partition_not_recreated_when_present(monkeypatch):
    @dataclass
    class _Present:
        executed: list[str] = field(default_factory=list)

        def execute(self, sql: str, params: tuple | None = None) -> _FakeCursor:
            norm = " ".join(sql.split()).lower()
            self.executed.append(norm)
            if "relkind" in norm:
                return _FakeCursor(row=("p",))
            return _FakeCursor(row=(1,))  # child already exists

    spy = _Present()
    created = ensure_observation_partition_for(spy, "2026-07-16T00:00:00Z", now=_NOW)
    assert created is False
    assert not any("partition of" in s for s in spy.executed)
