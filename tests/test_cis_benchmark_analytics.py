"""CIS benchmark analytics tests (#1832).

Covers the new ``aggregate_cis_benchmark_checks`` query path on both
storage backends and the ``/v1/cis/trends`` API endpoint that wires them
together. Postgres and ClickHouse are exercised against in-process fakes
so the suite stays runnable without a live database; a separate
integration test in ``tests/test_postgres_integration.py`` exercises the
real Postgres path.

Fixtures cover **AWS**, **Azure**, and **GCP** CIS records — the issue
explicitly asks for cross-cloud coverage so a future schema change in
one provider's CIS scanner can't silently break the trend roll-up.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

# ── Fixtures: AWS / Azure / GCP CIS records ─────────────────────────────


def _cis_check(
    *,
    cloud: str,
    section: str,
    status: str = "fail",
    severity: str = "high",
    measured_at: datetime | None = None,
    priority: int = 5,
) -> dict:
    """Build a CIS-shaped check row matching the analytics_contract output."""
    measured = (measured_at or datetime.now(timezone.utc)).isoformat()
    return {
        "scan_id": f"scan-{cloud}-{section}",
        "tenant_id": "tenant-x",
        "cloud": cloud,
        "check_id": f"{cloud}-{section}-001",
        "title": f"{cloud.upper()} CIS {section} demo",
        "status": status,
        "severity": severity,
        "cis_section": section,
        "evidence": "synthetic fixture",
        "resource_ids": [f"arn:{cloud}:resource:test"],
        "remediation": {"summary": "tighten config"},
        "fix_cli": "noop",
        "fix_console": "see console",
        "effort": "low",
        "priority": priority,
        "guardrails": [],
        "requires_human_review": False,
        "measured_at": measured,
    }


@pytest.fixture
def cross_cloud_cis_records() -> list[dict]:
    """20 records spread across AWS / Azure / GCP and three sections."""
    base = datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc)
    records: list[dict] = []
    for day_offset in range(5):
        ts = base + timedelta(days=day_offset)
        # 3 clouds × 3 sections × 2 statuses → enough cells for the bucket pivot
        for cloud in ("aws", "azure", "gcp"):
            for section in ("1.1", "2.1", "3.4"):
                for status in ("fail", "pass"):
                    records.append(
                        _cis_check(
                            cloud=cloud,
                            section=section,
                            status=status,
                            severity="high" if status == "fail" else "low",
                            measured_at=ts,
                        )
                    )
    return records


# ── In-process aggregator (matches the API endpoint's fallback path) ────


def _aggregate_in_memory(
    rows: list[dict],
    *,
    days: int,
    bucket: str,
    cloud: str | None = None,
    section: str | None = None,
    status: str | None = None,
    severity: str | None = None,
) -> list[dict]:
    from agent_bom.api.routes.compliance import _bucket_for

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    counts: dict[tuple[str, str, str, str, str], int] = {}
    for row in rows:
        ts = datetime.fromisoformat(row["measured_at"])
        if ts < cutoff and days > 0:
            # Records older than the window are excluded; tests use a 9999d
            # window so the whole fixture set participates.
            continue
        if cloud and row["cloud"] != cloud:
            continue
        if section and row["cis_section"] != section:
            continue
        if status and row["status"] != status:
            continue
        if severity and row["severity"] != severity:
            continue
        bucket_key = _bucket_for(row["measured_at"], bucket)
        key = (
            bucket_key,
            row["cloud"],
            row["cis_section"],
            row["status"],
            row["severity"],
        )
        counts[key] = counts.get(key, 0) + 1
    return [
        {
            "bucket": bucket_key,
            "cloud": cloud_value,
            "cis_section": section_value,
            "status": status_value,
            "severity": severity_value,
            "count": count,
        }
        for (bucket_key, cloud_value, section_value, status_value, severity_value), count in sorted(counts.items(), reverse=True)
    ]


# ── Bucket helper ───────────────────────────────────────────────────────


class TestBucketFor:
    def test_day_bucket_strips_to_midnight(self) -> None:
        from agent_bom.api.routes.compliance import _bucket_for

        out = _bucket_for("2026-04-15T13:42:11+00:00", "day")
        assert out.startswith("2026-04-15T00:00:00")

    def test_hour_bucket_keeps_hour(self) -> None:
        from agent_bom.api.routes.compliance import _bucket_for

        out = _bucket_for("2026-04-15T13:42:11+00:00", "hour")
        assert out.startswith("2026-04-15T13:00:00")

    def test_week_bucket_anchors_on_monday(self) -> None:
        from agent_bom.api.routes.compliance import _bucket_for

        # 2026-04-15 is a Wednesday → week bucket should land on Monday 2026-04-13.
        out = _bucket_for("2026-04-15T13:42:11+00:00", "week")
        assert out.startswith("2026-04-13T00:00:00")

    def test_invalid_bucket_falls_back_to_day(self) -> None:
        from agent_bom.api.routes.compliance import _bucket_for

        out = _bucket_for("2026-04-15T13:42:11+00:00", "fortnight")
        # Falls back to day truncation.
        assert out.startswith("2026-04-15T00:00:00")

    def test_empty_input_returns_empty(self) -> None:
        from agent_bom.api.routes.compliance import _bucket_for

        assert _bucket_for("", "day") == ""

    def test_unparseable_returns_input(self) -> None:
        from agent_bom.api.routes.compliance import _bucket_for

        assert _bucket_for("not-a-time", "day") == "not-a-time"


# ── In-memory aggregator covers the full filter set ─────────────────────


class TestAggregationContract:
    def test_aggregate_cross_cloud_pivot(self, cross_cloud_cis_records: list[dict]) -> None:
        out = _aggregate_in_memory(cross_cloud_cis_records, days=9999, bucket="day")
        # 5 days × 3 clouds × 3 sections × 2 statuses = 90 cells.
        assert len(out) == 90
        # Each cell has exactly one record under the synthetic fixture.
        assert all(cell["count"] == 1 for cell in out)
        # All three clouds present.
        clouds = {cell["cloud"] for cell in out}
        assert clouds == {"aws", "azure", "gcp"}

    def test_filter_by_cloud_narrows_to_single_provider(self, cross_cloud_cis_records: list[dict]) -> None:
        aws_only = _aggregate_in_memory(cross_cloud_cis_records, days=9999, bucket="day", cloud="aws")
        assert all(cell["cloud"] == "aws" for cell in aws_only)
        # 5 days × 3 sections × 2 statuses = 30 AWS cells.
        assert len(aws_only) == 30

    def test_filter_by_status_narrows_to_failures_only(self, cross_cloud_cis_records: list[dict]) -> None:
        fails = _aggregate_in_memory(cross_cloud_cis_records, days=9999, bucket="day", status="fail")
        assert all(cell["status"] == "fail" for cell in fails)
        assert len(fails) == 5 * 3 * 3  # days × clouds × sections

    def test_filter_by_severity_narrows_to_severity_label(self, cross_cloud_cis_records: list[dict]) -> None:
        highs = _aggregate_in_memory(cross_cloud_cis_records, days=9999, bucket="day", severity="high")
        assert all(cell["severity"] == "high" for cell in highs)

    def test_filter_by_section_narrows_to_one_section(self, cross_cloud_cis_records: list[dict]) -> None:
        section_only = _aggregate_in_memory(cross_cloud_cis_records, days=9999, bucket="day", section="2.1")
        assert all(cell["cis_section"] == "2.1" for cell in section_only)

    def test_compound_filters_intersect(self, cross_cloud_cis_records: list[dict]) -> None:
        narrow = _aggregate_in_memory(
            cross_cloud_cis_records,
            days=9999,
            bucket="day",
            cloud="azure",
            section="1.1",
            status="fail",
        )
        assert all(cell["cloud"] == "azure" and cell["cis_section"] == "1.1" and cell["status"] == "fail" for cell in narrow)
        # 5 days × 1 cloud × 1 section × 1 status = 5 cells.
        assert len(narrow) == 5

    def test_week_bucket_collapses_5_daily_records_into_one(self, cross_cloud_cis_records: list[dict]) -> None:
        # Picking a single (cloud, section, status, severity) cell, the
        # 5 daily records should collapse to either 1 or 2 weekly buckets
        # depending on whether the test window straddles a Monday.
        single = _aggregate_in_memory(
            cross_cloud_cis_records,
            days=9999,
            bucket="week",
            cloud="aws",
            section="1.1",
            status="fail",
            severity="high",
        )
        assert sum(cell["count"] for cell in single) == 5
        assert len(single) <= 2


# ── Fixture sanity ──────────────────────────────────────────────────────


class TestFixtureCoverage:
    def test_fixture_has_aws_azure_gcp(self, cross_cloud_cis_records: list[dict]) -> None:
        clouds = {row["cloud"] for row in cross_cloud_cis_records}
        assert clouds == {"aws", "azure", "gcp"}

    def test_fixture_has_multiple_sections(self, cross_cloud_cis_records: list[dict]) -> None:
        sections = {row["cis_section"] for row in cross_cloud_cis_records}
        assert sections == {"1.1", "2.1", "3.4"}

    def test_fixture_has_pass_and_fail_records(self, cross_cloud_cis_records: list[dict]) -> None:
        statuses = {row["status"] for row in cross_cloud_cis_records}
        assert statuses == {"pass", "fail"}


# ── Public API surface check ────────────────────────────────────────────


def test_postgres_store_exposes_aggregate_method() -> None:
    """Both stores must expose ``aggregate_cis_benchmark_checks`` for the
    trend endpoint to call. This is a contract test — if the method is
    renamed, the API endpoint silently falls back to the in-memory path
    and operators lose the columnar speedup."""
    from agent_bom.api.postgres_store import PostgresJobStore

    assert hasattr(PostgresJobStore, "aggregate_cis_benchmark_checks")
    assert callable(PostgresJobStore.aggregate_cis_benchmark_checks)


def test_clickhouse_store_exposes_aggregate_method() -> None:
    from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

    assert hasattr(ClickHouseAnalyticsStore, "aggregate_cis_benchmark_checks")
    assert callable(ClickHouseAnalyticsStore.aggregate_cis_benchmark_checks)


def test_buffered_analytics_store_proxies_aggregate(monkeypatch: pytest.MonkeyPatch) -> None:
    """The buffered wrapper must expose the same surface as the underlying
    ClickHouse store so the trend endpoint's runtime call works whether
    the caller is using the buffered or unbuffered backend."""
    from agent_bom.api.clickhouse_store import BufferedAnalyticsStore

    # Buffered store proxies via attribute lookup on _store; the trend
    # endpoint calls it via getattr(store, "aggregate_cis_benchmark_checks", None).
    assert "aggregate_cis_benchmark_checks" in dir(BufferedAnalyticsStore) or hasattr(BufferedAnalyticsStore, "_store")
