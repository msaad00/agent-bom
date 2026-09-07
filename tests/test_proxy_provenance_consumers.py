"""Receipt completeness and producer identity remain independent in consumers."""

from datetime import datetime, timedelta, timezone

import pytest
from test_proxy_provenance_foundation import provenance, record

from agent_bom.api.gateway_activity_store import InMemoryGatewayActivityStore, SQLiteGatewayActivityStore
from agent_bom.api.routes.gateway_feed import _feed_health_from_metrics, build_gateway_feed, build_gateway_feed_kpis
from agent_bom.api.routes.proxy import _build_runtime_production_index
from agent_bom.runtime_blueprints import evaluate_runtime_blueprint_drift


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_window_preserves_mixed_assurance_and_totals(tmp_path, backend):
    store = InMemoryGatewayActivityStore() if backend == "memory" else SQLiteGatewayActivityStore(str(tmp_path / "ledger.db"))
    store.append_batch([record(), record("new", submission_provenance=provenance(producer_assurance="caller_asserted"))])
    summary = store.summarize_window("tenant-a", start="2026-07-28T00:00:00+00:00", end="2026-07-29T00:00:00+00:00")
    assert summary.tool_calls_authorized == 2
    assert summary.producer_assurance_counts == {"unknown": 1, "caller_asserted": 1}
    empty = store.summarize_window("tenant-b", start=summary.start, end=summary.end)
    assert empty.producer_assurance_counts == {"unknown": 0, "caller_asserted": 0}


def test_feed_and_kpi_preserve_assurance_without_trusting_flat_claim():
    legacy = record().to_dict()
    legacy["producer_assurance"] = "caller_asserted"
    current = record("new", submission_provenance=provenance(producer_assurance="caller_asserted")).to_dict()
    forged = dict(current, event_id="forged", submission_provenance={**current["submission_provenance"], "producer_assurance": "verified"})
    feed = build_gateway_feed(tenant_id="tenant-a", alerts=[legacy, current, forged], llm_records=[], limit=10)
    assert {e["event_id"]: e["producer_assurance"] for e in feed["events"]} == {
        "legacy": "unknown",
        "new": "caller_asserted",
        "forged": "unknown",
    }
    kpis = build_gateway_feed_kpis(tenant_id="tenant-a", alerts=[legacy, current, forged], llm_records=[], uptime_seconds=None)
    assert kpis["calls_today"] == 3
    assert kpis["producer_assurance_counts"] == {"unknown": 2, "caller_asserted": 1}
    assert kpis["producer_assurance"] == "unknown"


@pytest.mark.parametrize("age,state", [(0, "live"), (300, "stale")])
def test_transport_freshness_does_not_upgrade_producer(age, state):
    metrics = {
        "source_id": "collector",
        "session_id": "batch",
        "received_at": (datetime.now(timezone.utc) - timedelta(seconds=age)).isoformat(),
    }
    health = _feed_health_from_metrics(metrics)
    assert health["state"] == state
    assert health["producer_assurance"] == "unknown"
    assert health["assurance_basis"] == "transport_receipt"


def test_production_index_and_blueprint_qualify_submitted_evidence():
    metrics = {
        "source_id": "collector",
        "session_id": "batch",
        "calls_by_tool": {"read_file": 1},
        "total_tool_calls": 1,
        "submission_provenance": provenance(producer_assurance="caller_asserted").model_dump(),
    }
    index = _build_runtime_production_index("tenant-a", metrics, [])
    assert index["producer_assurance_counts"] == {"unknown": 0, "caller_asserted": 1}
    assert index["producer_assurance"] == "caller_asserted"
    result = evaluate_runtime_blueprint_drift("developer", index, tenant_id="tenant-a")
    assert result["status"] == "aligned"
    assert result["comparison_scope"] == "reported_activity_only"
    assert result["producer_assurance"] == "caller_asserted"
    empty = evaluate_runtime_blueprint_drift("developer", {}, tenant_id="tenant-a")
    assert empty["status"] == "no_runtime_activity"
    assert empty["producer_assurance"] == "unknown"


def test_postgres_window_preserves_buckets_without_changing_bounds(monkeypatch):
    from contextlib import contextmanager
    from unittest.mock import Mock

    from agent_bom.api import postgres_gateway_activity as postgres

    connection = Mock()
    connection.execute.return_value.fetchall.return_value = [
        (4, 2, "gateway.tool_call.allowed", "", 2, "unknown"),
        (4, 2, "gateway.tool_call.allowed", "", 1, "caller_asserted"),
    ]

    @contextmanager
    def scoped_connection(pool):
        yield connection

    monkeypatch.setattr(postgres, "_tenant_connection", scoped_connection)
    store = object.__new__(postgres.PostgresGatewayActivityStore)
    store._pool = Mock()
    summary = store.summarize_window("tenant-a", start="2026-07-28", end="2026-07-29")
    assert summary.tool_calls_authorized == 3
    assert summary.producer_assurance_counts == {"unknown": 2, "caller_asserted": 1}
    assert (summary.latest_ordinal, summary.retention_floor_ordinal) == (4, 2)
    assert connection.execute.call_args.args[1] == ("tenant-a", "tenant-a", "tenant-a", "tenant-a", "2026-07-28", "2026-07-29")


def test_clickhouse_unknown_duplicate_dominates_without_inflating_total():
    from unittest.mock import Mock

    from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

    store = object.__new__(ClickHouseAnalyticsStore)
    store._client = Mock()
    store._client.query_json.return_value = [{"event_type": "gateway.tool_call.allowed", "severity": "info", "cnt": 3, "unknown_count": 2}]
    row = store.query_event_summary(24, tenant_id="tenant-a")[0]
    assert row["cnt"] == 3
    assert row["producer_assurance_counts"] == {"unknown": 2, "caller_asserted": 1}
    assert row["producer_assurance"] == "unknown"


def test_configuration_presence_does_not_assert_runtime_liveness():
    from agent_bom.api.service_registry import _runtime_flag

    assert _runtime_flag({"has_proxy": True}, "has_proxy")["state"] == "connected"
    assert "configuration" in _runtime_flag({"has_proxy": True}, "has_proxy")["detail"]


def test_legacy_version_cannot_acquire_assurance_from_extra_metadata():
    from agent_bom.api.proxy_provenance import projected_producer_assurance

    old = record().to_dict()
    old["submission_provenance"] = provenance(producer_assurance="caller_asserted").model_dump()
    assert projected_producer_assurance(old) == "unknown"
