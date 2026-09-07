"""Conservative producer assurance without changing live ingestion authority."""

import json
from datetime import datetime, timezone

import pytest

from agent_bom.api.gateway_activity_store import SQLiteGatewayActivityStore, _record_from_json, gateway_activity_record_from_event

NOW = datetime(2026, 7, 28, 12, tzinfo=timezone.utc)


def record(event_id="legacy", **kwargs):
    return gateway_activity_record_from_event(
        dict(
            schema_version="gateway.runtime.event.v1",
            event_id=event_id,
            decision_id=event_id,
            event_type="gateway.tool_call.allowed",
            event_timestamp="2026-07-28T11:59:00+00:00",
            agent_id="agent-a",
            upstream="files",
            tool="read_file",
            decision="allow",
            policy_source="policy",
            trace_id="trace",
        ),
        tenant_id="tenant-a",
        source_id="collector",
        session_id="batch",
        received_at=NOW,
        **kwargs,
    )


def provenance(**kwargs):
    from agent_bom.api.proxy_provenance import GatewaySubmissionProvenance

    return GatewaySubmissionProvenance(submission_source_id="collector", submission_session_id="batch", **kwargs)


def test_legacy_serialization_and_digest_remain_immutable(tmp_path):
    legacy = record()
    assert legacy.event_digest == "6c7f86b8bf60cccf813b1e65d57732f1590bfde6c15d6d80057de540e1500070"
    assert "submission_provenance" not in legacy.to_dict()
    assert legacy.producer_assurance == "unknown"
    store = SQLiteGatewayActivityStore(str(tmp_path / "ledger.db"))
    store.append_batch([legacy])
    persisted = store.list_activity("tenant-a").events[0]
    assert persisted["event_digest"] == legacy.event_digest
    assert _record_from_json(json.dumps(persisted)).producer_assurance == "unknown"
    assert store.append_batch([legacy]).duplicate_event_ids == ("legacy",)


def test_new_typed_provenance_roundtrips_without_verified_state(tmp_path):
    p = provenance(
        producer_assurance="caller_asserted",
        reported_source_id="reported-runtime",
        reported_session_id="reported-session",
        submitter_principal_id="principal-a",
        authentication_method="api_key",
    )
    new = record("new", submission_provenance=p)
    assert new.record_schema_version == "gateway.activity.record.v2"
    assert new.producer_assurance == "caller_asserted"
    store = SQLiteGatewayActivityStore(str(tmp_path / "ledger.db"))
    store.append_batch([record(), new])
    rows = store.list_activity("tenant-a").events
    restored = _record_from_json(json.dumps(rows[1]))
    assert restored.submission_provenance == p
    assert restored.event_digest == new.event_digest
    assert store.append_batch([new]).duplicate_event_ids == ("new",)


def test_provenance_rejects_verified_and_credential_fields():
    for kwargs in (
        {"producer_assurance": "verified"},
        {"token": "sensitive"},
        {"secret": "sensitive"},
        {"submitter_principal_id": "a" * 201},
    ):
        with pytest.raises(ValueError):
            provenance(**kwargs)


def test_submitter_change_cannot_rewrite_hashed_provenance():
    first = record("new", submission_provenance=provenance(submitter_principal_id="principal-a", authentication_method="api_key"))
    second = record("new", submission_provenance=provenance(submitter_principal_id="principal-b", authentication_method="oidc"))
    assert first.event_digest != second.event_digest
    assert first.to_dict() != second.to_dict()


def test_changed_reported_origin_changes_digest_and_mismatched_context_rejected():
    first = record("new", submission_provenance=provenance(reported_source_id="a"))
    second = record("new", submission_provenance=provenance(reported_source_id="b"))
    assert first.event_digest != second.event_digest
    with pytest.raises(ValueError):
        record("new", submission_provenance=provenance().model_copy(update={"submission_source_id": "different"}))
    with pytest.raises(ValueError):
        record("new", submission_provenance={"producer_assurance": "caller_asserted"})


def test_analytics_projects_only_typed_server_provenance():
    from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

    store = object.__new__(ClickHouseAnalyticsStore)
    claimed = store._event_row({"event_id": "a", "submission_provenance": {"producer_assurance": "verified"}}, tenant_id="tenant-a")
    assert claimed["producer_assurance"] == "unknown"
    assert claimed["submission_provenance"] == "{}"
    p = provenance(producer_assurance="caller_asserted", reported_source_id="runtime")
    row = store._event_row({"event_id": "a", "submission_provenance": p}, tenant_id="tenant-a")
    assert row["producer_assurance"] == "caller_asserted"
    assert json.loads(row["submission_provenance"]) == p.model_dump()


def test_analytics_ddl_supports_existing_and_fresh_tables():
    from agent_bom.cloud.clickhouse import _TABLE_DDL, _TABLE_MIGRATIONS

    for field in ("producer_assurance", "submission_provenance"):
        assert any(f"ADD COLUMN IF NOT EXISTS {field}" in ddl for ddl in _TABLE_MIGRATIONS)
        assert any("CREATE TABLE IF NOT EXISTS runtime_events" in ddl and field in ddl for ddl in _TABLE_DDL)


def test_versioned_hydration_cannot_upgrade_missing_or_legacy_provenance():
    payload = record().to_dict()
    payload["record_schema_version"] = "gateway.activity.record.v2"
    with pytest.raises(ValueError):
        _record_from_json(json.dumps(payload))
    payload["submission_provenance"] = provenance().model_dump()
    payload["record_schema_version"] = "gateway.activity.record.v1"
    with pytest.raises(ValueError):
        _record_from_json(json.dumps(payload))
    payload["record_schema_version"] = "gateway.activity.record.v99"
    with pytest.raises(ValueError):
        _record_from_json(json.dumps(payload))


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_new_records_keep_dedupe_tombstones_and_conflict_semantics(backend, tmp_path):
    from agent_bom.api.gateway_activity_store import GatewayActivityConflictError, InMemoryGatewayActivityStore

    store = (
        InMemoryGatewayActivityStore(max_events_per_tenant=1)
        if backend == "memory"
        else SQLiteGatewayActivityStore(str(tmp_path / "bounded.db"), max_events_per_tenant=1)
    )
    first = record("first", submission_provenance=provenance(producer_assurance="caller_asserted"))
    store.append_batch([first])
    store.append_batch([record("later", submission_provenance=provenance())])
    assert store.append_batch([first]).duplicate_event_ids == ("first",)
    with pytest.raises(GatewayActivityConflictError):
        store.append_batch([record("first", submission_provenance=provenance(reported_source_id="other"))])
    assert store.list_activity("other-tenant").events == []


def test_postgres_page_uses_shared_versioned_decoder(monkeypatch):
    from contextlib import contextmanager
    from dataclasses import replace
    from unittest.mock import Mock

    from agent_bom.api import postgres_gateway_activity as postgres

    old = replace(record(), ingest_ordinal=1)
    new = replace(record("new", submission_provenance=provenance(producer_assurance="caller_asserted")), ingest_ordinal=2)
    connection = Mock()
    connection.execute.return_value.fetchall.return_value = [(2, 1, old.to_json()), (2, 1, new.to_json())]

    @contextmanager
    def scoped_connection(pool):
        yield connection

    monkeypatch.setattr(postgres, "_tenant_connection", scoped_connection)
    store = object.__new__(postgres.PostgresGatewayActivityStore)
    store._pool = Mock()
    store.max_events_per_tenant = 100
    store.max_tombstones_per_tenant = 100
    page = store.list_activity("tenant-a")
    assert [row["record_schema_version"] for row in page.events] == ["gateway.activity.record.v1", "gateway.activity.record.v2"]
    assert page.events[0]["event_digest"] == old.event_digest
    assert page.events[1]["submission_provenance"]["producer_assurance"] == "caller_asserted"
