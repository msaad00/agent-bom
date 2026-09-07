"""Canonical SLA deadlines survive rescans without inventing legacy provenance."""

from __future__ import annotations

import pytest

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, SQLiteComplianceHubStore
from agent_bom.api.finding_lifecycle import enriched_finding_payload
from agent_bom.finding_scope import canonical_finding_payload


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryComplianceHubStore()
    return SQLiteComplianceHubStore(str(tmp_path / "sla.db"))


def ingest(store, stamp, *, severity="high", tenant="tenant-a", **fields):
    finding = {"id": "finding-sla", "severity": severity, "first_seen": stamp, **fields}
    store.add(tenant, [finding])
    store.upsert_current_batch(tenant, [finding], observed_at=stamp, batch_id=stamp)
    current = store.get_current(tenant, "finding-sla")
    assert current is not None
    return canonical_finding_payload(enriched_finding_payload(current))


def test_rescan_deadline_uses_canonical_earliest_observation(store):
    first = ingest(store, "2026-08-01T00:00:00Z")
    later = ingest(store, "2026-09-01T00:00:00Z")
    assert later["first_seen"] == "2026-08-01T00:00:00Z"
    assert later["sla_due_at"] == first["sla_due_at"] == "2026-08-31T00:00:00+00:00"
    assert later["sla_due_at_source"] == "severity-kev/v1"


def test_severity_change_recalculates_from_original_anchor(store):
    ingest(store, "2026-08-01T00:00:00Z")
    later = ingest(store, "2026-09-01T00:00:00Z", severity="critical")
    assert later["sla_due_at"] == "2026-08-08T00:00:00+00:00"


@pytest.mark.parametrize("source", ["explicit", None, "future-policy/v2"])
def test_rescan_preserves_override_or_unknown_existing_deadline(store, source):
    fields = {"sla_due_at": "2026-12-25T00:00:00+00:00"}
    if source is not None:
        fields["sla_due_at_source"] = source
    first = ingest(store, "2026-08-01T00:00:00Z", **fields)
    later = ingest(store, "2026-09-01T00:00:00Z")
    assert later["sla_due_at"] == first["sla_due_at"]
    assert later["sla_due_at_source"] == ("explicit" if source == "explicit" else "unknown")


def test_known_earlier_kev_deadline_survives_rescan(store):
    ingest(store, "2026-08-01T00:00:00Z", kev_due_date="2026-08-03")
    later = ingest(store, "2026-09-01T00:00:00Z")
    assert later["sla_due_at"] == "2026-08-03T00:00:00+00:00"


def test_sqlite_restart_preserves_override_and_tenant_boundary(tmp_path):
    path = str(tmp_path / "restart.db")
    store = SQLiteComplianceHubStore(path)
    ingest(store, "2026-08-01T00:00:00Z", sla_due_at="2026-12-25T00:00:00Z", sla_due_at_source="explicit")
    reopened = SQLiteComplianceHubStore(path)
    later = ingest(reopened, "2026-09-01T00:00:00Z")
    other = ingest(reopened, "2026-09-01T00:00:00Z", tenant="tenant-b")
    assert later["sla_due_at"] == "2026-12-25T00:00:00Z"
    assert other["sla_due_at"] == "2026-10-01T00:00:00+00:00"


def test_missing_first_observation_does_not_retain_stale_derived_due():
    row = canonical_finding_payload({"severity": "high", "sla_due_at": "2026-10-01T00:00:00Z", "sla_due_at_source": "severity-kev/v1"})
    assert row["sla_due_at"] is None
    assert row["sla_due_at_source"] == "unavailable"


def test_legacy_overlay_preserves_unattributed_deadline_before_ledger_refresh(store):
    import json

    ingest(store, "2026-08-01T00:00:00Z", sla_due_at="2026-12-25T00:00:00Z")
    # Simulate the pre-provenance layout: deadline only in mutable ledger,
    # current-state overlay contains the ledger ID and no SLA metadata.
    if isinstance(store, InMemoryComplianceHubStore):
        store._current["tenant-a"]["finding-sla"]["payload"] = {"id": "finding-sla"}
        store._by_tenant["tenant-a"][0].pop("sla_due_at_source", None)
    else:
        with store._conn:
            store._conn.execute(
                "UPDATE hub_findings_current SET payload=? WHERE tenant_id=?", (json.dumps({"id": "finding-sla"}), "tenant-a")
            )
            store._conn.execute(
                "UPDATE compliance_hub_findings SET payload=json_remove(payload, '$.sla_due_at_source') WHERE tenant_id=?", ("tenant-a",)
            )
    later = ingest(store, "2026-09-01T00:00:00Z")
    assert later["sla_due_at"] == "2026-12-25T00:00:00Z"
    assert later["sla_due_at_source"] == "unknown"


def test_out_of_order_and_duplicate_observations_do_not_move_deadline(store):
    ingest(store, "2026-09-01T00:00:00Z")
    earlier = ingest(store, "2026-08-01T00:00:00Z")
    duplicate = ingest(store, "2026-08-01T00:00:00Z")
    assert earlier["sla_due_at"] == duplicate["sla_due_at"] == "2026-08-31T00:00:00+00:00"
    assert duplicate["scan_count"] == 2


def test_explicit_new_assignment_can_replace_an_existing_assignment(store):
    ingest(store, "2026-08-01T00:00:00Z", sla_due_at="2026-12-25T00:00:00Z", sla_due_at_source="explicit")
    changed = ingest(store, "2026-09-01T00:00:00Z", sla_due_at="2026-10-20T00:00:00Z", sla_due_at_source="explicit")
    assert changed["sla_due_at"] == "2026-10-20T00:00:00Z"
    assert changed["sla_due_at_source"] == "explicit"


def test_concurrent_sqlite_rescans_preserve_known_assignment(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    path = str(tmp_path / "concurrent.db")
    store = SQLiteComplianceHubStore(path)
    ingest(store, "2026-08-01T00:00:00Z", sla_due_at="2026-12-25T00:00:00Z", sla_due_at_source="explicit")
    stores = [SQLiteComplianceHubStore(path), SQLiteComplianceHubStore(path)]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(ingest, instance, stamp) for instance, stamp in zip(stores, ["2026-09-01T00:00:00Z", "2026-08-20T00:00:00Z"])
        ]
        for future in futures:
            assert future.result()["sla_due_at"] == "2026-12-25T00:00:00Z"
    row = store.get_current("tenant-a", "finding-sla")
    assert row["first_seen"] == "2026-08-01T00:00:00Z"
    assert row["last_seen"] == "2026-09-01T00:00:00Z"
    assert row["scan_count"] == 3


def test_postgres_legacy_lookup_locks_existing_rows_in_stable_tenant_scope():
    from agent_bom.api.postgres_compliance_hub import _fetch_ledger_payloads_postgres

    class Connection:
        calls = []

        def execute(self, sql, params):
            self.calls.append((sql, params))
            return self

        def fetchall(self):
            return []

    connection = Connection()
    assert _fetch_ledger_payloads_postgres(connection, "tenant-a", ["finding-sla"], for_update=True) == {}
    sql, params = connection.calls[0]
    assert "ORDER BY finding_id FOR UPDATE" in sql
    assert params == ("tenant-a", ["finding-sla"])


def test_same_batch_duplicate_does_not_replace_an_explicit_assignment(store):
    first = {
        "id": "finding-sla",
        "severity": "high",
        "first_seen": "2026-08-01T00:00:00Z",
        "sla_due_at": "2026-12-25T00:00:00Z",
        "sla_due_at_source": "explicit",
    }
    duplicate = {"id": "finding-sla", "severity": "high", "first_seen": "2026-08-01T00:00:00Z"}
    store.add("tenant-a", [first, duplicate])
    assert store.list("tenant-a")[0]["sla_due_at"] == "2026-12-25T00:00:00Z"
    store.upsert_current_batch("tenant-a", [duplicate], observed_at="2026-08-01T00:00:00Z", batch_id="same-batch")
    current = store.get_current("tenant-a", "finding-sla")
    assert canonical_finding_payload(enriched_finding_payload(current))["sla_due_at"] == "2026-12-25T00:00:00Z"
