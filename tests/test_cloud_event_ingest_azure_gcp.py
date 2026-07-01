"""Tests for event-driven Azure + GCP posture ingestion.

Mirrors ``tests/test_cloud_event_ingest.py`` (AWS): patch the provider's scoped
``discover_inventory`` to return a deterministic synthetic inventory, and assert
a changed resource re-evaluates ONLY its resource type's CIS checks and produces
the expected finding — plus the bounded, fail-closed queue-drain contract.
"""

from __future__ import annotations

import json
import types
from typing import Any
from unittest.mock import patch

import pytest

from agent_bom.api.connection_store import (
    CloudConnectionRecord,
    InMemoryConnectionStore,
)
from agent_bom.cloud import azure_event_ingest, gcp_event_ingest
from agent_bom.cloud.azure_event_ingest import (
    consume_azure_events,
    parse_azure_event,
)
from agent_bom.cloud.azure_event_ingest import (
    dispatch_change_event as azure_dispatch,
)
from agent_bom.cloud.gcp_event_ingest import (
    consume_gcp_events,
    parse_gcp_event,
)
from agent_bom.cloud.gcp_event_ingest import (
    dispatch_change_event as gcp_dispatch,
)

_SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"
_TENANT = "99999999-8888-7777-6666-555555555555"
_PROJECT = "my-project"


# --------------------------------------------------------------------------- #
# Shared fake CIS report (drives the finding assertion for either cloud)
# --------------------------------------------------------------------------- #


def _fake_cis_report(fail_check_id: str, expected_checks: set[str]) -> Any:
    class _Report:
        def to_dict(self) -> dict[str, Any]:
            checks = [
                {
                    "check_id": cid,
                    "title": f"Check {cid}",
                    "status": "fail" if cid == fail_check_id else "pass",
                    "severity": "high",
                    "resource_ids": ["the-resource"],
                    "evidence": "evidence",
                }
                for cid in sorted(expected_checks)
            ]
            return {
                "benchmark": "CIS",
                "passed": len(checks) - 1,
                "failed": 1,
                "total": len(checks),
                "checks": checks,
            }

    return _Report()


# =========================================================================== #
# AZURE
# =========================================================================== #

_AZURE_STORAGE_CHECKS = {"3.1", "3.2", "3.3", "3.7", "3.8", "3.10", "3.11", "3.12"}


def _azure_record(*, subscription: str = _SUBSCRIPTION, tenant: str = _TENANT) -> CloudConnectionRecord:
    return CloudConnectionRecord(
        id="conn-az",
        tenant_id="tenant-a",
        provider="azure",
        display_name="prod-azure",
        role_ref="kv://vault/agent-bom-reader",
        external_id_encrypted="cipher",
        auth_params={"subscription_id": subscription, "tenant_id": tenant},
    )


def _azure_storage_event(*, subscription: str = _SUBSCRIPTION, tenant: str = _TENANT, name: str = "publicsa") -> dict[str, Any]:
    """A synthetic Event Grid-wrapped Activity Log storage-account write event."""
    return {
        "id": "evt-az-1",
        "eventType": "Microsoft.Resources.ResourceWriteSuccess",
        "subject": f"/subscriptions/{subscription}/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/{name}",
        "data": {
            "operationName": "Microsoft.Storage/storageAccounts/write",
            "subscriptionId": subscription,
            "tenantId": tenant,
        },
    }


_AZURE_SCOPED_INVENTORY: dict[str, Any] = {
    "provider": "azure",
    "status": "ok",
    "storage_accounts": [
        {
            "name": "publicsa",
            "id": "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/publicsa",
            "publicly_accessible": True,
            "allow_blob_public_access": True,
        }
    ],
}


def _patch_azure_inventory() -> Any:
    return patch(
        "agent_bom.cloud.azure_inventory.discover_inventory",
        return_value=_AZURE_SCOPED_INVENTORY,
    )


def _azure_run_benchmark(*, checks: list[str], **kwargs: Any) -> Any:
    assert set(checks) == _AZURE_STORAGE_CHECKS
    return _fake_cis_report("3.1", _AZURE_STORAGE_CHECKS)


def test_azure_parse_storage_event() -> None:
    event = parse_azure_event(_azure_storage_event())
    assert event is not None
    assert event.provider == "azure"
    assert event.resource_type == "storage"
    assert event.resource_id == "publicsa"
    assert event.account == _SUBSCRIPTION
    assert event.region == _TENANT  # tenant travels in region for the guard
    assert event.action == "Microsoft.Storage/storageAccounts/write"


def test_azure_dispatch_reevaluates_and_produces_finding() -> None:
    event = parse_azure_event(_azure_storage_event())
    assert event is not None

    record = _azure_record()
    store = InMemoryConnectionStore()
    store.put(record)
    persisted: dict[str, Any] = {}

    def _persist(rec: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
        persisted["report"] = report
        return "scan-az"

    with _patch_azure_inventory():
        delta = azure_dispatch(
            event,
            record,
            credential=object(),
            benchmark_runner=_azure_run_benchmark,
            persist=_persist,
            store=store,
        )

    assert delta is not None
    assert delta["scan_id"] == "scan-az"
    assert delta["provider"] == "azure"
    assert set(delta["checks_evaluated"]) == _AZURE_STORAGE_CHECKS
    assert delta["resource"] is not None
    assert delta["resource"]["name"] == "publicsa"
    assert delta["resource"]["publicly_accessible"] is True
    assert "3.1" in {f["check_id"] for f in delta["findings"]}

    report = persisted["report"]
    assert report.azure_cis_benchmark_data["failed"] >= 1
    assert report.scan_sources == ["cloud_connection", "cloud:azure", "event:activity_log"]

    fresh = store.get("tenant-a", "conn-az")
    assert fresh is not None
    assert fresh.last_event_at is not None
    assert fresh.last_scan_at is None


def test_azure_dispatch_drops_foreign_subscription() -> None:
    event = parse_azure_event(_azure_storage_event(subscription="00000000-0000-0000-0000-000000000000"))
    assert event is not None
    record = _azure_record()  # different subscription than the event
    called: dict[str, Any] = {}

    def _persist(rec: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
        called["hit"] = True
        return "nope"

    delta = azure_dispatch(event, record, credential=object(), persist=_persist)
    assert delta is None
    assert "hit" not in called


def test_azure_dispatch_drops_foreign_tenant() -> None:
    event = parse_azure_event(_azure_storage_event(tenant="00000000-0000-0000-0000-000000000000"))
    assert event is not None
    record = _azure_record()  # subscription matches, tenant differs
    delta = azure_dispatch(event, record, credential=object())
    assert delta is None


@pytest.mark.parametrize(
    "message",
    [
        "not json {",
        "[]",
        "null",
        # unsupported resource type (Cosmos DB has no rule):
        json.dumps(
            {
                "subject": f"/subscriptions/{_SUBSCRIPTION}/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/db",
                "data": {"operationName": "x", "subscriptionId": _SUBSCRIPTION},
            }
        ),
        # no subscription:
        json.dumps({"subject": "/subscriptions//providers/Microsoft.Storage/storageAccounts/s", "data": {"operationName": "w"}}),
    ],
)
def test_azure_parse_malformed_returns_none(message: str) -> None:
    assert parse_azure_event(message) is None


class _FakeAzureQueue:
    """Minimal Storage Queue stub: hands back a fixed message list per receive."""

    def __init__(self, batches: list[list[Any]]) -> None:
        self._batches = batches
        self.deleted: list[Any] = []

    def receive_messages(self, **kwargs: Any) -> Any:
        if self._batches:
            return iter(self._batches.pop(0))
        return iter([])

    def delete_message(self, message: Any) -> None:
        self.deleted.append(message)


def _azure_msg(body: dict[str, Any]) -> Any:
    return types.SimpleNamespace(content=json.dumps(body))


def test_azure_consume_disabled_when_no_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(azure_event_ingest.EVENT_QUEUE_ENV, raising=False)
    summary = consume_azure_events(_azure_record())
    assert summary["status"] == "disabled"
    assert summary["received"] == 0


def test_azure_consume_dispatches_and_deletes_valid_event() -> None:
    queue = _FakeAzureQueue(batches=[[_azure_msg(_azure_storage_event())]])
    store = InMemoryConnectionStore()
    record = _azure_record()
    store.put(record)
    persisted: dict[str, Any] = {}

    def _persist(rec: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
        persisted["report"] = report
        return "scan-az"

    with _patch_azure_inventory():
        summary = consume_azure_events(
            record,
            queue_url="https://acct.queue.core.windows.net/changes",
            queue_client=queue,
            credential=object(),
            benchmark_runner=_azure_run_benchmark,
            persist=_persist,
            store=store,
            max_batches=2,
        )
    assert summary["processed"] == 1
    assert summary["deleted"] == 1
    assert len(queue.deleted) == 1
    assert "report" in persisted


def test_azure_consume_drops_foreign_subscription() -> None:
    foreign = _azure_storage_event(subscription="00000000-0000-0000-0000-000000000000")
    queue = _FakeAzureQueue(batches=[[_azure_msg(foreign)]])
    called: dict[str, Any] = {}

    def _persist(rec: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
        called["hit"] = True
        return "nope"

    summary = consume_azure_events(
        _azure_record(),
        queue_url="https://acct.queue.core.windows.net/changes",
        queue_client=queue,
        credential=object(),
        persist=_persist,
        max_batches=2,
    )
    assert summary["skipped_foreign"] == 1
    assert summary["processed"] == 0
    assert len(queue.deleted) == 1
    assert "hit" not in called


def test_azure_consume_bounded_batch_stops() -> None:
    class _Endless:
        def __init__(self) -> None:
            self.receive_calls = 0
            self.deleted: list[Any] = []

        def receive_messages(self, **kwargs: Any) -> Any:
            self.receive_calls += 1
            return iter([types.SimpleNamespace(content=json.dumps({"garbage": True}))])

        def delete_message(self, message: Any) -> None:
            self.deleted.append(message)

    endless = _Endless()
    summary = consume_azure_events(
        _azure_record(),
        queue_url="https://acct.queue.core.windows.net/changes",
        queue_client=endless,
        credential=object(),
        max_batches=3,
    )
    assert endless.receive_calls == 3
    assert summary["batches"] == 3
    assert summary["skipped_malformed"] == 3
    assert summary["deleted"] == 3


# =========================================================================== #
# GCP
# =========================================================================== #

_GCP_STORAGE_CHECKS = {"5.1", "5.2"}


def _gcp_record(*, project: str = _PROJECT) -> CloudConnectionRecord:
    return CloudConnectionRecord(
        id="conn-gcp",
        tenant_id="tenant-a",
        provider="gcp",
        display_name="prod-gcp",
        role_ref="sa-key-ref",
        external_id_encrypted="cipher",
        auth_params={"project_id": project},
    )


def _gcp_storage_auditlog(*, project: str = _PROJECT, bucket: str = "public-bucket") -> dict[str, Any]:
    """A synthetic Pub/Sub-exported GCS setIamPolicy audit-log entry."""
    return {
        "protoPayload": {
            "methodName": "storage.setIamPermissions",
            "serviceName": "storage.googleapis.com",
            "resourceName": f"projects/_/buckets/{bucket}",
        },
        "resource": {"type": "gcs_bucket", "labels": {"project_id": project, "bucket_name": bucket}},
    }


_GCP_SCOPED_INVENTORY: dict[str, Any] = {
    "provider": "gcp",
    "status": "ok",
    "buckets": [
        {
            "name": "public-bucket",
            "id": "public-bucket",
            "publicly_accessible": True,
            "project_id": _PROJECT,
        }
    ],
}


def _patch_gcp_inventory() -> Any:
    return patch(
        "agent_bom.cloud.gcp_inventory.discover_inventory",
        return_value=_GCP_SCOPED_INVENTORY,
    )


def _gcp_run_benchmark(*, checks: list[str], **kwargs: Any) -> Any:
    assert set(checks) == _GCP_STORAGE_CHECKS
    return _fake_cis_report("5.1", _GCP_STORAGE_CHECKS)


def test_gcp_parse_storage_auditlog() -> None:
    event = parse_gcp_event(_gcp_storage_auditlog())
    assert event is not None
    assert event.provider == "gcp"
    assert event.resource_type == "storage"
    assert event.resource_id == "public-bucket"
    assert event.account == _PROJECT
    assert event.action == "storage.setIamPermissions"


def test_gcp_parse_compute_asset_feed() -> None:
    """The Cloud Asset feed branch: assetType + project derived from the asset name."""
    msg = {
        "asset": {
            "name": f"//compute.googleapis.com/projects/{_PROJECT}/zones/us-central1-a/instances/vm-1",
            "assetType": "compute.googleapis.com/Instance",
        }
    }
    event = parse_gcp_event(msg)
    assert event is not None
    assert event.resource_type == "compute"
    assert event.resource_id == "vm-1"
    assert event.account == _PROJECT


def test_gcp_dispatch_reevaluates_and_produces_finding() -> None:
    event = parse_gcp_event(_gcp_storage_auditlog())
    assert event is not None

    record = _gcp_record()
    store = InMemoryConnectionStore()
    store.put(record)
    persisted: dict[str, Any] = {}

    def _persist(rec: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
        persisted["report"] = report
        return "scan-gcp"

    with _patch_gcp_inventory():
        delta = gcp_dispatch(
            event,
            record,
            credentials=object(),
            benchmark_runner=_gcp_run_benchmark,
            persist=_persist,
            store=store,
        )

    assert delta is not None
    assert delta["scan_id"] == "scan-gcp"
    assert delta["provider"] == "gcp"
    assert set(delta["checks_evaluated"]) == _GCP_STORAGE_CHECKS
    assert delta["resource"] is not None
    assert delta["resource"]["name"] == "public-bucket"
    assert delta["resource"]["publicly_accessible"] is True
    assert "5.1" in {f["check_id"] for f in delta["findings"]}

    report = persisted["report"]
    assert report.gcp_cis_benchmark_data["failed"] >= 1
    assert report.scan_sources == ["cloud_connection", "cloud:gcp", "event:asset_feed"]

    fresh = store.get("tenant-a", "conn-gcp")
    assert fresh is not None
    assert fresh.last_event_at is not None
    assert fresh.last_scan_at is None


def test_gcp_dispatch_drops_foreign_project() -> None:
    event = parse_gcp_event(_gcp_storage_auditlog(project="other-project"))
    assert event is not None
    record = _gcp_record()  # different project than the event
    called: dict[str, Any] = {}

    def _persist(rec: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
        called["hit"] = True
        return "nope"

    delta = gcp_dispatch(event, record, credentials=object(), persist=_persist)
    assert delta is None
    assert "hit" not in called


@pytest.mark.parametrize(
    "message",
    [
        "not json {",
        "[]",
        "null",
        # unsupported service (BigQuery has no rule):
        json.dumps({"protoPayload": {"serviceName": "bigquery.googleapis.com", "resourceName": "projects/p/datasets/d"}}),
        # no project:
        json.dumps({"protoPayload": {"serviceName": "storage.googleapis.com", "resourceName": "projects/_/buckets/b"}}),
    ],
)
def test_gcp_parse_malformed_returns_none(message: str) -> None:
    assert parse_gcp_event(message) is None


class _FakeSubscriber:
    """Minimal Pub/Sub subscriber stub: hands back a fixed pull per call."""

    def __init__(self, batches: list[list[Any]]) -> None:
        self._batches = batches
        self.acked: list[str] = []
        self.pull_calls = 0

    def pull(self, *, subscription: str, max_messages: int) -> Any:
        self.pull_calls += 1
        received = self._batches.pop(0) if self._batches else []
        return types.SimpleNamespace(received_messages=received)

    def acknowledge(self, *, subscription: str, ack_ids: list[str]) -> None:
        self.acked.extend(ack_ids)


def _gcp_msg(body: dict[str, Any], ack_id: str) -> Any:
    message = types.SimpleNamespace(data=json.dumps(body).encode("utf-8"))
    return types.SimpleNamespace(message=message, ack_id=ack_id)


def test_gcp_consume_disabled_when_no_subscription(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(gcp_event_ingest.EVENT_SUBSCRIPTION_ENV, raising=False)
    summary = consume_gcp_events(_gcp_record())
    assert summary["status"] == "disabled"
    assert summary["received"] == 0


def test_gcp_consume_dispatches_and_acks_valid_event() -> None:
    subscriber = _FakeSubscriber(batches=[[_gcp_msg(_gcp_storage_auditlog(), "ack-1")]])
    store = InMemoryConnectionStore()
    record = _gcp_record()
    store.put(record)
    persisted: dict[str, Any] = {}

    def _persist(rec: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
        persisted["report"] = report
        return "scan-gcp"

    with _patch_gcp_inventory():
        summary = consume_gcp_events(
            record,
            subscription="projects/p/subscriptions/changes",
            subscriber_client=subscriber,
            credentials=object(),
            benchmark_runner=_gcp_run_benchmark,
            persist=_persist,
            store=store,
            max_batches=2,
        )
    assert summary["processed"] == 1
    assert summary["acked"] == 1
    assert subscriber.acked == ["ack-1"]
    assert "report" in persisted


def test_gcp_consume_drops_foreign_project() -> None:
    foreign = _gcp_storage_auditlog(project="other-project")
    subscriber = _FakeSubscriber(batches=[[_gcp_msg(foreign, "ack-foreign")]])
    called: dict[str, Any] = {}

    def _persist(rec: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
        called["hit"] = True
        return "nope"

    summary = consume_gcp_events(
        _gcp_record(),
        subscription="projects/p/subscriptions/changes",
        subscriber_client=subscriber,
        credentials=object(),
        persist=_persist,
        max_batches=2,
    )
    assert summary["skipped_foreign"] == 1
    assert summary["processed"] == 0
    assert subscriber.acked == ["ack-foreign"]
    assert "hit" not in called


def test_gcp_consume_bounded_batch_stops() -> None:
    class _Endless:
        def __init__(self) -> None:
            self.pull_calls = 0
            self.acked: list[str] = []

        def pull(self, *, subscription: str, max_messages: int) -> Any:
            self.pull_calls += 1
            return types.SimpleNamespace(received_messages=[_gcp_msg({"garbage": True}, f"ack-{self.pull_calls}")])

        def acknowledge(self, *, subscription: str, ack_ids: list[str]) -> None:
            self.acked.extend(ack_ids)

    endless = _Endless()
    summary = consume_gcp_events(
        _gcp_record(),
        subscription="projects/p/subscriptions/changes",
        subscriber_client=endless,
        credentials=object(),
        max_batches=3,
    )
    assert endless.pull_calls == 3
    assert summary["batches"] == 3
    assert summary["skipped_malformed"] == 3
    assert summary["acked"] == 3
