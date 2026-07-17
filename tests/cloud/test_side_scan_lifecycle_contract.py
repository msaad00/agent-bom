"""Contract tests for durable, provider-neutral side-scan lifecycle state."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.cloud.side_scan_lifecycle import (
    CleanupStatus,
    ExecutionStatus,
    SideScanStateConflictError,
    SideScanTemporaryResource,
    SQLiteSideScanStateStore,
    TemporaryResourceStatus,
    new_side_scan_execution,
    side_scan_provider_capabilities,
)


def _execution(*, tenant_id: str = "tenant-a", idempotency_key: str = "scan-request-1"):
    return new_side_scan_execution(
        tenant_id=tenant_id,
        provider="azure",
        account_id="subscription-1",
        target_id="/subscriptions/subscription-1/disks/os-disk",
        collector_id="collector-1",
        idempotency_key=idempotency_key,
        now="2026-07-17T20:00:00Z",
    )


def test_provider_capabilities_do_not_claim_unshipped_executors() -> None:
    capabilities = side_scan_provider_capabilities()

    assert capabilities["aws"].executor == "shipped"
    assert capabilities["aws"].cli_available is True
    assert capabilities["azure"].executor == "shipped"
    assert capabilities["gcp"].executor == "shipped"
    assert capabilities["azure"].cli_available is False
    assert capabilities["gcp"].cli_available is False


@pytest.mark.parametrize("status", [ExecutionStatus.DISABLED, ExecutionStatus.DENIED, ExecutionStatus.FAILED])
def test_non_execution_states_are_unevaluable_not_clean(status: ExecutionStatus) -> None:
    record = _execution().transition(status=status, phase="finished", now="2026-07-17T20:01:00Z")
    evidence = record.to_evidence_dict()

    assert evidence["schema_version"] == "agent-bom.cwpp.side_scan.evidence.v1"
    assert evidence["execution_status"] == status.value
    assert evidence["disposition"] == "unevaluable"
    assert evidence["negative_result_scope"] == "unavailable"
    assert evidence["clean_workload_assertion"] is False


def test_scan_is_complete_only_after_cleanup_completes() -> None:
    running = _execution().transition(
        status=ExecutionStatus.RUNNING,
        phase="scanning",
        now="2026-07-17T20:00:30Z",
    )
    record = running.transition(
        status=ExecutionStatus.SCAN_COMPLETE,
        phase="cleanup",
        cleanup_status=CleanupStatus.PENDING,
        now="2026-07-17T20:01:00Z",
    )

    assert record.to_evidence_dict()["disposition"] == "partial"

    cleaned = record.transition(
        phase="finished",
        cleanup_status=CleanupStatus.COMPLETE,
        package_count=12,
        vulnerability_count=2,
        now="2026-07-17T20:02:00Z",
    )
    evidence = cleaned.to_evidence_dict()

    assert evidence["disposition"] == "complete"
    assert evidence["negative_result_scope"] == "scanned_disk_only"
    assert evidence["package_count"] == 12
    assert evidence["vulnerability_count"] == 2
    assert evidence["clean_workload_assertion"] is False


def test_cleanup_ownership_is_deterministic_and_scope_bound() -> None:
    first = _execution()
    duplicate = _execution()

    assert first.execution_id == duplicate.execution_id
    assert first.cleanup_ownership == duplicate.cleanup_ownership
    tags = first.cleanup_ownership.required_tags()
    assert first.cleanup_ownership.owns(tags)
    assert not first.cleanup_ownership.owns({**tags, "agent-bom-sidescan-owner": "other"})
    assert not first.cleanup_ownership.owns({"agent-bom-sidescan": "true"})


def test_resource_registration_and_cleanup_are_retry_safe() -> None:
    record = _execution()
    snapshot = SideScanTemporaryResource(
        kind="snapshot",
        resource_id="snap-1",
        status=TemporaryResourceStatus.CREATED,
        ownership_tags=record.cleanup_ownership.required_tags(),
    )

    registered = record.register_resource(snapshot, now="2026-07-17T20:01:00Z")
    assert registered.register_resource(snapshot, now="2026-07-17T20:02:00Z") == registered
    assert registered.cleanup_candidates() == (snapshot,)

    wrong_owner = SideScanTemporaryResource(
        kind="disk",
        resource_id="disk-foreign",
        status=TemporaryResourceStatus.CREATED,
        ownership_tags={"agent-bom-sidescan": "true", "agent-bom-sidescan-owner": "foreign"},
    )
    with pytest.raises(ValueError, match="cleanup ownership"):
        registered.register_resource(wrong_owner, now="2026-07-17T20:02:00Z")

    deleted = registered.mark_resource_cleanup(
        "snap-1",
        status=TemporaryResourceStatus.DELETED,
        now="2026-07-17T20:03:00Z",
    )
    assert deleted.cleanup_candidates() == ()
    assert deleted.mark_resource_cleanup(
        "snap-1",
        status=TemporaryResourceStatus.DELETED,
        now="2026-07-17T20:04:00Z",
    ) == deleted
    with pytest.raises(ValueError, match="invalid resource cleanup transition"):
        deleted.mark_resource_cleanup(
            "snap-1",
            status=TemporaryResourceStatus.CLEANUP_FAILED,
            now="2026-07-17T20:05:00Z",
        )


def test_cleanup_cannot_complete_while_owned_resource_remains() -> None:
    record = _execution()
    snapshot = SideScanTemporaryResource(
        kind="snapshot",
        resource_id="snap-1",
        status=TemporaryResourceStatus.CREATED,
        ownership_tags=record.cleanup_ownership.required_tags(),
    )
    registered = record.register_resource(snapshot, now="2026-07-17T20:01:00Z")

    with pytest.raises(ValueError, match="temporary resources remain"):
        registered.transition(
            cleanup_status=CleanupStatus.COMPLETE,
            now="2026-07-17T20:02:00Z",
        )


def test_sqlite_store_survives_restart_and_deduplicates_jobs(tmp_path: Path) -> None:
    db_path = tmp_path / "side-scan-state.db"
    record = _execution()
    store = SQLiteSideScanStateStore(db_path)

    assert store.create_or_get(record) == record
    assert store.create_or_get(_execution()) == record

    restarted = SQLiteSideScanStateStore(db_path)
    assert restarted.get(tenant_id="tenant-a", execution_id=record.execution_id) == record
    assert restarted.get(tenant_id="tenant-b", execution_id=record.execution_id) is None

    other_tenant = _execution(tenant_id="tenant-b")
    assert restarted.create_or_get(other_tenant).execution_id != record.execution_id


def test_sqlite_store_rejects_stale_worker_update(tmp_path: Path) -> None:
    store = SQLiteSideScanStateStore(tmp_path / "side-scan-state.db")
    original = store.create_or_get(_execution())
    running = original.transition(status=ExecutionStatus.RUNNING, phase="snapshot", now="2026-07-17T20:01:00Z")
    store.save(running, expected_version=original.state_version)

    stale = original.transition(status=ExecutionStatus.DENIED, phase="finished", now="2026-07-17T20:02:00Z")
    with pytest.raises(SideScanStateConflictError):
        store.save(stale, expected_version=original.state_version)


def test_sqlite_store_returns_only_tenant_scoped_cleanup_retries(tmp_path: Path) -> None:
    store = SQLiteSideScanStateStore(tmp_path / "side-scan-state.db")
    original = store.create_or_get(_execution())
    pending = original.transition(
        status=ExecutionStatus.FAILED,
        phase="cleanup",
        cleanup_status=CleanupStatus.PENDING,
        failure_code="mount_failed",
        now="2026-07-17T20:01:00Z",
    )
    store.save(pending, expected_version=original.state_version)

    assert store.list_cleanup_due(tenant_id="tenant-a") == [pending]
    assert store.list_cleanup_due(tenant_id="tenant-b") == []

    retrying = pending.transition(
        phase="cleanup",
        cleanup_status=CleanupStatus.IN_PROGRESS,
        now="2026-07-17T20:02:00Z",
    )
    store.save(retrying, expected_version=pending.state_version)
    cleaned = retrying.transition(
        phase="finished",
        cleanup_status=CleanupStatus.COMPLETE,
        now="2026-07-17T20:03:00Z",
    )
    store.save(cleaned, expected_version=retrying.state_version)

    restarted = SQLiteSideScanStateStore(tmp_path / "side-scan-state.db")
    assert restarted.get(tenant_id="tenant-a", execution_id=cleaned.execution_id) == cleaned
    assert restarted.list_cleanup_due(tenant_id="tenant-a") == []


def test_serialized_state_contains_metadata_only() -> None:
    payload = _execution().to_dict()

    assert payload["schema_version"] == "agent-bom.cwpp.side_scan.lifecycle.v1"
    assert payload["cleanup_ownership"]["required_tags"]["agent-bom-sidescan"] == "true"
    assert "credential" not in payload
    assert "content" not in payload
    assert "secret_value" not in payload
