"""Fake-SDK tests for Azure/GCP side-scan lifecycle adapters."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agent_bom.cloud.side_scan_lifecycle import (
    CleanupStatus,
    ExecutionStatus,
    SQLiteSideScanStateStore,
    TemporaryResourceStatus,
    new_side_scan_execution,
)
from agent_bom.cloud.side_scan_provider_adapters import (
    AzureManagedDiskLifecycleAdapter,
    GcpPersistentDiskLifecycleAdapter,
    SideScanLifecycleTimeoutError,
    SideScanPermissionDeniedError,
)
from agent_bom.cloud.side_scan_targets import CloudSideScanTarget, run_cloud_side_scan_targets


class FakeSdkError(Exception):
    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class FakeOperation:
    def __init__(self, result: Any, *, done_after: int = 1, error: Exception | None = None) -> None:
        self._result = result
        self._done_after = done_after
        self._error = error
        self.done_calls = 0

    def done(self) -> bool:
        self.done_calls += 1
        return self.done_calls >= self._done_after

    def result(self) -> Any:
        if self._error is not None:
            raise self._error
        return self._result


class FakeAzureCollection:
    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.resources: dict[str, Any] = {}
        self.create_calls: list[tuple[str, str, dict[str, Any]]] = []
        self.delete_calls: list[tuple[str, str]] = []
        self.create_error: Exception | None = None
        self.delete_failures: set[str] = set()
        self.done_after = 1

    def get(self, resource_group: str, name: str) -> Any:
        key = f"{resource_group}/{name}"
        if key not in self.resources:
            raise FakeSdkError("not found", 404)
        return self.resources[key]

    def begin_create_or_update(self, resource_group: str, name: str, parameters: dict[str, Any]) -> FakeOperation:
        if self.create_error is not None:
            raise self.create_error
        self.create_calls.append((resource_group, name, parameters))
        resource_id = f"/subscriptions/sub-1/resourceGroups/{resource_group}/providers/Microsoft.Compute/{self.kind}/{name}"
        resource = SimpleNamespace(id=resource_id, name=name, tags=parameters["tags"])
        self.resources[f"{resource_group}/{name}"] = resource
        return FakeOperation(resource, done_after=self.done_after)

    def begin_delete(self, resource_group: str, name: str) -> FakeOperation:
        self.delete_calls.append((resource_group, name))
        if name in self.delete_failures:
            return FakeOperation(None, error=FakeSdkError("delete failed token=secret", 500))
        self.resources.pop(f"{resource_group}/{name}", None)
        return FakeOperation(None)

    def list(self) -> list[Any]:
        return list(self.resources.values())


class FakeAzureVms:
    def __init__(self) -> None:
        self.data_disks: list[dict[str, Any]] = []
        self.update_calls: list[dict[str, Any]] = []

    def get(self, resource_group: str, name: str) -> Any:
        return SimpleNamespace(storage_profile=SimpleNamespace(data_disks=list(self.data_disks)))

    def begin_update(self, resource_group: str, name: str, parameters: dict[str, Any]) -> FakeOperation:
        self.update_calls.append(parameters)
        self.data_disks = list(parameters["storage_profile"]["data_disks"])
        return FakeOperation(SimpleNamespace(id=f"/subscriptions/sub-1/vms/{name}"))


class FakeGcpCollection:
    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.resources: dict[str, dict[str, Any]] = {}
        self.insert_calls: list[dict[str, Any]] = []
        self.delete_calls: list[dict[str, Any]] = []
        self.insert_error: Exception | None = None
        self.delete_failures: set[str] = set()
        self.done_after = 1

    def get(self, *, request: dict[str, Any]) -> dict[str, Any]:
        name = str(request.get("snapshot") or request.get("disk") or "")
        if name not in self.resources:
            raise FakeSdkError("not found", 404)
        return self.resources[name]

    def insert(self, *, request: dict[str, Any]) -> FakeOperation:
        if self.insert_error is not None:
            raise self.insert_error
        self.insert_calls.append(request)
        body_key = "snapshot_resource" if self.kind == "snapshots" else "disk_resource"
        body = request[body_key]
        name = body["name"]
        location = "global" if self.kind == "snapshots" else request["zone"]
        resource = {
            "name": name,
            "id": name,
            "self_link": f"https://compute.googleapis.com/compute/v1/projects/proj-1/{location}/{self.kind}/{name}",
            "labels": dict(body["labels"]),
        }
        self.resources[name] = resource
        return FakeOperation(resource, done_after=self.done_after)

    def delete(self, *, request: dict[str, Any]) -> FakeOperation:
        self.delete_calls.append(request)
        name = str(request.get("snapshot") or request.get("disk") or "")
        if name in self.delete_failures:
            return FakeOperation(None, error=FakeSdkError("delete failed token=secret", 500))
        self.resources.pop(name, None)
        return FakeOperation(None)

    def list(self, *, request: dict[str, Any]) -> list[dict[str, Any]]:
        return list(self.resources.values())


class FakeGcpInstances:
    def __init__(self) -> None:
        self.disks: list[dict[str, Any]] = []
        self.attach_calls: list[dict[str, Any]] = []
        self.detach_calls: list[dict[str, Any]] = []

    def attach_disk(self, *, request: dict[str, Any]) -> FakeOperation:
        self.attach_calls.append(request)
        disk = dict(request["attached_disk_resource"])
        self.disks.append(disk)
        return FakeOperation(None)

    def detach_disk(self, *, request: dict[str, Any]) -> FakeOperation:
        self.detach_calls.append(request)
        device_name = request["device_name"]
        self.disks = [disk for disk in self.disks if disk.get("device_name") != device_name]
        return FakeOperation(None)


class FakeMount:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.unmounted: list[Path] = []

    def attach_and_mount(self, volume_id: str, device: str) -> Path:
        return self.path

    def unmount(self, mount_point: Path) -> None:
        self.unmounted.append(mount_point)


def _target(provider: str) -> CloudSideScanTarget:
    if provider == "azure":
        return CloudSideScanTarget(
            provider="azure",
            target_type="managed_disk",
            target_id="/subscriptions/sub-1/resourceGroups/workloads/providers/Microsoft.Compute/disks/os-disk",
            name="os-disk",
            account_id="sub-1",
            location="eastus",
            size_gb=128,
            encryption="provider-managed",
        )
    return CloudSideScanTarget(
        provider="gcp",
        target_type="persistent_disk",
        target_id="https://compute.googleapis.com/compute/v1/projects/proj-1/zones/us-central1-a/disks/os-disk",
        name="os-disk",
        account_id="proj-1",
        location="us-central1-a",
        size_gb=128,
        encryption="provider-managed",
    )


def _record(provider: str, store: SQLiteSideScanStateStore):
    target = _target(provider)
    record = new_side_scan_execution(
        tenant_id="tenant-a",
        provider=target.provider,
        account_id=target.account_id,
        target_id=target.target_id,
        collector_id="collector-1",
        idempotency_key="request-1",
        now="2026-07-17T20:00:00Z",
    )
    return store.create_or_get(record)


def _azure_adapter(tmp_path: Path):
    store = SQLiteSideScanStateStore(tmp_path / "state.db")
    snapshots = FakeAzureCollection("snapshots")
    disks = FakeAzureCollection("disks")
    vms = FakeAzureVms()
    adapter = AzureManagedDiskLifecycleAdapter(
        snapshots_client=snapshots,
        disks_client=disks,
        virtual_machines_client=vms,
        execution=_record("azure", store),
        state_store=store,
        collector_resource_group="collectors",
        collector_vm_name="collector-1",
        max_wait_attempts=3,
        wait_interval_seconds=0,
        sleep=lambda _seconds: None,
    )
    return adapter, store, snapshots, disks, vms


def _gcp_adapter(tmp_path: Path):
    store = SQLiteSideScanStateStore(tmp_path / "state.db")
    snapshots = FakeGcpCollection("snapshots")
    disks = FakeGcpCollection("disks")
    instances = FakeGcpInstances()
    adapter = GcpPersistentDiskLifecycleAdapter(
        snapshots_client=snapshots,
        disks_client=disks,
        instances_client=instances,
        execution=_record("gcp", store),
        state_store=store,
        project_id="proj-1",
        collector_zone="us-central1-a",
        collector_instance="collector-1",
        max_wait_attempts=3,
        wait_interval_seconds=0,
        sleep=lambda _seconds: None,
    )
    return adapter, store, snapshots, disks, instances


def test_azure_create_is_owned_bounded_and_idempotent(tmp_path: Path) -> None:
    adapter, _store, snapshots, _disks, _vms = _azure_adapter(tmp_path)
    target = _target("azure")

    first = adapter.create_snapshot(target)
    second = adapter.create_snapshot(target)

    assert first == second
    assert len(snapshots.create_calls) == 1
    tags = snapshots.create_calls[0][2]["tags"]
    assert tags == adapter.execution.cleanup_ownership.required_tags()
    assert len(adapter.execution.resources) == 1


def test_azure_permission_denial_persists_denied_not_clean(tmp_path: Path) -> None:
    adapter, store, snapshots, _disks, _vms = _azure_adapter(tmp_path)
    snapshots.create_error = FakeSdkError("authorization token=secret", 403)

    with pytest.raises(SideScanPermissionDeniedError):
        adapter.create_snapshot(_target("azure"))

    persisted = store.get(tenant_id="tenant-a", execution_id=adapter.execution.execution_id)
    assert persisted is not None
    assert persisted.status is ExecutionStatus.DENIED
    assert persisted.to_evidence_dict()["disposition"] == "unevaluable"
    assert "token=secret" not in repr(persisted.to_dict())


def test_azure_full_lifecycle_detaches_and_deletes_owned_resources(tmp_path: Path) -> None:
    adapter, _store, snapshots, disks, vms = _azure_adapter(tmp_path)
    target = _target("azure")
    snapshot_id = adapter.create_snapshot(target)
    disk_id = adapter.create_scan_disk(target, snapshot_id)
    device = adapter.attach_scan_disk(target, disk_id, "collector-1")
    adapter.mark_scan_complete()

    complete = adapter.cleanup(target, "collector-1")

    assert device == "/dev/disk/azure/scsi1/lun63"
    assert vms.data_disks == []
    assert snapshots.resources == {}
    assert disks.resources == {}
    assert complete.cleanup_status is CleanupStatus.COMPLETE
    assert complete.cleanup_candidates() == ()


def test_gcp_wait_timeout_is_bounded_and_persisted_failed(tmp_path: Path) -> None:
    adapter, store, snapshots, _disks, _instances = _gcp_adapter(tmp_path)
    snapshots.done_after = 99

    with pytest.raises(SideScanLifecycleTimeoutError):
        adapter.create_snapshot(_target("gcp"))

    operation = adapter.last_operation
    assert operation is not None and operation.done_calls == 3
    persisted = store.get(tenant_id="tenant-a", execution_id=adapter.execution.execution_id)
    assert persisted is not None
    assert persisted.status is ExecutionStatus.FAILED
    assert persisted.cleanup_status is CleanupStatus.PENDING
    assert persisted.failure_code == "operation_timeout"
    assert snapshots.resources, "the provider operation may complete after the worker times out"
    swept = adapter.sweep_orphans(active_execution_ids=set())
    assert len(swept) == 1
    assert snapshots.resources == {}


def test_cleanup_restarts_after_delete_failure_without_leaking_other_scope(tmp_path: Path) -> None:
    adapter, store, snapshots, disks, instances = _gcp_adapter(tmp_path)
    target = _target("gcp")
    snapshot_id = adapter.create_snapshot(target)
    disk_id = adapter.create_scan_disk(target, snapshot_id)
    adapter.attach_scan_disk(target, disk_id, "collector-1")
    adapter.mark_scan_complete(package_count=4, vulnerability_count=1)
    disk_name = disk_id.rsplit("/", 1)[-1]
    disks.delete_failures.add(disk_name)

    partial = adapter.cleanup(target, "collector-1")
    assert partial.cleanup_status is CleanupStatus.PARTIAL
    assert partial.to_evidence_dict()["disposition"] == "partial"
    assert not instances.disks
    assert not snapshots.resources
    assert any(resource.status is TemporaryResourceStatus.CLEANUP_FAILED for resource in partial.resources)

    disks.delete_failures.clear()
    restarted = GcpPersistentDiskLifecycleAdapter(
        snapshots_client=snapshots,
        disks_client=disks,
        instances_client=instances,
        execution=store.get(tenant_id="tenant-a", execution_id=partial.execution_id),
        state_store=store,
        project_id="proj-1",
        collector_zone="us-central1-a",
        collector_instance="collector-1",
        max_wait_attempts=3,
        wait_interval_seconds=0,
        sleep=lambda _seconds: None,
    )
    complete = restarted.cleanup(target, "collector-1")

    assert complete.cleanup_status is CleanupStatus.COMPLETE
    assert complete.to_evidence_dict()["disposition"] == "complete"
    assert not complete.cleanup_candidates()


def test_adapter_rejects_cross_account_target_before_sdk_call(tmp_path: Path) -> None:
    adapter, _store, snapshots, _disks, _vms = _azure_adapter(tmp_path)
    target = _target("azure")
    wrong = CloudSideScanTarget(**{**target.__dict__, "account_id": "sub-other"})

    with pytest.raises(ValueError, match="execution scope"):
        adapter.create_snapshot(wrong)

    assert snapshots.create_calls == []


def test_orphan_sweep_deletes_only_matching_tenant_scope(tmp_path: Path) -> None:
    adapter, _store, snapshots, disks, _vms = _azure_adapter(tmp_path)
    owned = adapter.execution.cleanup_ownership.required_tags()
    foreign = {**owned, "agent-bom-sidescan-scope": "0" * 24}
    snapshots.resources["workloads/owned-snap"] = SimpleNamespace(
        id="/subscriptions/sub-1/resourceGroups/workloads/providers/Microsoft.Compute/snapshots/owned-snap",
        name="owned-snap",
        tags=owned,
    )
    snapshots.resources["workloads/foreign-snap"] = SimpleNamespace(
        id="/subscriptions/sub-1/resourceGroups/workloads/providers/Microsoft.Compute/snapshots/foreign-snap",
        name="foreign-snap",
        tags=foreign,
    )
    disks.resources["workloads/owned-disk"] = SimpleNamespace(
        id="/subscriptions/sub-1/resourceGroups/workloads/providers/Microsoft.Compute/disks/owned-disk",
        name="owned-disk",
        tags=owned,
    )

    swept = adapter.sweep_orphans(active_execution_ids=set())

    assert set(swept) == {"owned-snap", "owned-disk"}
    assert "workloads/foreign-snap" in snapshots.resources


def test_gcp_orphan_sweep_deletes_only_matching_project_scope(tmp_path: Path) -> None:
    adapter, _store, snapshots, disks, _instances = _gcp_adapter(tmp_path)
    owned = adapter.execution.cleanup_ownership.required_tags()
    foreign = {**owned, "agent-bom-sidescan-scope": "0" * 24}
    snapshots.resources["owned-snap"] = {
        "name": "owned-snap",
        "self_link": "https://compute.googleapis.com/compute/v1/projects/proj-1/global/snapshots/owned-snap",
        "labels": owned,
    }
    snapshots.resources["foreign-snap"] = {
        "name": "foreign-snap",
        "self_link": "https://compute.googleapis.com/compute/v1/projects/proj-1/global/snapshots/foreign-snap",
        "labels": foreign,
    }
    disks.resources["owned-disk"] = {
        "name": "owned-disk",
        "self_link": "https://compute.googleapis.com/compute/v1/projects/proj-1/zones/us-central1-a/disks/owned-disk",
        "labels": owned,
    }

    swept = adapter.sweep_orphans(active_execution_ids=set())

    assert set(swept) == {"owned-snap", "owned-disk"}
    assert "foreign-snap" in snapshots.resources


@pytest.mark.asyncio
async def test_runner_persists_scan_evidence_and_guaranteed_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, store, _snapshots, _disks, _instances = _gcp_adapter(tmp_path)
    mount_path = tmp_path / "mount"
    mount_path.mkdir()
    mount = FakeMount(mount_path)
    monkeypatch.setenv("AGENT_BOM_SIDESCAN", "1")

    async def _no_cves(_packages: object) -> int:
        return 0

    monkeypatch.setattr("agent_bom.cloud.side_scan_targets._scan_packages", _no_cves)
    results = await run_cloud_side_scan_targets(
        [_target("gcp")],
        lifecycles={"gcp": adapter},
        collector_ids={"gcp": "collector-1"},
        mount_controller=mount,
        scan_secrets_enabled=False,
    )

    persisted = store.get(tenant_id="tenant-a", execution_id=adapter.execution.execution_id)
    assert results[0].cleaned_up is True
    assert mount.unmounted == [mount_path]
    assert persisted is not None
    assert persisted.status is ExecutionStatus.SCAN_COMPLETE
    assert persisted.cleanup_status is CleanupStatus.COMPLETE
    assert persisted.to_evidence_dict()["disposition"] == "complete"
