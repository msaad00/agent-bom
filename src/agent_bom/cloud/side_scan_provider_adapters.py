"""Opt-in Azure Managed Disk and GCP Persistent Disk lifecycle adapters.

The adapters accept already-authenticated provider SDK clients.  They never
load credentials, transfer block bytes, or mount filesystems themselves.  All
temporary resources use deterministic names and the ownership tags from the v1
side-scan execution contract; durable state is updated after each mutation so
cleanup can resume after a worker restart.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from agent_bom.security import sanitize_text

from .side_scan_lifecycle import (
    CleanupStatus,
    ExecutionStatus,
    SideScanExecutionRecord,
    SideScanTemporaryResource,
    SQLiteSideScanStateStore,
    TemporaryResourceStatus,
)
from .side_scan_targets import CloudSideScanTarget


class SideScanPermissionDeniedError(RuntimeError):
    """Provider denied a scoped lifecycle operation."""


class SideScanLifecycleTimeoutError(RuntimeError):
    """A provider operation did not finish inside the configured poll bound."""


class SideScanOwnershipError(RuntimeError):
    """A deterministic provider resource exists but is not owned by this run."""


@dataclass(frozen=True)
class _WaitPolicy:
    max_attempts: int
    interval_seconds: float
    sleep: Callable[[float], None]

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_wait_attempts must be at least 1")
        if self.interval_seconds < 0:
            raise ValueError("wait_interval_seconds cannot be negative")


class _PersistedLifecycleAdapter:
    provider: str

    def __init__(
        self,
        *,
        execution: SideScanExecutionRecord | None,
        state_store: SQLiteSideScanStateStore,
        max_wait_attempts: int,
        wait_interval_seconds: float,
        sleep: Callable[[float], None],
    ) -> None:
        if execution is None:
            raise ValueError("persisted side-scan execution is required")
        if execution.provider != self.provider:
            raise ValueError("side-scan execution provider does not match adapter")
        self.execution = execution
        self._store = state_store
        self._wait_policy = _WaitPolicy(max_wait_attempts, wait_interval_seconds, sleep)
        self.last_operation: Any | None = None

    def _validate_target(self, target: CloudSideScanTarget) -> None:
        if (
            target.provider != self.execution.provider
            or target.account_id != self.execution.account_id
            or target.target_id != self.execution.target_id
        ):
            raise ValueError("side-scan target is outside the persisted execution scope")

    def _save(self, record: SideScanExecutionRecord) -> None:
        if record == self.execution:
            return
        self._store.save(record, expected_version=self.execution.state_version)
        self.execution = record

    def _ensure_running(self, phase: str) -> None:
        if self.execution.status is ExecutionStatus.QUEUED:
            self._save(self.execution.transition(status=ExecutionStatus.RUNNING, phase=phase))
        elif self.execution.status is ExecutionStatus.RUNNING:
            self._save(self.execution.transition(phase=phase))
        else:
            raise ValueError(f"side-scan execution is not runnable: {self.execution.status.value}")

    def _register(self, kind: str, resource_id: str) -> None:
        resource = SideScanTemporaryResource(
            kind=kind,
            resource_id=resource_id,
            status=TemporaryResourceStatus.CREATED,
            ownership_tags=self.execution.cleanup_ownership.required_tags(),
        )
        self._save(self.execution.register_resource(resource))

    def _wait(self, operation: Any) -> Any:
        self.last_operation = operation
        done = getattr(operation, "done", None)
        result = getattr(operation, "result", None)
        if not callable(done) or not callable(result):
            raise TypeError("provider operation must expose done() and result()")
        for attempt in range(self._wait_policy.max_attempts):
            if done():
                return result()
            if attempt + 1 < self._wait_policy.max_attempts:
                self._wait_policy.sleep(self._wait_policy.interval_seconds)
        raise SideScanLifecycleTimeoutError("provider operation exceeded bounded wait")

    def _persist_failure(self, exc: Exception) -> None:
        denied = _is_denied(exc)
        cleanup = (
            CleanupStatus.PENDING
            if isinstance(exc, SideScanLifecycleTimeoutError) or self.execution.resources
            else CleanupStatus.COMPLETE
        )
        status = ExecutionStatus.DENIED if denied else ExecutionStatus.FAILED
        if denied:
            code = "permission_denied"
        elif isinstance(exc, SideScanLifecycleTimeoutError):
            code = "operation_timeout"
        else:
            code = "provider_operation_failed"
        self._save(
            self.execution.transition(
                status=status,
                phase="cleanup" if cleanup is CleanupStatus.PENDING else "finished",
                cleanup_status=cleanup,
                failure_code=code,
            )
        )

    def _raise_provider_error(self, exc: Exception) -> None:
        self._persist_failure(exc)
        if _is_denied(exc):
            raise SideScanPermissionDeniedError("provider denied the scoped side-scan lifecycle operation") from exc
        if isinstance(exc, SideScanLifecycleTimeoutError):
            raise exc
        raise RuntimeError("provider side-scan lifecycle operation failed") from exc

    def mark_scan_complete(
        self,
        *,
        package_count: int = 0,
        vulnerability_count: int = 0,
        secret_count: int = 0,
        config_finding_count: int = 0,
        ioc_finding_count: int = 0,
    ) -> SideScanExecutionRecord:
        """Persist metadata-only scan counts and queue mandatory cleanup."""
        self._save(
            self.execution.transition(
                status=ExecutionStatus.SCAN_COMPLETE,
                phase="cleanup",
                cleanup_status=CleanupStatus.PENDING,
                package_count=package_count,
                vulnerability_count=vulnerability_count,
                secret_count=secret_count,
                config_finding_count=config_finding_count,
                ioc_finding_count=ioc_finding_count,
            )
        )
        return self.execution

    def mark_scan_failed(self, *, failure_code: str = "scan_failed") -> SideScanExecutionRecord:
        """Persist a fail-closed scan outcome before mandatory cleanup."""
        if self.execution.status in {ExecutionStatus.QUEUED, ExecutionStatus.RUNNING}:
            self._save(
                self.execution.transition(
                    status=ExecutionStatus.FAILED,
                    phase="cleanup",
                    cleanup_status=CleanupStatus.PENDING,
                    failure_code=failure_code,
                )
            )
        return self.execution

    def cleanup(self, target: CloudSideScanTarget, collector_id: str) -> SideScanExecutionRecord:
        """Retry teardown from persisted resources; every step is idempotent."""
        self._validate_target(target)
        if self.execution.cleanup_status is CleanupStatus.COMPLETE:
            return self.execution
        self._save(self.execution.transition(phase="cleanup", cleanup_status=CleanupStatus.IN_PROGRESS))
        warning_codes = list(self.execution.warning_codes)
        order = {"attachment": 0, "scan_disk": 1, "snapshot": 2}
        resources = sorted(self.execution.cleanup_candidates(), key=lambda resource: order.get(resource.kind, 99))
        for resource in resources:
            try:
                if resource.kind == "attachment":
                    scan_disk_id = resource.resource_id.split("|", 1)[-1]
                    self.detach_scan_disk(target, scan_disk_id, collector_id)
                elif resource.kind == "scan_disk":
                    self.delete_scan_disk(target, resource.resource_id)
                elif resource.kind == "snapshot":
                    self.delete_snapshot(target, resource.resource_id)
                else:
                    raise ValueError(f"unknown temporary resource kind: {resource.kind}")
            except Exception as exc:  # noqa: BLE001 - cleanup continues and persists a safe code
                if _is_not_found(exc):
                    self._save(
                        self.execution.mark_resource_cleanup(
                            resource.resource_id,
                            status=TemporaryResourceStatus.DELETED,
                        )
                    )
                    continue
                code = f"cleanup_{resource.kind}_failed"
                if code not in warning_codes:
                    warning_codes.append(code)
                self._save(
                    self.execution.mark_resource_cleanup(
                        resource.resource_id,
                        status=TemporaryResourceStatus.CLEANUP_FAILED,
                    )
                )
                continue
            self._save(
                self.execution.mark_resource_cleanup(
                    resource.resource_id,
                    status=TemporaryResourceStatus.DELETED,
                )
            )
        if self.execution.cleanup_candidates():
            self._save(
                self.execution.transition(
                    cleanup_status=CleanupStatus.PARTIAL,
                    warning_codes=tuple(warning_codes),
                )
            )
        else:
            self._save(
                self.execution.transition(
                    phase="finished",
                    cleanup_status=CleanupStatus.COMPLETE,
                    warning_codes=tuple(warning_codes),
                )
            )
        return self.execution

    def detach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> None:
        raise NotImplementedError

    def delete_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str) -> None:
        raise NotImplementedError

    def delete_snapshot(self, target: CloudSideScanTarget, snapshot_id: str) -> None:
        raise NotImplementedError


class AzureManagedDiskLifecycleAdapter(_PersistedLifecycleAdapter):
    """Azure Compute SDK adapter for snapshot/temp-disk/collector lifecycle."""

    provider = "azure"

    def __init__(
        self,
        *,
        snapshots_client: Any,
        disks_client: Any,
        virtual_machines_client: Any,
        execution: SideScanExecutionRecord | None,
        state_store: SQLiteSideScanStateStore,
        collector_resource_group: str,
        collector_vm_name: str,
        collector_lun: int = 63,
        max_wait_attempts: int = 60,
        wait_interval_seconds: float = 5.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(
            execution=execution,
            state_store=state_store,
            max_wait_attempts=max_wait_attempts,
            wait_interval_seconds=wait_interval_seconds,
            sleep=sleep,
        )
        if not collector_resource_group.strip() or not collector_vm_name.strip():
            raise ValueError("Azure collector resource group and VM name are required")
        if collector_lun < 0 or collector_lun > 63:
            raise ValueError("Azure collector LUN must be between 0 and 63")
        self._snapshots = snapshots_client
        self._disks = disks_client
        self._vms = virtual_machines_client
        self._collector_resource_group = collector_resource_group
        self._collector_vm_name = collector_vm_name
        self._collector_lun = collector_lun

    def create_snapshot(self, target: CloudSideScanTarget) -> str:
        self._validate_target(target)
        self._ensure_running("snapshot")
        resource_group = _azure_resource_group(target.target_id)
        name = _resource_name(self.execution.cleanup_ownership.owner_id, "snapshot")
        try:
            existing = self._azure_get(self._snapshots, resource_group, name)
            if existing is not None:
                self._assert_owned(_tags(existing))
                resource_id = _resource_id(existing)
            else:
                operation = self._snapshots.begin_create_or_update(
                    resource_group,
                    name,
                    {
                        "location": target.location,
                        "tags": self.execution.cleanup_ownership.required_tags(),
                        "creation_data": {"create_option": "Copy", "source_resource_id": target.target_id},
                    },
                )
                resource_id = _resource_id(self._wait(operation))
            self._register("snapshot", resource_id)
            return resource_id
        except Exception as exc:  # noqa: BLE001
            self._raise_provider_error(exc)
            raise AssertionError("unreachable")

    def create_scan_disk(self, target: CloudSideScanTarget, snapshot_id: str) -> str:
        self._validate_target(target)
        self._ensure_running("temp_disk")
        resource_group = _azure_resource_group(target.target_id)
        name = _resource_name(self.execution.cleanup_ownership.owner_id, "disk")
        try:
            existing = self._azure_get(self._disks, resource_group, name)
            if existing is not None:
                self._assert_owned(_tags(existing))
                resource_id = _resource_id(existing)
            else:
                operation = self._disks.begin_create_or_update(
                    resource_group,
                    name,
                    {
                        "location": target.location,
                        "tags": self.execution.cleanup_ownership.required_tags(),
                        "creation_data": {"create_option": "Copy", "source_resource_id": snapshot_id},
                    },
                )
                resource_id = _resource_id(self._wait(operation))
            self._register("scan_disk", resource_id)
            return resource_id
        except Exception as exc:  # noqa: BLE001
            self._raise_provider_error(exc)
            raise AssertionError("unreachable")

    def attach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> str:
        self._validate_target(target)
        self._ensure_running("attached")
        if collector_id != self.execution.collector_id or collector_id != self._collector_vm_name:
            raise ValueError("collector is outside the persisted execution scope")
        try:
            vm = self._vms.get(self._collector_resource_group, self._collector_vm_name)
            current = [_azure_disk_dict(item) for item in getattr(getattr(vm, "storage_profile", None), "data_disks", []) or []]
            attached_ids = {str((item.get("managed_disk") or {}).get("id") or "") for item in current}
            if scan_disk_id not in attached_ids:
                if any(int(item.get("lun", -1)) == self._collector_lun for item in current):
                    raise ValueError("configured Azure collector LUN is already occupied")
                current.append(
                    {
                        "lun": self._collector_lun,
                        "name": _resource_name(self.execution.cleanup_ownership.owner_id, "disk"),
                        "create_option": "Attach",
                        "managed_disk": {"id": scan_disk_id},
                    }
                )
                self._wait(
                    self._vms.begin_update(
                        self._collector_resource_group,
                        self._collector_vm_name,
                        {"storage_profile": {"data_disks": current}},
                    )
                )
            self._register("attachment", f"{collector_id}|{scan_disk_id}")
            return f"/dev/disk/azure/scsi1/lun{self._collector_lun}"
        except Exception as exc:  # noqa: BLE001
            self._raise_provider_error(exc)
            raise AssertionError("unreachable")

    def detach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> None:
        self._validate_target(target)
        if collector_id != self.execution.collector_id:
            raise ValueError("collector is outside the persisted execution scope")
        vm = self._vms.get(self._collector_resource_group, self._collector_vm_name)
        current = [_azure_disk_dict(item) for item in getattr(getattr(vm, "storage_profile", None), "data_disks", []) or []]
        retained = [item for item in current if str((item.get("managed_disk") or {}).get("id") or "") != scan_disk_id]
        if len(retained) == len(current):
            return
        self._wait(
            self._vms.begin_update(
                self._collector_resource_group,
                self._collector_vm_name,
                {"storage_profile": {"data_disks": retained}},
            )
        )

    def delete_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str) -> None:
        resource_group, name = _azure_group_and_name(scan_disk_id)
        try:
            self._wait(self._disks.begin_delete(resource_group, name))
        except Exception as exc:
            if not _is_not_found(exc):
                raise

    def delete_snapshot(self, target: CloudSideScanTarget, snapshot_id: str) -> None:
        resource_group, name = _azure_group_and_name(snapshot_id)
        try:
            self._wait(self._snapshots.begin_delete(resource_group, name))
        except Exception as exc:
            if not _is_not_found(exc):
                raise

    def sweep_orphans(self, *, active_execution_ids: set[str]) -> list[str]:
        """Delete only resources in this tenant/account scope not marked active."""
        swept: list[str] = []
        scope = self.execution.cleanup_ownership.scope_hash
        for client, kind in ((self._disks, "disk"), (self._snapshots, "snapshot")):
            for resource in list(client.list()):
                tags = _tags(resource)
                if not _orphan_candidate(tags, scope=scope, active_execution_ids=active_execution_ids):
                    continue
                resource_id = _resource_id(resource)
                resource_group, name = _azure_group_and_name(resource_id)
                try:
                    if kind == "disk":
                        self.detach_scan_disk(_target_for_execution(self.execution), resource_id, self.execution.collector_id)
                    self._wait(client.begin_delete(resource_group, name))
                    swept.append(name)
                except Exception as exc:  # noqa: BLE001
                    if not _is_not_found(exc):
                        continue
        return swept

    @staticmethod
    def _azure_get(client: Any, resource_group: str, name: str) -> Any | None:
        try:
            return client.get(resource_group, name)
        except Exception as exc:
            if _is_not_found(exc):
                return None
            raise

    def _assert_owned(self, tags: Mapping[str, str]) -> None:
        if not self.execution.cleanup_ownership.owns(tags):
            raise SideScanOwnershipError("deterministic Azure resource name is not owned by this execution")


class GcpPersistentDiskLifecycleAdapter(_PersistedLifecycleAdapter):
    """Google Compute Engine SDK adapter for snapshot/temp-disk lifecycle."""

    provider = "gcp"

    def __init__(
        self,
        *,
        snapshots_client: Any,
        disks_client: Any,
        instances_client: Any,
        execution: SideScanExecutionRecord | None,
        state_store: SQLiteSideScanStateStore,
        project_id: str,
        collector_zone: str,
        collector_instance: str,
        max_wait_attempts: int = 60,
        wait_interval_seconds: float = 5.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(
            execution=execution,
            state_store=state_store,
            max_wait_attempts=max_wait_attempts,
            wait_interval_seconds=wait_interval_seconds,
            sleep=sleep,
        )
        if execution is not None and execution.account_id != project_id:
            raise ValueError("GCP project does not match persisted execution scope")
        if not project_id.strip() or not collector_zone.strip() or not collector_instance.strip():
            raise ValueError("GCP project, collector zone, and collector instance are required")
        self._snapshots = snapshots_client
        self._disks = disks_client
        self._instances = instances_client
        self._project = project_id
        self._collector_zone = collector_zone
        self._collector_instance = collector_instance
        self._device_name = _resource_name(self.execution.cleanup_ownership.owner_id, "disk")

    def create_snapshot(self, target: CloudSideScanTarget) -> str:
        self._validate_target(target)
        self._ensure_running("snapshot")
        name = _resource_name(self.execution.cleanup_ownership.owner_id, "snapshot")
        try:
            existing = self._gcp_get(self._snapshots, {"project": self._project, "snapshot": name})
            if existing is not None:
                self._assert_owned(_labels(existing))
                resource_id = _resource_id(existing)
            else:
                operation = self._snapshots.insert(
                    request={
                        "project": self._project,
                        "snapshot_resource": {
                            "name": name,
                            "source_disk": target.target_id,
                            "labels": self.execution.cleanup_ownership.required_tags(),
                        },
                    }
                )
                self._wait(operation)
                created = self._gcp_get(self._snapshots, {"project": self._project, "snapshot": name})
                if created is None:
                    raise RuntimeError("created GCP snapshot could not be read back")
                resource_id = _resource_id(created)
            self._register("snapshot", resource_id)
            return resource_id
        except Exception as exc:  # noqa: BLE001
            self._raise_provider_error(exc)
            raise AssertionError("unreachable")

    def create_scan_disk(self, target: CloudSideScanTarget, snapshot_id: str) -> str:
        self._validate_target(target)
        self._ensure_running("temp_disk")
        name = _resource_name(self.execution.cleanup_ownership.owner_id, "disk")
        try:
            existing = self._gcp_get(
                self._disks,
                {"project": self._project, "zone": target.location, "disk": name},
            )
            if existing is not None:
                self._assert_owned(_labels(existing))
                resource_id = _resource_id(existing)
            else:
                operation = self._disks.insert(
                    request={
                        "project": self._project,
                        "zone": target.location,
                        "disk_resource": {
                            "name": name,
                            "source_snapshot": snapshot_id,
                            "labels": self.execution.cleanup_ownership.required_tags(),
                        },
                    }
                )
                self._wait(operation)
                created = self._gcp_get(
                    self._disks,
                    {"project": self._project, "zone": target.location, "disk": name},
                )
                if created is None:
                    raise RuntimeError("created GCP disk could not be read back")
                resource_id = _resource_id(created)
            self._register("scan_disk", resource_id)
            return resource_id
        except Exception as exc:  # noqa: BLE001
            self._raise_provider_error(exc)
            raise AssertionError("unreachable")

    def attach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> str:
        self._validate_target(target)
        self._ensure_running("attached")
        if collector_id != self.execution.collector_id or collector_id != self._collector_instance:
            raise ValueError("collector is outside the persisted execution scope")
        try:
            self._wait(
                self._instances.attach_disk(
                    request={
                        "project": self._project,
                        "zone": self._collector_zone,
                        "instance": self._collector_instance,
                        "attached_disk_resource": {
                            "source": scan_disk_id,
                            "device_name": self._device_name,
                            "mode": "READ_ONLY",
                            "auto_delete": False,
                        },
                    }
                )
            )
            self._register("attachment", f"{collector_id}|{scan_disk_id}")
            return f"/dev/disk/by-id/google-{self._device_name}"
        except Exception as exc:  # noqa: BLE001
            if _is_conflict(exc):
                self._register("attachment", f"{collector_id}|{scan_disk_id}")
                return f"/dev/disk/by-id/google-{self._device_name}"
            self._raise_provider_error(exc)
            raise AssertionError("unreachable")

    def detach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> None:
        self._validate_target(target)
        if collector_id != self.execution.collector_id:
            raise ValueError("collector is outside the persisted execution scope")
        try:
            self._wait(
                self._instances.detach_disk(
                    request={
                        "project": self._project,
                        "zone": self._collector_zone,
                        "instance": self._collector_instance,
                        "device_name": self._device_name,
                    }
                )
            )
        except Exception as exc:
            if not _is_not_found(exc):
                raise

    def delete_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str) -> None:
        name = scan_disk_id.rsplit("/", 1)[-1]
        zone = _gcp_zone(scan_disk_id) or target.location
        try:
            self._wait(self._disks.delete(request={"project": self._project, "zone": zone, "disk": name}))
        except Exception as exc:
            if not _is_not_found(exc):
                raise

    def delete_snapshot(self, target: CloudSideScanTarget, snapshot_id: str) -> None:
        name = snapshot_id.rsplit("/", 1)[-1]
        try:
            self._wait(self._snapshots.delete(request={"project": self._project, "snapshot": name}))
        except Exception as exc:
            if not _is_not_found(exc):
                raise

    def sweep_orphans(self, *, active_execution_ids: set[str]) -> list[str]:
        """Delete only labels matching this tenant/project scope."""
        swept: list[str] = []
        scope = self.execution.cleanup_ownership.scope_hash
        resources: tuple[tuple[Any, str, dict[str, str]], ...] = (
            (self._disks, "disk", {"project": self._project, "zone": _gcp_zone(self.execution.target_id) or self._collector_zone}),
            (self._snapshots, "snapshot", {"project": self._project}),
        )
        target = _target_for_execution(self.execution)
        for client, kind, request in resources:
            for resource in list(client.list(request=request)):
                labels = _labels(resource)
                if not _orphan_candidate(labels, scope=scope, active_execution_ids=active_execution_ids):
                    continue
                resource_id = _resource_id(resource)
                name = resource_id.rsplit("/", 1)[-1]
                try:
                    if kind == "disk":
                        self.detach_scan_disk(target, resource_id, self.execution.collector_id)
                        self._wait(client.delete(request={**request, "disk": name}))
                    else:
                        self._wait(client.delete(request={**request, "snapshot": name}))
                    swept.append(name)
                except Exception as exc:  # noqa: BLE001
                    if not _is_not_found(exc):
                        continue
        return swept

    @staticmethod
    def _gcp_get(client: Any, request: dict[str, str]) -> Any | None:
        try:
            return client.get(request=request)
        except Exception as exc:
            if _is_not_found(exc):
                return None
            raise

    def _assert_owned(self, labels: Mapping[str, str]) -> None:
        if not self.execution.cleanup_ownership.owns(labels):
            raise SideScanOwnershipError("deterministic GCP resource name is not owned by this execution")


def _resource_name(owner_id: str, suffix: str) -> str:
    return f"abom-{owner_id}-{suffix}"[:63]


def _resource_id(resource: Any) -> str:
    if isinstance(resource, Mapping):
        value = resource.get("self_link") or resource.get("selfLink") or resource.get("id") or resource.get("name")
    else:
        value = getattr(resource, "id", None) or getattr(resource, "self_link", None) or getattr(resource, "name", None)
    result = str(value or "").strip()
    if not result:
        raise RuntimeError("provider operation returned no resource id")
    return result


def _tags(resource: Any) -> dict[str, str]:
    raw = resource.get("tags") if isinstance(resource, Mapping) else getattr(resource, "tags", None)
    return {str(key): str(value) for key, value in raw.items()} if isinstance(raw, Mapping) else {}


def _labels(resource: Any) -> dict[str, str]:
    raw = resource.get("labels") if isinstance(resource, Mapping) else getattr(resource, "labels", None)
    return {str(key): str(value) for key, value in raw.items()} if isinstance(raw, Mapping) else {}


def _azure_resource_group(resource_id: str) -> str:
    parts = [part for part in resource_id.split("/") if part]
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError) as exc:
        raise ValueError("Azure target id is missing a resource group") from exc


def _azure_group_and_name(resource_id: str) -> tuple[str, str]:
    return _azure_resource_group(resource_id), resource_id.rstrip("/").rsplit("/", 1)[-1]


def _azure_disk_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, Mapping):
        return dict(item)
    managed = getattr(item, "managed_disk", None)
    managed_id = managed.get("id") if isinstance(managed, Mapping) else getattr(managed, "id", None)
    return {
        "lun": getattr(item, "lun", None),
        "name": getattr(item, "name", ""),
        "create_option": getattr(item, "create_option", "Attach"),
        "managed_disk": {"id": str(managed_id or "")},
    }


def _gcp_zone(resource_id: str) -> str:
    parts = [part for part in resource_id.split("/") if part]
    try:
        return parts[parts.index("zones") + 1]
    except (ValueError, IndexError):
        return ""


def _target_for_execution(execution: SideScanExecutionRecord) -> CloudSideScanTarget:
    return CloudSideScanTarget(
        provider=execution.provider,
        target_type="managed_disk" if execution.provider == "azure" else "persistent_disk",
        target_id=execution.target_id,
        name=execution.target_id.rstrip("/").rsplit("/", 1)[-1],
        account_id=execution.account_id,
        location=_gcp_zone(execution.target_id),
        size_gb=None,
        encryption="unknown",
    )


def _orphan_candidate(tags: Mapping[str, str], *, scope: str, active_execution_ids: set[str]) -> bool:
    return (
        tags.get("agent-bom-sidescan") == "true"
        and tags.get("agent-bom-sidescan-scope") == scope
        and bool(tags.get("agent-bom-sidescan-owner"))
        and tags.get("agent-bom-sidescan-execution") not in active_execution_ids
    )


def _status_code(exc: Exception) -> int | None:
    raw = getattr(exc, "status_code", None)
    if isinstance(raw, int):
        return raw
    code = getattr(exc, "code", None)
    if callable(code):
        code = code()
    if isinstance(code, int):
        return code
    value = getattr(code, "value", None)
    return int(value) if isinstance(value, int) else None


def _is_denied(exc: Exception) -> bool:
    return _status_code(exc) in {401, 403}


def _is_not_found(exc: Exception) -> bool:
    return _status_code(exc) == 404


def _is_conflict(exc: Exception) -> bool:
    return _status_code(exc) in {409, 412}


def sanitized_provider_error(exc: Exception) -> str:
    """Expose a sanitized diagnostic for logs without changing state codes."""
    return sanitize_text(exc)
