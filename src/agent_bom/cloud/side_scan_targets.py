"""Provider-neutral agentless workload side-scan targets and runner.

Inventory projection is metadata-only and safe in normal read-only scans. The
separate runner executes snapshot lifecycle actions only after the operator
opts in and supplies provider adapters, collector configuration, and scoped
mutation credentials.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol, cast

from agent_bom.filesystem import scan_disk_path_native
from agent_bom.models import Package
from agent_bom.secret_scanner import scan_secrets
from agent_bom.security import sanitize_text

from .side_scan import (
    CollectorMountController,
    MountController,
    SideScanConfigError,
    SideScanDisabledError,
    SideScanDiskFinding,
    SideScanSecret,
    is_sidescan_enabled,
    scan_workload_disk_findings,
)
from .side_scan_lifecycle import SideScanProvider

# Type of the pluggable SDK-client factory: given a provider (plus subscription /
# project id and optional region) it returns the already-authenticated provider
# SDK clients the concrete adapter needs. The default builds them from the
# provider's standard credential chain; tests inject fakes.
ProviderClientFactory = Callable[..., dict[str, Any]]

# Default on-disk lifecycle state store for CLI-driven cross-cloud side-scans,
# matching the repo-wide ``~/.agent-bom`` convention.
DEFAULT_SIDE_SCAN_STATE_DB = Path.home() / ".agent-bom" / "side_scan_state.db"

# Env override so every surface (CLI, API, MCP, scheduler) reads and writes the
# SAME durable lifecycle store when SQLite is selected.
SIDE_SCAN_STATE_DB_ENV = "AGENT_BOM_SIDE_SCAN_STATE_DB"


def side_scan_state_db_path() -> Path:
    """Resolve the shared side-scan lifecycle store path (env override or default).

    Keeping every surface on one resolver is what makes CLI/API/MCP execution
    status consistent for the SQLite tier. Multi-replica control planes select
    the shared Postgres backend through ``get_side_scan_state_store`` instead.
    """
    raw = os.environ.get(SIDE_SCAN_STATE_DB_ENV)
    if raw and raw.strip():
        return Path(raw.strip()).expanduser()
    return DEFAULT_SIDE_SCAN_STATE_DB


CloudSideScanProvider = SideScanProvider


@dataclass(frozen=True)
class CloudSideScanTarget:
    """A disk-like workload asset that can be scanned by an opt-in side-scan."""

    provider: CloudSideScanProvider
    target_type: str
    target_id: str
    name: str
    account_id: str
    location: str
    size_gb: int | None
    encryption: str
    status: str = "eligible"
    execution: str = "not_started"
    requires_snapshot_role: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "name": self.name,
            "account_id": self.account_id,
            "location": self.location,
            "size_gb": self.size_gb,
            "encryption": self.encryption,
            "status": self.status,
            "execution": self.execution,
            "requires_snapshot_role": self.requires_snapshot_role,
        }


@dataclass
class CloudSideScanExecutionResult:
    """Metadata-only result returned by the fixture-tested adapter runner.

    Azure/GCP injected-SDK adapters live in :mod:`side_scan_provider_adapters`;
    durable execution/evidence state belongs to :mod:`side_scan_lifecycle`.
    """

    provider: CloudSideScanProvider
    target_type: str
    target_id: str
    account_id: str
    location: str
    execution_id: str = ""
    execution_status: str = ""
    cleanup_status: str = ""
    snapshot_id: str | None = None
    scan_disk_id: str | None = None
    packages: list[Package] = field(default_factory=list)
    secrets: list[SideScanSecret] = field(default_factory=list)
    config_findings: list[SideScanDiskFinding] = field(default_factory=list)
    ioc_findings: list[SideScanDiskFinding] = field(default_factory=list)
    vulnerability_count: int = 0
    warnings: list[str] = field(default_factory=list)
    cleaned_up: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "account_id": self.account_id,
            "location": self.location,
            "execution_id": self.execution_id,
            "execution_status": self.execution_status,
            "cleanup_status": self.cleanup_status,
            "snapshot_id": self.snapshot_id,
            "scan_disk_id": self.scan_disk_id,
            "package_count": len(self.packages),
            "vulnerability_count": self.vulnerability_count,
            "secret_count": len(self.secrets),
            "config_finding_count": len(self.config_findings),
            "ioc_finding_count": len(self.ioc_findings),
            "secrets": [secret.to_dict() for secret in self.secrets],
            "config_findings": [finding.to_dict() for finding in self.config_findings],
            "ioc_findings": [finding.to_dict() for finding in self.ioc_findings],
            "warnings": list(self.warnings),
            "cleaned_up": self.cleaned_up,
        }


class CloudSideScanLifecycle(Protocol):
    """Provider lifecycle boundary for snapshot-backed side-scan execution."""

    def create_snapshot(self, target: CloudSideScanTarget) -> str:
        """Create a provider snapshot for *target* and return the snapshot id."""
        ...

    def create_scan_disk(self, target: CloudSideScanTarget, snapshot_id: str) -> str:
        """Create a temporary scan disk from *snapshot_id*."""
        ...

    def attach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> str:
        """Attach the temp disk to a collector and return the local device path."""
        ...

    def detach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> None:
        """Detach the temp scan disk from the collector."""
        ...

    def delete_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str) -> None:
        """Delete the temporary scan disk."""
        ...

    def delete_snapshot(self, target: CloudSideScanTarget, snapshot_id: str) -> None:
        """Delete the snapshot created for the side-scan."""
        ...


def _target_from_dict(raw: dict[str, Any]) -> CloudSideScanTarget:
    provider = str(raw.get("provider") or "").strip().lower()
    if provider not in {"aws", "azure", "gcp"}:
        raise SideScanConfigError(f"Unsupported side-scan provider: {provider or 'missing'}")
    target_id = str(raw.get("target_id") or "").strip()
    if not target_id:
        raise SideScanConfigError("side-scan target is missing target_id")
    return CloudSideScanTarget(
        provider=cast(CloudSideScanProvider, provider),
        target_type=str(raw.get("target_type") or "disk"),
        target_id=target_id,
        name=str(raw.get("name") or target_id),
        account_id=str(raw.get("account_id") or ""),
        location=str(raw.get("location") or ""),
        size_gb=raw.get("size_gb") if isinstance(raw.get("size_gb"), int) else None,
        encryption=str(raw.get("encryption") or "unknown"),
        status=str(raw.get("status") or "eligible"),
        execution=str(raw.get("execution") or "not_started"),
        requires_snapshot_role=bool(raw.get("requires_snapshot_role", True)),
    )


def _redacted_secret_findings(mount_point: Path) -> list[SideScanSecret]:
    try:
        scan_result = scan_secrets(mount_point)
    except Exception:
        return []
    return [
        SideScanSecret(
            secret_type=finding.secret_type,
            file_path=finding.file_path,
            line_number=finding.line_number,
            severity=finding.severity,
            category=finding.category,
        )
        for finding in scan_result.findings
    ]


async def _scan_packages(packages: list[Package]) -> int:
    if not packages:
        return 0
    from agent_bom.scanners import scan_packages

    return await scan_packages(packages)


async def run_cloud_side_scan_targets(
    targets: list[dict[str, Any] | CloudSideScanTarget],
    *,
    lifecycles: dict[CloudSideScanProvider, CloudSideScanLifecycle],
    collector_ids: dict[CloudSideScanProvider, str],
    mount_controller: MountController,
    scan_secrets_enabled: bool = True,
    max_targets: int = 10,
) -> list[CloudSideScanExecutionResult]:
    """Run Azure/GCP snapshot side-scans through caller-supplied adapters.

    The runner is opt-in, bounded, and metadata-only. Provider SDK calls stay
    behind ``CloudSideScanLifecycle``. Concrete Azure Managed Disk and GCP
    Persistent Disk adapters accept injected SDK clients; credentials,
    scheduler/CLI wiring, and live cloud proof are deliberately separate.
    """

    if not is_sidescan_enabled():
        raise SideScanDisabledError(
            "Disk side-scan is opt-in and currently OFF. Set AGENT_BOM_SIDESCAN=1 and provide a scoped snapshot role."
        )
    if max_targets < 1:
        raise SideScanConfigError("max_targets must be at least 1")
    coerced = [_target_from_dict(target) if isinstance(target, dict) else target for target in targets]
    results: list[CloudSideScanExecutionResult] = []
    for target in coerced[:max_targets]:
        if target.provider == "aws":
            raise SideScanConfigError("Use run_side_scan for AWS EBS side-scans")
        lifecycle = lifecycles.get(target.provider)
        collector_id = collector_ids.get(target.provider, "").strip()
        if lifecycle is None or not collector_id:
            raise SideScanConfigError(f"{target.provider} side-scan requires a lifecycle adapter and collector id")
        result = CloudSideScanExecutionResult(
            provider=target.provider,
            target_type=target.target_type,
            target_id=target.target_id,
            account_id=target.account_id,
            location=target.location,
        )
        persisted_execution = getattr(lifecycle, "execution", None)
        if persisted_execution is not None:
            result.execution_id = str(getattr(persisted_execution, "execution_id", ""))
            result.execution_status = str(getattr(getattr(persisted_execution, "status", None), "value", ""))
            result.cleanup_status = str(getattr(getattr(persisted_execution, "cleanup_status", None), "value", ""))
        mount_point: Path | None = None
        scan_disk_id = ""
        try:
            result.snapshot_id = lifecycle.create_snapshot(target)
            scan_disk_id = lifecycle.create_scan_disk(target, result.snapshot_id)
            result.scan_disk_id = scan_disk_id
            device = lifecycle.attach_scan_disk(target, scan_disk_id, collector_id)
            mount_point = mount_controller.attach_and_mount(scan_disk_id, device)
            result.packages = scan_disk_path_native(mount_point)
            result.vulnerability_count = await _scan_packages(result.packages)
            result.config_findings, result.ioc_findings = scan_workload_disk_findings(mount_point)
            if scan_secrets_enabled:
                result.secrets = _redacted_secret_findings(mount_point)
            mark_complete = getattr(lifecycle, "mark_scan_complete", None)
            if callable(mark_complete):
                mark_complete(
                    package_count=len(result.packages),
                    vulnerability_count=result.vulnerability_count,
                    secret_count=len(result.secrets),
                    config_finding_count=len(result.config_findings),
                    ioc_finding_count=len(result.ioc_findings),
                )
        except Exception:
            mark_failed = getattr(lifecycle, "mark_scan_failed", None)
            if callable(mark_failed):
                mark_failed(failure_code="scan_failed")
            raise
        finally:
            if mount_point is not None:
                try:
                    mount_controller.unmount(mount_point)
                except Exception as exc:  # noqa: BLE001
                    result.warnings.append(f"unmount failed: {sanitize_text(exc)}")
            persisted_cleanup = getattr(lifecycle, "cleanup", None)
            if callable(persisted_cleanup):
                try:
                    execution = persisted_cleanup(target, collector_id)
                    result.execution_id = str(getattr(execution, "execution_id", result.execution_id))
                    result.execution_status = str(getattr(getattr(execution, "status", None), "value", result.execution_status))
                    result.cleanup_status = str(getattr(getattr(execution, "cleanup_status", None), "value", result.cleanup_status))
                    result.warnings.extend(str(code) for code in getattr(execution, "warning_codes", ()) if code)
                    result.cleaned_up = getattr(getattr(execution, "cleanup_status", None), "value", "") == "complete"
                except Exception as exc:  # noqa: BLE001
                    result.warnings.append(f"persisted cleanup failed: {sanitize_text(exc)}")
            else:
                if scan_disk_id:
                    try:
                        lifecycle.detach_scan_disk(target, scan_disk_id, collector_id)
                    except Exception as exc:  # noqa: BLE001
                        result.warnings.append(f"detach disk failed: {sanitize_text(exc)}")
                    try:
                        lifecycle.delete_scan_disk(target, scan_disk_id)
                    except Exception as exc:  # noqa: BLE001
                        result.warnings.append(f"delete disk failed: {sanitize_text(exc)}")
                if result.snapshot_id:
                    try:
                        lifecycle.delete_snapshot(target, result.snapshot_id)
                    except Exception as exc:  # noqa: BLE001
                        result.warnings.append(f"delete snapshot failed: {sanitize_text(exc)}")
                result.cleaned_up = not result.warnings
                result.cleanup_status = "complete" if result.cleaned_up else "partial"
            if result.warnings:
                result.cleaned_up = False
        results.append(result)
    return results


def _default_provider_clients(provider: str, *, account_id: str, region: str | None) -> dict[str, Any]:
    """Build authenticated Azure/GCP compute SDK clients via the default credential chain.

    Honest boundary: the executors are shipped and wired, but they never embed
    credentials. When the provider extra is not installed, or ambient read-only
    credentials cannot be resolved, this raises :class:`SideScanConfigError` with
    an actionable message — it never proceeds with a half-authenticated client
    and it never reads as a clean scan.
    """
    if provider == "azure":
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.compute import ComputeManagementClient
        except ImportError as exc:
            raise SideScanConfigError(
                "Azure Managed Disk side-scan requires the azure extra. Install with: pip install 'agent-bom[azure]'"
            ) from exc
        try:
            credential = DefaultAzureCredential()
            client = ComputeManagementClient(credential, subscription_id=account_id)
        except Exception as exc:  # noqa: BLE001 - sanitized, actionable, no secret leakage
            detail = sanitize_text(exc)
            raise SideScanConfigError(
                f"Azure Managed Disk side-scan could not resolve scoped lifecycle credentials for the collector subscription: {detail}"
            ) from exc
        return {
            "snapshots_client": client.snapshots,
            "disks_client": client.disks,
            "virtual_machines_client": client.virtual_machines,
        }
    if provider == "gcp":
        try:
            from google.cloud import compute_v1
        except ImportError as exc:
            raise SideScanConfigError(
                "GCP Persistent Disk side-scan requires the gcp extra. Install with: pip install 'agent-bom[gcp]'"
            ) from exc
        try:
            return {
                "snapshots_client": compute_v1.SnapshotsClient(),
                "disks_client": compute_v1.DisksClient(),
                "instances_client": compute_v1.InstancesClient(),
            }
        except Exception as exc:  # noqa: BLE001 - sanitized, actionable, no secret leakage
            raise SideScanConfigError(
                f"GCP Persistent Disk side-scan could not resolve scoped lifecycle credentials: {sanitize_text(exc)}"
            ) from exc
    raise SideScanConfigError(f"cross-cloud side-scan supports only azure|gcp, not {provider!r}")


async def run_provider_side_scan(
    *,
    provider: CloudSideScanProvider,
    target_id: str,
    account_id: str,
    location: str,
    collector_id: str,
    tenant_id: str,
    idempotency_key: str | None = None,
    state_db_path: str | Path | None = None,
    collector_resource_group: str | None = None,
    collector_lun: int = 63,
    region: str | None = None,
    scan_secrets_enabled: bool = True,
    client_factory: ProviderClientFactory | None = None,
    mount_controller: MountController | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[CloudSideScanExecutionResult]:
    """Run one Azure/GCP snapshot side-scan end to end from the CLI/scheduler.

    This is the shipped Azure Managed Disk + GCP Persistent Disk executor: it
    builds the durable lifecycle record, constructs the concrete injected-SDK
    adapter, and drives :func:`run_cloud_side_scan_targets`, which guarantees
    teardown of every owned temporary resource on success *and* failure. AWS EBS
    keeps its own entry point (:func:`agent_bom.cloud.side_scan.run_side_scan`).

    Credentials are never embedded; ``client_factory`` resolves them from the
    provider's default chain (tests inject fakes). ``credentialed_smoke`` in the
    capability registry stays ``False`` until a real live-cloud run is proven.
    """
    if provider not in {"azure", "gcp"}:
        raise SideScanConfigError("run_provider_side_scan handles only azure|gcp; use run_side_scan for AWS EBS")
    if not is_sidescan_enabled():
        raise SideScanDisabledError(
            "Disk side-scan is opt-in and currently OFF. Set AGENT_BOM_SIDESCAN=1 and provide a scoped snapshot role "
            "plus an in-account collector instance."
        )

    required = (
        ("--volume-id (target disk id)", target_id),
        ("--account-id (subscription/project)", account_id),
        ("--availability-zone (disk location/zone)", location),
        ("--collector-instance-id (in-account collector)", collector_id),
    )
    missing = [label for label, value in required if not str(value).strip()]
    if missing:
        raise SideScanConfigError(f"{provider} side-scan requires: {', '.join(missing)}")
    if provider == "azure" and not str(collector_resource_group or "").strip():
        raise SideScanConfigError("Azure Managed Disk side-scan requires --collector-resource-group for the in-account collector VM")

    from .side_scan_lifecycle import get_side_scan_state_store, new_side_scan_execution
    from .side_scan_provider_adapters import (
        AzureManagedDiskLifecycleAdapter,
        GcpPersistentDiskLifecycleAdapter,
    )

    target_id = target_id.strip()
    account_id = account_id.strip()
    location = location.strip()
    collector_id = collector_id.strip()

    target = CloudSideScanTarget(
        provider=provider,
        target_type="managed_disk" if provider == "azure" else "persistent_disk",
        target_id=target_id,
        name=target_id.rstrip("/").rsplit("/", 1)[-1] or target_id,
        account_id=account_id,
        location=location,
        size_gb=None,
        encryption="unknown",
    )

    store = get_side_scan_state_store(state_db_path=state_db_path)
    execution = store.create_or_get(
        new_side_scan_execution(
            tenant_id=tenant_id,
            provider=provider,
            account_id=account_id,
            target_id=target_id,
            collector_id=collector_id,
            idempotency_key=idempotency_key or uuid.uuid4().hex,
        )
    )

    factory = client_factory or _default_provider_clients
    clients = factory(provider, account_id=account_id, region=region)

    lifecycle: CloudSideScanLifecycle
    if provider == "azure":
        lifecycle = AzureManagedDiskLifecycleAdapter(
            snapshots_client=clients["snapshots_client"],
            disks_client=clients["disks_client"],
            virtual_machines_client=clients["virtual_machines_client"],
            execution=execution,
            state_store=store,
            collector_resource_group=str(collector_resource_group),
            collector_vm_name=collector_id,
            collector_lun=collector_lun,
            sleep=sleep,
        )
    else:
        lifecycle = GcpPersistentDiskLifecycleAdapter(
            snapshots_client=clients["snapshots_client"],
            disks_client=clients["disks_client"],
            instances_client=clients["instances_client"],
            execution=execution,
            state_store=store,
            project_id=account_id,
            collector_zone=location,
            collector_instance=collector_id,
            sleep=sleep,
        )

    return await run_cloud_side_scan_targets(
        [target],
        lifecycles={provider: lifecycle},
        collector_ids={provider: collector_id},
        mount_controller=mount_controller or CollectorMountController(),
        scan_secrets_enabled=scan_secrets_enabled,
        max_targets=1,
    )


def azure_managed_disk_targets(disks: list[dict[str, Any]], *, subscription_id: str) -> list[dict[str, Any]]:
    """Project Azure Managed Disks into side-scan target records."""

    targets: list[dict[str, Any]] = []
    for disk in disks:
        target_id = str(disk.get("id") or disk.get("name") or "").strip()
        name = str(disk.get("name") or target_id).strip()
        if not target_id or not name:
            continue
        size = disk.get("disk_size_gb")
        targets.append(
            CloudSideScanTarget(
                provider="azure",
                target_type="managed_disk",
                target_id=target_id,
                name=name,
                account_id=subscription_id,
                location=str(disk.get("location") or ""),
                size_gb=size if isinstance(size, int) else None,
                encryption=str(disk.get("encryption_type") or "unknown"),
            ).to_dict()
        )
    return targets


def gcp_persistent_disk_targets(disks: list[dict[str, Any]], *, project_id: str) -> list[dict[str, Any]]:
    """Project GCP Persistent Disks into side-scan target records."""

    targets: list[dict[str, Any]] = []
    for disk in disks:
        target_id = str(disk.get("id") or disk.get("name") or "").strip()
        name = str(disk.get("name") or target_id).strip()
        if not target_id or not name:
            continue
        size = disk.get("size_gb")
        encryption = "customer-managed" if disk.get("encrypted") else "provider-managed-or-unknown"
        targets.append(
            CloudSideScanTarget(
                provider="gcp",
                target_type="persistent_disk",
                target_id=target_id,
                name=name,
                account_id=project_id,
                location=str(disk.get("location") or ""),
                size_gb=size if isinstance(size, int) else None,
                encryption=encryption,
            ).to_dict()
        )
    return targets
