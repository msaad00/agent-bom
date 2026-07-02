"""Provider-neutral agentless workload side-scan target metadata.

This module does not execute snapshot lifecycle actions. It projects already
discovered disk inventory into a shared contract that the side-scan executor can
consume later. The output is metadata-only and safe to include in normal
read-only inventory scans.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from agent_bom.filesystem import scan_disk_path_native
from agent_bom.models import Package
from agent_bom.secret_scanner import scan_secrets
from agent_bom.security import sanitize_text

from .side_scan import (
    MountController,
    SideScanConfigError,
    SideScanDisabledError,
    SideScanDiskFinding,
    SideScanSecret,
    is_sidescan_enabled,
    scan_workload_disk_findings,
)

CloudSideScanProvider = Literal["aws", "azure", "gcp"]


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
    """Metadata-only side-scan result for Azure/GCP disk targets."""

    provider: CloudSideScanProvider
    target_type: str
    target_id: str
    account_id: str
    location: str
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
    """Run Azure/GCP snapshot side-scans through provider lifecycle adapters.

    The runner is opt-in, bounded, and metadata-only. Provider SDK calls stay
    behind ``CloudSideScanLifecycle`` so production integrations can wrap Azure
    Managed Disk or GCP Persistent Disk APIs while unit tests prove lifecycle and
    cleanup behavior without real cloud credentials.
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
        finally:
            if mount_point is not None:
                try:
                    mount_controller.unmount(mount_point)
                except Exception as exc:  # noqa: BLE001
                    result.warnings.append(f"unmount failed: {sanitize_text(exc)}")
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
        results.append(result)
    return results


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
