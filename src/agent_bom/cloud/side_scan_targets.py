"""Provider-neutral agentless workload side-scan target metadata.

This module does not execute snapshot lifecycle actions. It projects already
discovered disk inventory into a shared contract that the side-scan executor can
consume later. The output is metadata-only and safe to include in normal
read-only inventory scans.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

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
