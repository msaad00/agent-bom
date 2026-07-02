from __future__ import annotations

from agent_bom.cloud.side_scan_targets import azure_managed_disk_targets, gcp_persistent_disk_targets


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
