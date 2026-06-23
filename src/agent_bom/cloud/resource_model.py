"""Normalized, provider-agnostic cloud resource model.

Each provider's inventory historically emitted its own dict shape
(``storage_accounts`` / ``instances`` / ``security_groups`` for Azure, and
different keys for AWS/GCP). That makes the graph, CIS, and findings layers
re-learn every provider's vocabulary and blocks cross-cloud normalization.

:class:`CloudResource` is the single shape every provider maps onto. Adapters
translate native resources into normalized ones (``provider`` + normalized
:class:`CloudResourceType` + the native type string for provenance); downstream
consumers read the normalized fields and never the provider-specific dicts.

This module is additive — it does not change existing inventory output. It
provides the normalized *view* that later phases (graph ingestion, gap-fill,
AWS/GCP adapters) consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CloudResourceType(str, Enum):
    """Provider-agnostic resource categories.

    Intentionally broad so AWS/GCP equivalents map onto the same member
    (e.g. Azure Storage Account, AWS S3 bucket, and GCS bucket are all
    :attr:`OBJECT_STORE`).
    """

    COMPUTE_INSTANCE = "compute_instance"  # VM / EC2 / GCE
    CONTAINER_CLUSTER = "container_cluster"  # AKS / EKS / GKE
    CONTAINER_APP = "container_app"  # Container Apps / App Runner / Cloud Run
    CONTAINER_INSTANCE = "container_instance"  # ACI / Fargate task
    SERVERLESS_FUNCTION = "serverless_function"  # Functions / Lambda / Cloud Functions
    OBJECT_STORE = "object_store"  # Storage Account / S3 / GCS
    BLOCK_STORAGE = "block_storage"  # Managed Disk / EBS / PD
    SECRET_STORE = "secret_store"  # Key Vault / Secrets Manager / Secret Manager
    DATABASE = "database"  # SQL / Cosmos / RDS / Spanner / BigQuery
    CACHE = "cache"  # Redis / ElastiCache / Memorystore
    MESSAGING = "messaging"  # Service Bus / SQS-SNS / Pub-Sub
    VIRTUAL_NETWORK = "virtual_network"  # VNet / VPC
    NETWORK_SECURITY_GROUP = "network_security_group"  # NSG / Security Group / Firewall
    LOAD_BALANCER = "load_balancer"
    PUBLIC_IP = "public_ip"
    CONTAINER_REGISTRY = "container_registry"  # ACR / ECR / Artifact Registry
    MANAGED_IDENTITY = "managed_identity"  # User-assigned MI / IAM role / service account
    AI_SERVICE = "ai_service"  # Azure OpenAI / Bedrock / Vertex
    AI_MODEL_DEPLOYMENT = "ai_model_deployment"
    ML_WORKSPACE = "ml_workspace"  # Azure ML / SageMaker / Vertex Workbench
    OTHER = "other"


@dataclass(frozen=True)
class CloudResource:
    """One cloud resource, normalized across providers.

    ``native_type`` keeps the provider-native type string (e.g.
    ``Microsoft.Storage/storageAccounts``) for provenance and round-tripping;
    ``resource_type`` is the normalized category consumers branch on.
    """

    provider: str  # "azure" | "aws" | "gcp"
    resource_type: CloudResourceType
    native_type: str
    resource_id: str  # provider-native id / ARN / self-link
    name: str
    account: str = ""  # subscription id / account id / project id
    region: str = ""
    resource_group: str = ""  # RG (azure) / project (gcp) / "" (aws)
    tags: dict[str, str] = field(default_factory=dict)
    owner: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "resource_type": self.resource_type.value,
            "native_type": self.native_type,
            "resource_id": self.resource_id,
            "name": self.name,
            "account": self.account,
            "region": self.region,
            "resource_group": self.resource_group,
            "tags": dict(self.tags),
            "owner": self.owner,
        }


# Native Azure inventory collection -> (normalized type, native type string).
_AZURE_COLLECTION_MAP: dict[str, tuple[CloudResourceType, str]] = {
    "storage_accounts": (CloudResourceType.OBJECT_STORE, "Microsoft.Storage/storageAccounts"),
    "instances": (CloudResourceType.COMPUTE_INSTANCE, "Microsoft.Compute/virtualMachines"),
    "security_groups": (CloudResourceType.NETWORK_SECURITY_GROUP, "Microsoft.Network/networkSecurityGroups"),
    "managed_identities": (CloudResourceType.MANAGED_IDENTITY, "Microsoft.ManagedIdentity/userAssignedIdentities"),
    "key_vaults": (CloudResourceType.SECRET_STORE, "Microsoft.KeyVault/vaults"),
    "container_registries": (CloudResourceType.CONTAINER_REGISTRY, "Microsoft.ContainerRegistry/registries"),
    "databases": (CloudResourceType.DATABASE, "Microsoft.DocumentDB/databaseAccounts"),
    "virtual_networks": (CloudResourceType.VIRTUAL_NETWORK, "Microsoft.Network/virtualNetworks"),
    "public_ips": (CloudResourceType.PUBLIC_IP, "Microsoft.Network/publicIPAddresses"),
    "load_balancers": (CloudResourceType.LOAD_BALANCER, "Microsoft.Network/loadBalancers"),
}


def normalize_azure_inventory(inventory: dict[str, Any]) -> list[CloudResource]:
    """Map an Azure inventory payload onto normalized :class:`CloudResource`.

    Reads the existing ``azure_inventory`` dict shape (``storage_accounts``,
    ``instances`` …) without mutating it. Items missing an id or name are
    skipped rather than emitted as blanks.
    """
    account = str(inventory.get("subscription_id") or inventory.get("account_id") or "")
    resources: list[CloudResource] = []
    for collection, (rtype, native_type) in _AZURE_COLLECTION_MAP.items():
        for item in inventory.get(collection, []) or []:
            if not isinstance(item, dict):
                continue
            resource_id = str(item.get("id") or "")
            name = str(item.get("name") or "").strip()
            if not resource_id and not name:
                continue
            tags = item.get("tags") or {}
            resources.append(
                CloudResource(
                    provider="azure",
                    resource_type=rtype,
                    # items may carry their own native_type (e.g. a SQL vs Cosmos
                    # database in the shared "databases" collection); fall back
                    # to the collection default otherwise.
                    native_type=str(item.get("native_type") or native_type),
                    resource_id=resource_id,
                    name=name,
                    account=account,
                    region=str(item.get("location") or ""),
                    resource_group=str(item.get("resource_group") or ""),
                    tags={str(k): str(v) for k, v in tags.items()} if isinstance(tags, dict) else {},
                    raw=item,
                )
            )
    return resources


_PROVIDER_NORMALIZERS = {
    "azure": normalize_azure_inventory,
}


def normalize_cloud_inventory(inventory: dict[str, Any]) -> list[CloudResource]:
    """Dispatch to the per-provider normalizer based on ``inventory['provider']``.

    Returns an empty list for providers without a normalizer yet (AWS/GCP land
    here until their adapters are added), so callers can rely on the shape.
    """
    provider = str(inventory.get("provider") or "").lower()
    normalizer = _PROVIDER_NORMALIZERS.get(provider)
    return normalizer(inventory) if normalizer else []
