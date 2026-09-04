"""Normalized, provider-agnostic cloud resource model.

Each provider's inventory historically emitted its own dict shape
(``storage_accounts`` / ``instances`` / ``security_groups`` for Azure, and
different keys for AWS/GCP). That makes the graph, CIS, and findings layers
re-learn every provider's vocabulary and blocks cross-cloud normalization.

:class:`CloudResource` is the provider-neutral shape each provider can map onto.
Adapters translate native resources into normalized ones (``provider`` +
normalized :class:`CloudResourceType` + the native type string for provenance),
letting downstream consumers migrate off provider-specific dicts incrementally.

This module is additive — it does not change existing inventory output. It
provides the normalized *view* that later phases (graph ingestion and gap-fill)
consume.
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
    DATA_WAREHOUSE = "data_warehouse"  # Redshift / Snowflake warehouse
    OTHER = "other"


@dataclass(frozen=True)
class CloudResource:
    """One cloud resource, normalized across providers.

    ``native_type`` keeps the provider-native type string (e.g.
    ``Microsoft.Storage/storageAccounts``) for provenance and round-tripping;
    ``resource_type`` is the normalized category consumers branch on.
    """

    provider: str  # "azure" | "aws" | "gcp" | "snowflake"
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


@dataclass(frozen=True)
class _CollectionAdapter:
    """Declarative mapping from one native inventory collection."""

    resource_type: CloudResourceType
    native_type: str
    id_fields: tuple[str, ...]
    name_fields: tuple[str, ...] = ("name",)
    region_fields: tuple[str, ...] = ("region", "location", "zone")
    resource_group_fields: tuple[str, ...] = ("resource_group",)
    native_type_field: str = ""


# Native Azure inventory collection -> (normalized type, native type string).
_AZURE_COLLECTION_MAP: dict[str, tuple[CloudResourceType, str]] = {
    "storage_accounts": (CloudResourceType.OBJECT_STORE, "Microsoft.Storage/storageAccounts"),
    "instances": (CloudResourceType.COMPUTE_INSTANCE, "Microsoft.Compute/virtualMachines"),
    "security_groups": (CloudResourceType.NETWORK_SECURITY_GROUP, "Microsoft.Network/networkSecurityGroups"),
    "managed_identities": (CloudResourceType.MANAGED_IDENTITY, "Microsoft.ManagedIdentity/userAssignedIdentities"),
    "container_clusters": (CloudResourceType.CONTAINER_CLUSTER, "Microsoft.ContainerService/managedClusters"),
    "key_vaults": (CloudResourceType.SECRET_STORE, "Microsoft.KeyVault/vaults"),
    "container_registries": (CloudResourceType.CONTAINER_REGISTRY, "Microsoft.ContainerRegistry/registries"),
    "databases": (CloudResourceType.DATABASE, "Microsoft.DocumentDB/databaseAccounts"),
    "virtual_networks": (CloudResourceType.VIRTUAL_NETWORK, "Microsoft.Network/virtualNetworks"),
    "public_ips": (CloudResourceType.PUBLIC_IP, "Microsoft.Network/publicIPAddresses"),
    "load_balancers": (CloudResourceType.LOAD_BALANCER, "Microsoft.Network/loadBalancers"),
    "application_gateways": (CloudResourceType.LOAD_BALANCER, "Microsoft.Network/applicationGateways"),
    "front_doors": (CloudResourceType.LOAD_BALANCER, "Microsoft.Network/frontDoors"),
    "api_management": (CloudResourceType.LOAD_BALANCER, "Microsoft.ApiManagement/service"),
    "event_hubs": (CloudResourceType.MESSAGING, "Microsoft.EventHub/namespaces"),
    "service_bus_namespaces": (CloudResourceType.MESSAGING, "Microsoft.ServiceBus/namespaces"),
    "redis_caches": (CloudResourceType.CACHE, "Microsoft.Cache/Redis"),
    "managed_disks": (CloudResourceType.BLOCK_STORAGE, "Microsoft.Compute/disks"),
    "app_services": (CloudResourceType.SERVERLESS_FUNCTION, "Microsoft.Web/sites"),
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


_AWS_COLLECTION_MAP: dict[str, _CollectionAdapter] = {
    "buckets": _CollectionAdapter(CloudResourceType.OBJECT_STORE, "AWS::S3::Bucket", ("arn", "id", "name")),
    "instances": _CollectionAdapter(
        CloudResourceType.COMPUTE_INSTANCE,
        "AWS::EC2::Instance",
        ("instance_id", "arn", "id", "name"),
    ),
    "security_groups": _CollectionAdapter(
        CloudResourceType.NETWORK_SECURITY_GROUP,
        "AWS::EC2::SecurityGroup",
        ("group_id", "arn", "id", "name"),
    ),
    "roles": _CollectionAdapter(CloudResourceType.MANAGED_IDENTITY, "AWS::IAM::Role", ("arn", "role_id", "id", "name")),
    "rds_instances": _CollectionAdapter(
        CloudResourceType.DATABASE,
        "AWS::RDS::DBInstance",
        ("db_instance_arn", "arn", "db_instance_identifier", "id", "name"),
    ),
    "lambda_functions": _CollectionAdapter(
        CloudResourceType.SERVERLESS_FUNCTION,
        "AWS::Lambda::Function",
        ("function_arn", "arn", "id", "name"),
    ),
    "dynamodb_tables": _CollectionAdapter(
        CloudResourceType.DATABASE,
        "AWS::DynamoDB::Table",
        ("table_arn", "arn", "id", "name"),
    ),
    "eks_clusters": _CollectionAdapter(
        CloudResourceType.CONTAINER_CLUSTER,
        "AWS::EKS::Cluster",
        ("arn", "id", "name"),
    ),
    "elb_load_balancers": _CollectionAdapter(
        CloudResourceType.LOAD_BALANCER,
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
        ("load_balancer_arn", "arn", "id", "name"),
    ),
    "vpcs": _CollectionAdapter(CloudResourceType.VIRTUAL_NETWORK, "AWS::EC2::VPC", ("vpc_id", "arn", "id", "name")),
    "secrets": _CollectionAdapter(
        CloudResourceType.SECRET_STORE,
        "AWS::SecretsManager::Secret",
        ("arn", "id", "name"),
    ),
    "ecr_repositories": _CollectionAdapter(
        CloudResourceType.CONTAINER_REGISTRY,
        "AWS::ECR::Repository",
        ("repository_arn", "arn", "uri", "id", "name"),
    ),
    "redshift_clusters": _CollectionAdapter(
        CloudResourceType.DATA_WAREHOUSE,
        "AWS::Redshift::Cluster",
        ("arn", "cluster_identifier", "id", "name"),
    ),
    "messaging": _CollectionAdapter(CloudResourceType.MESSAGING, "AWS::Messaging::Endpoint", ("arn", "url", "id", "name")),
    "api_gateways": _CollectionAdapter(
        CloudResourceType.LOAD_BALANCER,
        "AWS::ApiGateway::RestApi",
        ("arn", "id", "name"),
    ),
    "ip_addresses": _CollectionAdapter(
        CloudResourceType.PUBLIC_IP,
        "AWS::EC2::EIP",
        ("allocation_id", "public_ip", "id", "name"),
    ),
}


_GCP_COLLECTION_MAP: dict[str, _CollectionAdapter] = {
    "buckets": _CollectionAdapter(CloudResourceType.OBJECT_STORE, "storage.googleapis.com/Bucket", ("id", "self_link", "name")),
    "instances": _CollectionAdapter(
        CloudResourceType.COMPUTE_INSTANCE,
        "compute.googleapis.com/Instance",
        ("id", "self_link", "instance_id", "name"),
    ),
    "firewalls": _CollectionAdapter(
        CloudResourceType.NETWORK_SECURITY_GROUP,
        "compute.googleapis.com/Firewall",
        ("id", "self_link", "name"),
    ),
    "service_accounts": _CollectionAdapter(
        CloudResourceType.MANAGED_IDENTITY,
        "iam.googleapis.com/ServiceAccount",
        ("email", "arn", "principal_id", "id", "name"),
    ),
    "gke_clusters": _CollectionAdapter(
        CloudResourceType.CONTAINER_CLUSTER,
        "container.googleapis.com/Cluster",
        ("id", "self_link", "name"),
    ),
    "cloud_run_services": _CollectionAdapter(
        CloudResourceType.CONTAINER_APP,
        "run.googleapis.com/Service",
        ("id", "self_link", "name"),
    ),
    "cloud_functions": _CollectionAdapter(
        CloudResourceType.SERVERLESS_FUNCTION,
        "cloudfunctions.googleapis.com/Function",
        ("id", "self_link", "name"),
    ),
    "cloud_sql_instances": _CollectionAdapter(
        CloudResourceType.DATABASE,
        "sqladmin.googleapis.com/DatabaseInstance",
        ("id", "self_link", "name"),
    ),
    "vpc_networks": _CollectionAdapter(
        CloudResourceType.VIRTUAL_NETWORK,
        "compute.googleapis.com/Network",
        ("id", "self_link", "name"),
    ),
    "load_balancers": _CollectionAdapter(
        CloudResourceType.LOAD_BALANCER,
        "compute.googleapis.com/LoadBalancer",
        ("id", "self_link", "name"),
    ),
    "api_gateways": _CollectionAdapter(
        CloudResourceType.LOAD_BALANCER,
        "apigateway.googleapis.com/Gateway",
        ("id", "self_link", "name"),
    ),
    "ip_addresses": _CollectionAdapter(
        CloudResourceType.PUBLIC_IP,
        "compute.googleapis.com/Address",
        ("id", "self_link", "address", "name"),
    ),
    "disks": _CollectionAdapter(
        CloudResourceType.BLOCK_STORAGE,
        "compute.googleapis.com/Disk",
        ("id", "self_link", "name"),
    ),
    "pubsub_topics": _CollectionAdapter(
        CloudResourceType.MESSAGING,
        "pubsub.googleapis.com/Topic",
        ("id", "self_link", "name"),
    ),
}


_SNOWFLAKE_COLLECTION_MAP: dict[str, _CollectionAdapter] = {
    "warehouses": _CollectionAdapter(CloudResourceType.DATA_WAREHOUSE, "SNOWFLAKE::WAREHOUSE", ("id", "name")),
    "databases": _CollectionAdapter(CloudResourceType.DATABASE, "SNOWFLAKE::DATABASE", ("id", "name")),
    "schemas": _CollectionAdapter(
        CloudResourceType.DATABASE,
        "SNOWFLAKE::SCHEMA",
        ("fqn", "id", "name"),
        resource_group_fields=("database_name", "database"),
    ),
    "objects": _CollectionAdapter(
        CloudResourceType.DATABASE,
        "SNOWFLAKE::OBJECT",
        ("fqn", "id", "name"),
        resource_group_fields=("schema", "database"),
        native_type_field="object_type",
    ),
}


def _first_text(item: dict[str, Any], fields: tuple[str, ...]) -> str:
    for field_name in fields:
        value = item.get(field_name)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _resource_tags(item: dict[str, Any]) -> dict[str, str]:
    raw_tags = item.get("tags")
    if not isinstance(raw_tags, dict):
        raw_tags = item.get("labels")
    if not isinstance(raw_tags, dict):
        return {}
    return {str(key): str(value) for key, value in raw_tags.items()}


def _normalize_collections(
    inventory: dict[str, Any],
    *,
    provider: str,
    collection_map: dict[str, _CollectionAdapter],
    account_fields: tuple[str, ...],
) -> list[CloudResource]:
    """Apply declarative native-collection mappings without mutating input."""
    default_account = _first_text(inventory, account_fields)
    default_region = _first_text(inventory, ("region", "location"))
    resources: list[CloudResource] = []
    for collection, adapter in collection_map.items():
        for item in inventory.get(collection, []) or []:
            if not isinstance(item, dict):
                continue
            resource_id = _first_text(item, adapter.id_fields)
            name = _first_text(item, adapter.name_fields)
            if not resource_id and not name:
                continue
            tags = _resource_tags(item)
            native_type = str(item.get("native_type") or adapter.native_type)
            if adapter.native_type_field:
                item_native_type = str(item.get(adapter.native_type_field) or "").strip()
                if item_native_type:
                    native_type = f"{provider.upper()}::{item_native_type.upper()}"
            resources.append(
                CloudResource(
                    provider=provider,
                    resource_type=adapter.resource_type,
                    native_type=native_type,
                    resource_id=resource_id,
                    name=name,
                    account=_first_text(item, account_fields) or default_account,
                    region=_first_text(item, adapter.region_fields) or default_region,
                    resource_group=_first_text(item, adapter.resource_group_fields),
                    tags=tags,
                    owner=str(item.get("owner") or tags.get("owner") or tags.get("Owner") or ""),
                    raw=item,
                )
            )
    return resources


def normalize_aws_inventory(inventory: dict[str, Any]) -> list[CloudResource]:
    """Map the current AWS estate inventory collections onto ``CloudResource``."""
    return _normalize_collections(
        inventory,
        provider="aws",
        collection_map=_AWS_COLLECTION_MAP,
        account_fields=("account_id", "account"),
    )


def normalize_gcp_inventory(inventory: dict[str, Any]) -> list[CloudResource]:
    """Map the current GCP estate inventory collections onto ``CloudResource``."""
    return _normalize_collections(
        inventory,
        provider="gcp",
        collection_map=_GCP_COLLECTION_MAP,
        account_fields=("project_id", "account_id", "account"),
    )


def normalize_snowflake_inventory(inventory: dict[str, Any]) -> list[CloudResource]:
    """Map a Snowflake services/object payload onto ``CloudResource``.

    Snowflake currently reaches the graph through separate ``snowflake_*``
    report blocks rather than ``cloud_inventory``. This adapter accepts either
    block after the caller stamps ``provider=snowflake`` and also supports a
    combined payload; graph migration remains a separate change.
    """
    return _normalize_collections(
        inventory,
        provider="snowflake",
        collection_map=_SNOWFLAKE_COLLECTION_MAP,
        account_fields=("account", "account_id"),
    )


_PROVIDER_NORMALIZERS = {
    "aws": normalize_aws_inventory,
    "azure": normalize_azure_inventory,
    "gcp": normalize_gcp_inventory,
    "snowflake": normalize_snowflake_inventory,
}


def normalize_cloud_inventory(inventory: dict[str, Any]) -> list[CloudResource]:
    """Dispatch to the per-provider normalizer based on ``inventory['provider']``.

    Returns an empty list for unknown providers so callers can rely on the
    result shape without guessing provider semantics.
    """
    provider = str(inventory.get("provider") or "").lower()
    normalizer = _PROVIDER_NORMALIZERS.get(provider)
    return normalizer(inventory) if normalizer else []
