"""The ``environment`` scope dimension must be provider-symmetric.

The estate hierarchy is ``provider`` / account / region / ``environment``. The
environment leg is read from a resource's own tags (AWS/Azure) or labels (GCP)
and is what ``select_observed_scope(kind="environment")``, ``/v1/graph/scoped``,
and ``/v1/inventory?environment=`` all key off.

Before this guard only two emission sites populated it — the shared bucket loop
and the Azure-only normalized-resource loop — so an AWS RDS instance, an EKS
cluster, a GCP Cloud SQL instance, or *any* provider's compute instance tagged
``environment=prod`` was invisible to the environment drill-down while the
equivalent Azure resource was not.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.scope import select_observed_scope

ENV = "prod"
_TAGS = {"environment": ENV, "owner": "team-a"}

# Provider payloads describing the SAME logical estate: an object store, a
# compute instance, a managed database, a container cluster, and a registry —
# every one tagged/labelled ``environment=prod`` the way its provider does it.
AWS_INVENTORY: dict[str, Any] = {
    "provider": "aws",
    "status": "ok",
    "account_id": "123456789012",
    "region": "us-east-1",
    "buckets": [{"name": "aws-bucket", "tags": dict(_TAGS)}],
    "instances": [{"instance_id": "i-1", "name": "aws-vm", "tags": dict(_TAGS)}],
    "rds_instances": [{"name": "aws-db", "engine": "postgres", "tags": dict(_TAGS)}],
    "eks_clusters": [{"name": "aws-eks", "tags": dict(_TAGS)}],
    "ecr_repositories": [{"name": "aws-ecr", "tags": dict(_TAGS)}],
}

AZURE_INVENTORY: dict[str, Any] = {
    "provider": "azure",
    "status": "ok",
    "account_id": "sub-1",
    "subscription_id": "sub-1",
    "region": "eastus",
    "storage_accounts": [{"name": "azblob", "id": "/subscriptions/sub-1/sa", "tags": dict(_TAGS)}],
    "instances": [{"instance_id": "vm-1", "name": "az-vm", "tags": dict(_TAGS)}],
    "databases": [{"name": "az-db", "id": "/subscriptions/sub-1/db", "tags": dict(_TAGS)}],
    "container_clusters": [{"name": "az-aks", "id": "/subscriptions/sub-1/aks", "tags": dict(_TAGS)}],
    "container_registries": [{"name": "azacr", "id": "/subscriptions/sub-1/acr", "tags": dict(_TAGS)}],
}

# GCP labels its resources; ``labels`` is the provider-native spelling of
# ``tags`` and the only place a GCE instance / Cloud SQL instance carries an
# environment marker (``network_tags`` is firewall targeting, not metadata).
GCP_INVENTORY: dict[str, Any] = {
    "provider": "gcp",
    "status": "ok",
    "account_id": "proj-1",
    "project_id": "proj-1",
    "region": "us-central1",
    "buckets": [{"name": "gcs-bucket", "tags": dict(_TAGS)}],
    "instances": [{"instance_id": "gce-1", "name": "gce-vm", "labels": dict(_TAGS)}],
    "cloud_sql_instances": [{"name": "gcp-sql", "labels": dict(_TAGS)}],
    "gke_clusters": [{"name": "gcp-gke", "id": "gke-1", "labels": dict(_TAGS)}],
    "cloud_run_services": [{"name": "gcp-run", "labels": dict(_TAGS)}],
}

_INVENTORIES = {"aws": AWS_INVENTORY, "azure": AZURE_INVENTORY, "gcp": GCP_INVENTORY}

_RESOURCE_ENTITIES = {"cloud_resource", "data_store"}


def _build(provider: str):
    return build_unified_graph_from_report({"cloud_inventory": [_INVENTORIES[provider]]})


def _resource_nodes(graph) -> list[Any]:
    return [node for node in graph.nodes.values() if getattr(node.entity_type, "value", node.entity_type) in _RESOURCE_ENTITIES]


@pytest.mark.parametrize("provider", sorted(_INVENTORIES))
def test_tagged_resources_carry_the_environment_dimension(provider: str) -> None:
    """Every inventoried resource tagged ``environment=prod`` carries the facet."""
    graph = _build(provider)
    resources = _resource_nodes(graph)
    assert resources, f"{provider} produced no resource nodes"
    missing = sorted(node.attributes.get("resource_name") or node.id for node in resources if node.dimensions.environment != ENV)
    assert not missing, f"{provider} resources missing the environment dimension: {missing}"


def test_environment_scope_is_provider_symmetric() -> None:
    """The environment drill-down returns each provider's whole tagged estate."""
    counts = {}
    for provider in _INVENTORIES:
        graph = _build(provider)
        scoped = select_observed_scope(
            graph,
            kind="environment",
            scope_id=ENV,
            max_depth=4,
            max_nodes=500,
            max_edges=500,
        )
        counts[provider] = (len(_resource_nodes(graph)), len(scoped.graph.nodes))

    for provider, (total, scoped_nodes) in counts.items():
        assert scoped_nodes == total, (
            f"{provider}: environment scope returned {scoped_nodes} of {total} tagged resources (all providers: {counts})"
        )


def test_gcp_network_tags_are_not_mistaken_for_an_environment() -> None:
    """GCE ``network_tags`` are firewall targets, never an environment label."""
    graph = build_unified_graph_from_report(
        {
            "cloud_inventory": [
                {
                    "provider": "gcp",
                    "status": "ok",
                    "account_id": "proj-2",
                    "instances": [
                        {
                            "instance_id": "gce-2",
                            "name": "untagged",
                            "network_tags": ["environment", "prod-web"],
                        }
                    ],
                }
            ]
        }
    )
    instances = [n for n in _resource_nodes(graph) if n.attributes.get("resource_type") == "instance"]
    assert instances, "no GCE instance node built"
    assert all(node.dimensions.environment == "" for node in instances)
