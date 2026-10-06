"""Project provider service collections without changing native identity semantics."""

from __future__ import annotations

from typing import Any

from agent_bom.core.cloud_identity import cloud_resource_node_id
from agent_bom.graph.cloud_context import _add_account_resource_hierarchy, _recorded_exposure_attributes, _resource_environment
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def project_aws_services(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    *,
    provider: str,
    account_id: str,
    account_node_id: str,
    region: str,
    data_sources: list[str],
    resource_ids: list[str],
) -> list[tuple[str, str]]:
    """Project AWS-shaped service records and return observed public load balancers."""
    internet_facing_lbs: list[tuple[str, str]] = []
    # ── AWS data + compute services (RDS / DynamoDB / Lambda / EKS) ──────
    # (key, service, resource_type, kind, label, is_data_store)
    for coll_key, svc, rtype, kind, label, is_data in (
        ("rds_instances", "rds", "database", "rds-instance", "rds database", True),
        ("dynamodb_tables", "dynamodb", "database", "dynamodb-table", "dynamodb table", True),
        ("lambda_functions", "lambda", "function", "lambda-function", "lambda function", False),
        ("eks_clusters", "eks", "container_cluster", "eks-cluster", "eks cluster", False),
        ("elb_load_balancers", "elbv2", "load_balancer", "elb-load-balancer", "load balancer", False),
        ("vpcs", "ec2", "virtual_network", "vpc", "vpc", False),
        ("kms_keys", "kms", "key", "kms-key", "kms key", False),
        ("secrets", "secretsmanager", "secret", "secretsmanager-secret", "secret", False),
        ("cloudfront_distributions", "cloudfront", "cdn", "cloudfront-distribution", "cdn distribution", False),
        ("ecr_repositories", "ecr", "container_registry", "ecr-repository", "container registry", False),
        ("redshift_clusters", "redshift", "data_warehouse", "redshift-cluster", "redshift warehouse", True),
        ("messaging", "messaging", "messaging", "aws-messaging", "messaging", False),
    ):
        for item in inventory.get(coll_key, []) or []:
            if not isinstance(item, dict):
                continue
            name = _clean_graph_part(item.get("name"))
            if not name:
                continue
            node_id = cloud_resource_node_id(provider, f"{svc}:{rtype}", item, account_id, region)
            exposure = _recorded_exposure_attributes(item, "publicly_accessible", "internet_exposed", "endpoint_public")
            item_env = _resource_environment(item)
            graph.add_node(
                UnifiedNode(
                    id=node_id,
                    entity_type=EntityType.DATA_STORE if is_data else EntityType.CLOUD_RESOURCE,
                    label=f"{label}: {name}",
                    attributes={
                        "resource_id": _clean_graph_part(item.get("arn")) or name,
                        "resource_name": name,
                        "resource_type": rtype,
                        "resource_kind": kind,
                        "cloud_provider": provider,
                        "cloud_service": svc,
                        "location": _clean_graph_part(item.get("location")) or region,
                        **exposure,
                        "is_data_store": is_data,
                        "engine": _clean_graph_part(item.get("engine")),
                        "runtime": _clean_graph_part(item.get("runtime")),
                        "encrypted": bool(item.get("encrypted")),
                        "account_id": account_id,
                        "environment": item_env,
                    },
                    data_sources=data_sources,
                    dimensions=NodeDimensions(cloud_provider=provider, surface=svc, environment=item_env),
                )
            )
            resource_ids.append(node_id)
            if account_node_id:
                _add_account_resource_hierarchy(
                    graph,
                    account_node_id,
                    node_id,
                    evidence={"source": "cloud-inventory"},
                )
            if coll_key == "elb_load_balancers" and exposure["internet_exposed"] is True:
                internet_facing_lbs.append((node_id, _clean_graph_part(item.get("vpc_id"))))
    return internet_facing_lbs


def project_gcp_services(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    *,
    provider: str,
    account_id: str,
    account_node_id: str,
    region: str,
    data_sources: list[str],
    resource_ids: list[str],
) -> None:
    """Project GCP-native services only for a GCP inventory."""
    # ── GCP estate breadth (GKE / Cloud Run / Functions / Cloud SQL / VPC /
    # disks / Pub/Sub) → CLOUD_RESOURCE or DATA_STORE, OWNS from the project. ──
    # Mirrors the AWS service loop above. Cloud SQL is a DATA_STORE so DSPM tiers
    # apply; public-IP instances carry `internet_exposed` for CNAPP. Native IDs
    # retain provider scope; local identifiers are bound to project and location.
    if provider == "gcp":
        for coll_key, svc, rtype, kind, label, is_data in (
            ("gke_clusters", "gke", "container_cluster", "gke-cluster", "gke cluster", False),
            ("cloud_run_services", "run", "function", "cloud-run-service", "cloud run service", False),
            ("cloud_functions", "cloudfunctions", "function", "cloud-function", "cloud function", False),
            ("cloud_sql_instances", "cloudsql", "database", "cloud-sql-instance", "cloud sql database", True),
            ("vpc_networks", "compute", "virtual_network", "vpc-network", "vpc network", False),
            ("disks", "compute", "storage", "persistent-disk", "persistent disk", False),
            ("pubsub_topics", "pubsub", "messaging", "pubsub-topic", "pubsub topic", False),
        ):
            for item in inventory.get(coll_key, []) or []:
                if not isinstance(item, dict):
                    continue
                name = _clean_graph_part(item.get("name"))
                if not name:
                    continue
                node_id = cloud_resource_node_id("gcp", f"{svc}:{rtype}", item, account_id, region)
                exposure = _recorded_exposure_attributes(item, "publicly_accessible", "internet_exposed")
                item_env = _resource_environment(item)
                graph.add_node(
                    UnifiedNode(
                        id=node_id,
                        entity_type=EntityType.DATA_STORE if is_data else EntityType.CLOUD_RESOURCE,
                        label=f"{label}: {name}",
                        attributes={
                            "resource_id": _clean_graph_part(item.get("id")) or name,
                            "resource_name": name,
                            "resource_type": rtype,
                            "resource_kind": kind,
                            "cloud_provider": "gcp",
                            "cloud_service": svc,
                            "location": _clean_graph_part(item.get("location")) or region,
                            **exposure,
                            "is_data_store": is_data,
                            "engine": _clean_graph_part(item.get("database_version")),
                            "encrypted": bool(item.get("encrypted")),
                            "account_id": account_id,
                            "environment": item_env,
                        },
                        data_sources=data_sources,
                        dimensions=NodeDimensions(cloud_provider="gcp", surface=svc, environment=item_env),
                    )
                )
                resource_ids.append(node_id)
                if account_node_id:
                    _add_account_resource_hierarchy(
                        graph,
                        account_node_id,
                        node_id,
                        evidence={"source": "cloud-inventory"},
                    )
