"""Project cloud storage and side-scan targets from recorded inventory."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.cloud_context import _add_account_resource_hierarchy, _recorded_exposure_attributes, _resource_environment
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def project_side_scan_targets(
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
    """Record eligible workload disks and their owning account."""
    # ── Agentless side-scan targets → workload disk CLOUD_RESOURCE ──
    for target in inventory.get("side_scan_targets", []) or []:
        if not isinstance(target, dict):
            continue
        target_id_raw = target.get("target_id") or target.get("id") or target.get("name")
        target_id = _clean_graph_part(target_id_raw)
        if not target_id:
            continue
        target_provider = _clean_graph_part(target.get("provider")) or provider
        target_type = _clean_graph_part(target.get("target_type")) or "disk"
        target_location = _clean_graph_part(target.get("location")) or region
        node_id = f"cloud_resource:{target_provider}:cwpp:{target_type}:{target_id}"
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"{target_type}: {target.get('name') or target_id}",
                attributes={
                    "resource_id": target_id_raw,
                    "resource_name": _clean_graph_part(target.get("name")) or target_id,
                    "resource_type": "workload_disk",
                    "resource_kind": target_type,
                    "cloud_provider": target_provider,
                    "cloud_service": "cwpp-side-scan",
                    "location": target_location,
                    "account_id": target.get("account_id") or account_id,
                    "side_scan_status": _clean_graph_part(target.get("status")) or "eligible",
                    "side_scan_execution": _clean_graph_part(target.get("execution")) or "not_started",
                    "side_scan_requires_snapshot_role": bool(target.get("requires_snapshot_role", True)),
                    "size_gb": target.get("size_gb"),
                    "encryption": _clean_graph_part(target.get("encryption")) or "unknown",
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=target_provider, surface="cwpp"),
            )
        )
        resource_ids.append(node_id)
        if account_node_id:
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "cloud-inventory", "reason": "side_scan_target"},
            )


def project_buckets(
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
    """Preserve bucket identity, exposure and redacted classification."""
    # ── S3 buckets → CLOUD_RESOURCE (CNAPP makes the DATA_STORE companion) ──
    for bucket in inventory.get("buckets", []) or []:
        if not isinstance(bucket, dict):
            continue
        name = _clean_graph_part(bucket.get("name"))
        if not name:
            continue
        bucket_service = _clean_graph_part(bucket.get("_service")) or "s3"
        bucket_kind = _clean_graph_part(bucket.get("_kind")) or "s3-bucket"
        bucket_label = _clean_graph_part(bucket.get("_label")) or "s3 bucket"
        bucket_tags = bucket.get("tags", {}) if isinstance(bucket.get("tags"), dict) else {}
        bucket_env = _resource_environment(bucket)
        node_id = f"cloud_resource:{provider}:{bucket_service}:bucket:{name}"
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                # Label carries a data-store keyword ("bucket"/"storage account")
                # so the CNAPP overlay's data-store match fires and builds the
                # DATA_STORE companion.
                label=f"{bucket_label}: {name}",
                attributes={
                    "resource_id": bucket.get("arn") or bucket.get("id") or name,
                    "resource_name": name,
                    "resource_type": "bucket",
                    "resource_kind": bucket_kind,
                    "cloud_provider": provider,
                    "cloud_service": bucket_service,
                    "location": _clean_graph_part(bucket.get("location")) or region,
                    **_recorded_exposure_attributes(bucket, "publicly_accessible"),
                    "tags": bucket_tags,
                    "account_id": account_id,
                    "environment": bucket_env,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="s3", environment=bucket_env),
            )
        )
        resource_ids.append(node_id)
        # Redacted DSPM content-sampling evidence rides onto the resource node so
        # the CNAPP/DSPM overlay's ``content_classification`` reader promotes the
        # DATA_STORE companion to a sensitive crown jewel (parity with the DB path
        # below). Copied verbatim — it is already redacted (types/counts only).
        bucket_classification = bucket.get("content_classification")
        if isinstance(bucket_classification, dict):
            graph.nodes[node_id].attributes["content_classification"] = bucket_classification
        if account_node_id:
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "cloud-inventory"},
            )


def project_databases(
    graph: UnifiedGraph,
    original_inventory: dict[str, Any],
    *,
    provider: str,
    account_id: str,
    account_node_id: str,
    region: str,
    data_sources: list[str],
    resource_ids: list[str],
) -> None:
    """Preserve database content-scan evidence from the original payload."""
    # ── DSPM databases → CLOUD_RESOURCE (RDS/Postgres/warehouse content stores) ──
    # A ``dspm_databases`` record carries the redacted database content-scan
    # classification (``agent-bom.dspm.database_scan.v1``). Materialize each as a
    # data-store-labelled CLOUD_RESOURCE carrying the classification so the CNAPP
    # overlay attaches a DATA_STORE companion and, when publicly reachable, the
    # public→sensitive toxic-combination path fires — the same surface S3/GCS
    # content sampling feeds. Never raises into the builder.
    for db in original_inventory.get("dspm_databases", []) or []:
        if not isinstance(db, dict):
            continue
        db_name = _clean_graph_part(db.get("name"))
        if not db_name:
            continue
        db_classification = db.get("content_classification")
        db_attributes: dict[str, Any] = {
            "resource_id": db.get("id") or db.get("arn") or db_name,
            "resource_name": db_name,
            "resource_type": "database",
            "resource_kind": _clean_graph_part(db.get("engine")) or "database",
            "cloud_provider": provider,
            "cloud_service": "dspm-database",
            "location": _clean_graph_part(db.get("location")) or region,
            **_recorded_exposure_attributes(db, "publicly_accessible"),
            "is_data_store": True,
            "account_id": db.get("account_id") or account_id,
        }
        if isinstance(db_classification, dict):
            db_attributes["content_classification"] = db_classification
        node_id = f"cloud_resource:{provider}:database:{db_name}"
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                # Label carries the "database" data-store keyword so the CNAPP
                # overlay's data-store match fires and builds the companion.
                label=f"database: {db_name}",
                attributes=db_attributes,
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="dspm"),
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
