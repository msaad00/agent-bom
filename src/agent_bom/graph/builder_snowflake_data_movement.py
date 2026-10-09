"""Snowflake external data and exfiltration-path projection."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.builder_snowflake_lane import _snowflake_data_store, _SnowflakeLane
from agent_bom.graph.cloud_context import _add_identity_node, _prepare_cloud_payload
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part

_EXFIL_STAGE_SERVICE = {"aws": "s3", "azure": "blob", "gcp": "gcs"}


_SF_EXTERNAL_BUCKET_SERVICE = {"aws": "s3", "azure": "blob", "gcp": "gcs"}


def _link_iceberg_bucket(lane: _SnowflakeLane, node_id: str, cloud: str, bucket: str) -> None:
    graph = lane.graph
    service = _SF_EXTERNAL_BUCKET_SERVICE.get(cloud, "storage")
    bucket_id = f"cloud_resource:{cloud}:{service}:bucket:{bucket}"
    if bucket_id not in graph.nodes:
        graph.add_node(
            UnifiedNode(
                id=bucket_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"bucket: {bucket}",
                attributes={
                    "resource_name": bucket,
                    "resource_type": "bucket",
                    "resource_kind": f"{service}-bucket",
                    "cloud_provider": cloud,
                    "cloud_service": service,
                },
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider=cloud, surface=service),
            )
        )
    _add_rel_edge(
        graph,
        node_id,
        bucket_id,
        RelationshipType.EXPOSED_TO,
        {"source": "snowflake-external-data", "channel": "iceberg-base-location"},
    )


def _add_snowflake_iceberg_tables(lane: _SnowflakeLane, tables: Any) -> None:
    for tbl in tables or []:
        if not isinstance(tbl, dict):
            continue
        fqn = _clean_graph_part(tbl.get("fqn")) or _clean_graph_part(tbl.get("name"))
        if not fqn:
            continue
        node_id = _snowflake_data_store(
            lane,
            f"data_store:snowflake:iceberg:{fqn}",
            f"iceberg table: {fqn}",
            {
                "fqn": fqn,
                "object_type": "iceberg_table",
                "table_format": "iceberg",
                "catalog": tbl.get("catalog"),
                "catalog_source": tbl.get("catalog_source"),
                "base_location": tbl.get("base_location"),
            },
        )
        cloud = _clean_graph_part(tbl.get("cloud_provider"))
        bucket = _clean_graph_part(tbl.get("bucket"))
        if cloud and bucket:
            _link_iceberg_bucket(lane, node_id, cloud, bucket)


def _add_snowflake_external_tables(lane: _SnowflakeLane, tables: Any) -> None:
    graph = lane.graph
    for tbl in tables or []:
        if not isinstance(tbl, dict):
            continue
        fqn = _clean_graph_part(tbl.get("fqn")) or _clean_graph_part(tbl.get("name"))
        if not fqn:
            continue
        node_id = _snowflake_data_store(
            lane,
            f"data_store:snowflake:external_table:{fqn}",
            f"external table: {fqn}",
            {"fqn": fqn, "object_type": "external_table", "location": tbl.get("location")},
        )
        stage = _clean_graph_part(tbl.get("stage"))
        if not stage:
            continue
        stage_name = stage.split(".")[-1]
        stage_id = f"cloud_resource:snowflake:stage:{stage_name}"
        if stage_id not in graph.nodes:
            graph.add_node(
                UnifiedNode(
                    id=stage_id,
                    entity_type=EntityType.CLOUD_RESOURCE,
                    label=f"external stage: {stage_name}",
                    attributes={"cloud_provider": "snowflake", "resource_type": "external-stage"},
                    data_sources=lane.data_sources,
                    dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
                )
            )
        _add_rel_edge(
            graph,
            node_id,
            stage_id,
            RelationshipType.DEPENDS_ON,
            {"source": "snowflake-external-data", "via": "external-table-stage"},
        )


def _add_snowflake_external_data(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake open-table-format + external data into the graph.

    * **Iceberg tables** → ``DATA_STORE``; when the base location is a cloud
      bucket, ``EXPOSED_TO`` that bucket node (same id a cloud scan emits — the
      cross-cloud stitch), so off-account Iceberg data is traversable.
    * **External tables** → ``DATA_STORE``; ``DEPENDS_ON`` the stage they read
      from (which the exfil layer links onward to the bucket).

    Never raises; a non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-external-data")
    if prepared is None:
        return
    account, data_sources = prepared
    lane = _SnowflakeLane(graph, account, data_sources, "snowflake-external-data")
    _add_snowflake_iceberg_tables(lane, payload.get("iceberg_tables", []))
    _add_snowflake_external_tables(lane, payload.get("external_tables", []))


def _add_snowflake_outbound_shares(lane: _SnowflakeLane, shares: Any) -> None:
    """Outbound shares → consumer accounts."""
    graph = lane.graph
    for share in shares or []:
        if not isinstance(share, dict):
            continue
        share_name = _clean_graph_part(share.get("share_name"))
        if not share_name:
            continue
        db = _clean_graph_part(share.get("database_name"))
        is_marketplace = bool(share.get("is_marketplace"))
        share_id = lane.own(
            UnifiedNode(
                id=f"data_store:snowflake:share:{share_name}",
                entity_type=EntityType.DATA_STORE,
                label=f"outbound share: {share_name}",
                attributes={
                    "share_name": share_name,
                    "database": db,
                    "cloud_provider": "snowflake",
                    "is_data_store": True,
                    "is_outbound_share": True,
                    "is_marketplace": is_marketplace,
                },
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        consumers = list(share.get("consumers") or [])
        if is_marketplace and not consumers:
            consumers = ["public-marketplace"]
        for consumer in consumers:
            consumer = _clean_graph_part(consumer)
            if not consumer:
                continue
            consumer_id = _add_identity_node(
                graph,
                EntityType.ACCOUNT,
                consumer,
                "snowflake",
                lane.data_sources,
                label=f"consumer account: {consumer}",
                account_id=consumer,
                cloud_provider="snowflake",
                is_external_consumer=True,
                internet_exposed=consumer == "public-marketplace",
            )
            _add_rel_edge(
                graph,
                share_id,
                consumer_id,
                RelationshipType.EXPOSED_TO,
                {"source": "snowflake-exfil", "channel": "data-share", "marketplace": is_marketplace},
            )


def _add_snowflake_stage_bucket(lane: _SnowflakeLane, stage_id: str, cloud: str, bucket: str) -> None:
    graph = lane.graph
    service = _EXFIL_STAGE_SERVICE.get(cloud, "storage")
    bucket_node_id = f"cloud_resource:{cloud}:{service}:bucket:{bucket}"
    if bucket_node_id not in graph.nodes:
        # Thin destination node — a cloud scan, if also run, owns the rich one.
        graph.add_node(
            UnifiedNode(
                id=bucket_node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"bucket: {bucket}",
                attributes={
                    "resource_name": bucket,
                    "resource_type": "bucket",
                    "resource_kind": f"{service}-bucket",
                    "cloud_provider": cloud,
                    "cloud_service": service,
                },
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider=cloud, surface=service),
            )
        )
    _add_rel_edge(
        graph,
        stage_id,
        bucket_node_id,
        RelationshipType.EXPOSED_TO,
        {"source": "snowflake-exfil", "channel": "external-stage", "destination_cloud": cloud},
    )


def _add_snowflake_external_stages(lane: _SnowflakeLane, stages: Any) -> None:
    """External stages → destination buckets (cross-cloud stitch)."""
    for stage in stages or []:
        if not isinstance(stage, dict):
            continue
        stage_name = _clean_graph_part(stage.get("stage_name"))
        bucket = _clean_graph_part(stage.get("bucket"))
        cloud = _clean_graph_part(stage.get("cloud_provider"))
        if not stage_name or not bucket or not cloud:
            continue
        stage_id = lane.own(
            UnifiedNode(
                id=f"cloud_resource:snowflake:stage:{stage_name}",
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"external stage: {stage_name}",
                attributes={
                    "resource_name": stage_name,
                    "resource_type": "external-stage",
                    "resource_kind": "snowflake-external-stage",
                    "cloud_provider": "snowflake",
                    "destination_cloud": cloud,
                    "destination_bucket": bucket,
                    "url": _clean_graph_part(stage.get("url")),
                },
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        _add_snowflake_stage_bucket(lane, stage_id, cloud, bucket)


def _add_snowflake_sensitive_objects(lane: _SnowflakeLane, objects: Any) -> None:
    """Sensitive objects → DATA_STORE with sensitivity."""
    for obj in objects or []:
        if not isinstance(obj, dict):
            continue
        fqn = _clean_graph_part(obj.get("fqn"))
        if not fqn:
            continue
        lane.own(
            UnifiedNode(
                id=f"data_store:snowflake:{fqn}",
                entity_type=EntityType.DATA_STORE,
                label=f"sensitive: {fqn}",
                attributes={
                    "fqn": fqn,
                    "cloud_provider": "snowflake",
                    "is_data_store": True,
                    "sensitivity": _clean_graph_part(obj.get("sensitivity")) or "sensitive",
                    "tagged_columns": obj.get("tagged_columns"),
                    "is_protected": bool(obj.get("is_protected")),
                },
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )


def _add_snowflake_exfil(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake egress surfaces into the graph (exfil layer).

    Three node/edge families that model how data leaves the account:

    - **Outbound shares** → ``DATA_STORE`` for the shared database, ``EXPOSED_TO``
      each consumer ``ACCOUNT`` (a Marketplace listing reaches an open consumer
      set, modeled as a single internet-reachable consumer).
    - **External stages** → ``CLOUD_RESOURCE`` stage node, ``EXPOSED_TO`` the
      destination bucket. The bucket id matches the scheme an AWS/Azure/GCP scan
      emits (``cloud_resource:{cloud}:{service}:bucket:{name}``), so when both a
      cloud scan and this Snowflake scan run, the edge **stitches the two clouds'
      graphs together** rather than landing on a thin node.
    - **Sensitive objects** → ``DATA_STORE`` carrying a ``sensitivity`` attribute
      and ``is_protected`` (masking/row-access coverage).

    Never raises; a missing/empty/non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-exfil")
    if prepared is None:
        return
    account, data_sources = prepared
    lane = _SnowflakeLane(graph, account, data_sources, "snowflake-exfil")
    _add_snowflake_outbound_shares(lane, payload.get("outbound_shares", []))
    _add_snowflake_external_stages(lane, payload.get("external_stages", []))
    _add_snowflake_sensitive_objects(lane, payload.get("sensitive_objects", []))
