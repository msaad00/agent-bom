"""Snowflake platform projection: organization, services, integrations and pipelines."""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.normalization import coerce_bool_or_none
from agent_bom.graph.builder_snowflake_lane import _snowflake_thin_node, _SnowflakeLane
from agent_bom.graph.cloud_context import _add_account_resource_hierarchy, _add_identity_node, _prepare_cloud_payload
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part
from agent_bom.security import sanitize_sensitive_payload


def _add_snowflake_organization(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote the Snowflake Organization → Accounts roll-up into the graph.

    The Snowflake analogue of :func:`_add_aws_organization` and
    :func:`_add_gcp_organization`: multiple Snowflake accounts roll up under a
    parent ``ORG`` node via ``CONTAINS`` so the estate is traversable top-down.

    The account nodes reuse the same ``account:snowflake:<locator>`` id that
    :func:`_add_snowflake_services` (and the rest of the Snowflake graph) emits, so
    the org backbone stitches onto any already-inventoried account graph rather
    than creating a parallel island. When org data is absent or non-ok the call is
    a no-op and the account stays the root — single-account behavior is unchanged.

    Never raises; a non-ok / non-dict payload is a no-op.
    """
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return
    accounts = payload.get("accounts") or []
    if not accounts:
        return
    data_sources = sorted({data_source, "snowflake-organizations"} - {""})
    org_name = _clean_graph_part(payload.get("org_name")) or "organization"
    org_node_id = f"org:snowflake:{org_name}"
    graph.add_node(
        UnifiedNode(
            id=org_node_id,
            entity_type=EntityType.ORG,
            label=f"Snowflake org: {org_name}",
            attributes={
                "org_name": org_name,
                "cloud_provider": "snowflake",
                "account_count": len([a for a in accounts if isinstance(a, dict)]),
            },
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider="snowflake", surface="identity"),
        )
    )

    for member in accounts:
        if not isinstance(member, dict):
            continue
        locator = _clean_graph_part(member.get("locator"))
        if not locator:
            continue
        account_node = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            locator,
            "snowflake",
            data_sources,
            label=_clean_graph_part(member.get("name")) or locator,
            account_id=locator,
            cloud_provider="snowflake",
            account_name=_clean_graph_part(member.get("name")),
            region=_clean_graph_part(member.get("region")),
            edition=_clean_graph_part(member.get("edition")),
            source="snowflake-organizations",
        )
        _add_rel_edge(graph, org_node_id, account_node, RelationshipType.CONTAINS, {"source": "snowflake-organizations"})


def _add_snowflake_integrations(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake account integrations into the graph (external-trust layer).

    Account-owned nodes retain category and enabled configuration for outbound
    connections and federation. SHOW INTEGRATIONS does not establish inbound
    internet reachability, effective authorization or successful data transfer.
    A non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-integrations")
    if prepared is None:
        return
    account, data_sources = prepared
    account_node_id = ""
    if account:
        account_node_id = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            account,
            "snowflake",
            data_sources,
            label=account or "snowflake",
            account_id=account,
            cloud_provider="snowflake",
            source="snowflake-integrations",
        )

    egress_categories = {"STORAGE", "API", "EXTERNAL_ACCESS", "NOTIFICATION", "CATALOG"}
    for integ in payload.get("integrations", []) or []:
        if not isinstance(integ, dict):
            continue
        name = _clean_graph_part(integ.get("name"))
        if not name:
            continue
        category = str(integ.get("category", "") or "").strip().upper().replace(" ", "_")
        enabled = coerce_bool_or_none(integ.get("enabled"))
        node_id = f"cloud_resource:snowflake:integration:{name}"
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"integration: {name}",
                attributes={
                    "resource_name": name,
                    "resource_type": "integration",
                    "resource_kind": "snowflake-integration",
                    "cloud_provider": "snowflake",
                    "integration_type": integ.get("type"),
                    "integration_category": category,
                    "enabled": enabled,
                    "internet_exposed": None,
                    "outbound_access_configured": enabled if category in egress_categories else None,
                    "integration_evidence": {
                        "source": "snowflake-integrations",
                        "basis": "recorded_configuration",
                        "network_direction": "outbound" if category in egress_categories else "not_assessed",
                        "access_outcome": "not_observed",
                        "inputs": sanitize_sensitive_payload({key: integ[key] for key in ("category", "type", "enabled") if key in integ}),
                        **(
                            {"enabled_observation": sanitize_sensitive_payload(integ["enabled_evidence"])}
                            if isinstance(integ.get("enabled_evidence"), dict)
                            else {}
                        ),
                    },
                    "external_access": category == "EXTERNAL_ACCESS",
                    "identity_federation": category == "SECURITY",
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="network"),
            )
        )
        if account_node_id:
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "snowflake-integrations"},
            )


def _add_snowflake_warehouses(lane: _SnowflakeLane, warehouses: Any) -> None:
    for wh in warehouses or []:
        if not isinstance(wh, dict):
            continue
        name = _clean_graph_part(wh.get("name"))
        if not name:
            continue
        lane.own(
            UnifiedNode(
                id=f"cloud_resource:snowflake:warehouse:{name}",
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"warehouse: {name}",
                attributes={
                    "resource_name": name,
                    "resource_type": "warehouse",
                    "resource_kind": "snowflake-warehouse",
                    "cloud_provider": "snowflake",
                    "size": wh.get("size"),
                    "state": wh.get("state"),
                    "auto_suspend": wh.get("auto_suspend"),
                },
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="compute"),
            )
        )


def _add_snowflake_databases(lane: _SnowflakeLane, databases: Any) -> dict[str, str]:
    db_node_by_name: dict[str, str] = {}
    for db in databases or []:
        if not isinstance(db, dict):
            continue
        name = _clean_graph_part(db.get("name"))
        if not name:
            continue
        db_node_by_name[name] = lane.own(
            UnifiedNode(
                id=f"data_store:snowflake:db:{name}",
                entity_type=EntityType.DATA_STORE,
                label=f"database: {name}",
                attributes={
                    "database_name": name,
                    "object_type": "database",
                    "cloud_provider": "snowflake",
                    "is_data_store": True,
                    "is_container": True,
                    "retention_time": db.get("retention_time"),
                },
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
    return db_node_by_name


def _add_snowflake_schemas(lane: _SnowflakeLane, schemas: Any, db_node_by_name: dict[str, str]) -> dict[str, str]:
    schema_node_by_fqn: dict[str, str] = {}
    for sch in schemas or []:
        if not isinstance(sch, dict):
            continue
        fqn = _clean_graph_part(sch.get("fqn"))
        db_name = _clean_graph_part(sch.get("database_name"))
        if not fqn or not db_name:
            continue
        sch_id = f"data_store:snowflake:schema:{fqn}"
        lane.graph.add_node(
            UnifiedNode(
                id=sch_id,
                entity_type=EntityType.DATA_STORE,
                label=f"schema: {fqn}",
                attributes={
                    "fqn": fqn,
                    "object_type": "schema",
                    "database": db_name,
                    "cloud_provider": "snowflake",
                    "is_data_store": True,
                    "is_container": True,
                },
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        schema_node_by_fqn[fqn] = sch_id
        # database CONTAINS schema
        parent_db_id = db_node_by_name.get(db_name)
        if parent_db_id:
            _add_rel_edge(lane.graph, parent_db_id, sch_id, RelationshipType.CONTAINS, {"source": "snowflake-services"})
    return schema_node_by_fqn


def _link_snowflake_objects_to_schemas(graph: UnifiedGraph, schema_node_by_fqn: dict[str, str]) -> None:
    """Link existing object-graph table/view nodes under their schema (schema CONTAINS object)."""
    for node in list(graph.nodes.values()):
        if node.entity_type != EntityType.DATA_STORE:
            continue
        obj_fqn = str(node.attributes.get("fqn") or "")
        # Only DB.SCHEMA.OBJECT (3-part) table/view nodes, not the containers themselves.
        if node.attributes.get("is_container") or obj_fqn.count(".") != 2:
            continue
        parent_schema = obj_fqn.rsplit(".", 1)[0]
        parent_sch_id = schema_node_by_fqn.get(parent_schema)
        if parent_sch_id:
            _add_rel_edge(graph, parent_sch_id, node.id, RelationshipType.CONTAINS, {"source": "snowflake-services"})


def _add_snowflake_services(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake compute + the database/schema containment tree into the graph.

    Completes the object catalog beyond tables/views:

    * **Warehouses** → ``CLOUD_RESOURCE`` (compute) owned by the account.
    * **Databases** → ``DATA_STORE`` container owned by the account.
    * **Schemas** → ``DATA_STORE`` container; the database ``CONTAINS`` the schema.
    * Existing table/view nodes (``data_store:snowflake:DB.SCHEMA.OBJ`` from the
      object graph) are linked under their schema via ``CONTAINS``, so the graph
      renders a navigable DB → schema → table tree instead of a flat owned-by-account list.

    Never raises; missing/empty/non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-services")
    if prepared is None:
        return
    account, data_sources = prepared
    lane = _SnowflakeLane(graph, account, data_sources, "snowflake-services")
    _add_snowflake_warehouses(lane, payload.get("warehouses", []))
    # Database + schema containers, keyed by fqn so table nodes can attach.
    db_node_by_name = _add_snowflake_databases(lane, payload.get("databases", []))
    schema_node_by_fqn = _add_snowflake_schemas(lane, payload.get("schemas", []), db_node_by_name)
    if schema_node_by_fqn:
        _link_snowflake_objects_to_schemas(graph, schema_node_by_fqn)


def _add_snowflake_tasks(lane: _SnowflakeLane, tasks: Any) -> None:
    graph = lane.graph
    for task in tasks or []:
        if not isinstance(task, dict):
            continue
        fqn = _clean_graph_part(task.get("fqn")) or _clean_graph_part(task.get("name"))
        if not fqn:
            continue
        task_id = lane.own(
            UnifiedNode(
                id=f"cloud_resource:snowflake:task:{fqn}",
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"task: {fqn}",
                attributes={
                    "resource_name": fqn,
                    "resource_type": "task",
                    "resource_kind": "snowflake-task",
                    "cloud_provider": "snowflake",
                    "schedule": task.get("schedule"),
                    "state": task.get("state"),
                },
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="compute"),
            )
        )
        warehouse = _clean_graph_part(task.get("warehouse"))
        if warehouse:
            wh_id = f"cloud_resource:snowflake:warehouse:{warehouse}"
            _snowflake_thin_node(lane, wh_id, EntityType.CLOUD_RESOURCE, f"warehouse: {warehouse}", "compute")
            _add_rel_edge(graph, task_id, wh_id, RelationshipType.DEPENDS_ON, {"source": "snowflake-pipeline", "via": "warehouse"})
        owner = _clean_graph_part(task.get("owner"))
        if owner:
            role_id = f"role:snowflake:{owner}"
            _snowflake_thin_node(lane, role_id, EntityType.ROLE, f"role: {owner}", "identity")
            _add_rel_edge(graph, task_id, role_id, RelationshipType.ASSUMES, {"source": "snowflake-pipeline", "runs_as": owner})


def _add_snowflake_streams(lane: _SnowflakeLane, streams: Any) -> None:
    for stream in streams or []:
        if not isinstance(stream, dict):
            continue
        fqn = _clean_graph_part(stream.get("fqn")) or _clean_graph_part(stream.get("name"))
        if not fqn:
            continue
        stream_id = lane.own(
            UnifiedNode(
                id=f"data_store:snowflake:stream:{fqn}",
                entity_type=EntityType.DATA_STORE,
                label=f"stream: {fqn}",
                attributes={
                    "fqn": fqn,
                    "object_type": "stream",
                    "cloud_provider": "snowflake",
                    "is_data_store": True,
                    "stale": bool(stream.get("stale")),
                },
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        source = _clean_graph_part(stream.get("source_fqn"))
        if source:
            src_id = f"data_store:snowflake:{source}"
            _snowflake_thin_node(lane, src_id, EntityType.DATA_STORE, f"object: {source}", "data")
            _add_rel_edge(lane.graph, stream_id, src_id, RelationshipType.DEPENDS_ON, {"source": "snowflake-pipeline", "via": "cdc-source"})


def _add_snowflake_pipes(lane: _SnowflakeLane, pipes: Any) -> None:
    for pipe in pipes or []:
        if not isinstance(pipe, dict):
            continue
        fqn = _clean_graph_part(pipe.get("fqn")) or _clean_graph_part(pipe.get("name"))
        if not fqn:
            continue
        pipe_id = lane.own(
            UnifiedNode(
                id=f"cloud_resource:snowflake:pipe:{fqn}",
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"pipe: {fqn}",
                attributes={
                    "resource_name": fqn,
                    "resource_type": "pipe",
                    "resource_kind": "snowflake-pipe",
                    "cloud_provider": "snowflake",
                    "auto_ingest": bool(pipe.get("auto_ingest")),
                    "integration": pipe.get("integration"),
                },
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        stage = _clean_graph_part(pipe.get("stage"))
        if stage:
            stage_name = stage.split(".")[-1]
            stage_id = f"cloud_resource:snowflake:stage:{stage_name}"
            _snowflake_thin_node(lane, stage_id, EntityType.CLOUD_RESOURCE, f"external stage: {stage_name}", "data")
            _add_rel_edge(
                lane.graph, pipe_id, stage_id, RelationshipType.DEPENDS_ON, {"source": "snowflake-pipeline", "via": "ingest-stage"}
            )


def _add_snowflake_pipeline(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake data-pipeline + automation objects into the graph.

    * **Tasks** → ``CLOUD_RESOURCE`` (automation); ``DEPENDS_ON`` the warehouse
      it runs on, ``ASSUMES`` the owner role (privilege surface).
    * **Streams** → ``DATA_STORE``; ``DEPENDS_ON`` the source table it tracks.
    * **Pipes** → ``CLOUD_RESOURCE`` (ingestion); ``DEPENDS_ON`` the stage it
      reads from — which the exfil layer links onward to the actual cloud bucket,
      so the ingress path is traversable end to end.

    Endpoints (warehouse/table/stage) may already exist from other layers; a thin
    node is created only when absent. Never raises; non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-pipeline")
    if prepared is None:
        return
    account, data_sources = prepared
    lane = _SnowflakeLane(graph, account, data_sources, "snowflake-pipeline")
    _add_snowflake_tasks(lane, payload.get("tasks", []))
    _add_snowflake_streams(lane, payload.get("streams", []))
    _add_snowflake_pipes(lane, payload.get("pipes", []))
