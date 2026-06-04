"""Cloud-CNAPP enrichment: internet exposure, data stores, and toxic chains.

Moves the graph toward Wiz/Orca/CrowdStrike attack-path grade by deriving
network-exposure and data-at-rest structure from signals already in the graph
(CIS/IaC misconfigurations + cloud resources), without needing new scanner
inputs:

- Cloud resources flagged public/internet-reachable by a misconfiguration are
  marked ``internet_exposed`` and linked ``EXPOSED_TO`` the data stores they can
  reach.
- Data-store-like cloud resources (buckets, databases, lakes, warehouses) gain a
  ``DATA_STORE`` companion node via ``STORES`` so path-to-sensitive-data is
  traversable.
- An exposed + vulnerable resource is recorded as a toxic combination — the
  classic "internet-reachable and exploitable" chain.
"""

from __future__ import annotations

from agent_bom.graph.container import InteractionRisk, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus, RelationshipType

_OVERLAY_SOURCE = "cnapp-overlay"

# Keywords that, in a misconfiguration label/finding, indicate public exposure.
_EXPOSURE_KEYWORDS = (
    "public",
    "0.0.0.0/0",
    "::/0",
    "internet",
    "anonymous",
    "unauthenticated",
    "publicly accessible",
    "world-readable",
    "open to the world",
    "allow_all",
)

# Keywords that mark a cloud resource as a data store.
_DATA_STORE_KEYWORDS = (
    "s3",
    "bucket",
    "blob",
    "storage account",
    "rds",
    "database",
    "dynamodb",
    "cosmos",
    "datalake",
    "data lake",
    "bigquery",
    "redshift",
    "snowflake",
    "warehouse",
    "gcs",
    "cloud storage",
    "efs",
    "filestore",
)


def _text_of(node: UnifiedNode) -> str:
    parts = [node.label]
    for key in ("description", "rule", "rule_id", "title", "resource_type", "service", "name"):
        val = node.attributes.get(key)
        if isinstance(val, str):
            parts.append(val)
    return " ".join(parts).lower()


def _matches(text: str, keywords: tuple[str, ...]) -> bool:
    return any(kw in text for kw in keywords)


def apply_cnapp_overlay(graph: UnifiedGraph) -> dict[str, int]:
    """Enrich ``graph`` with exposure + data-store structure in place.

    Returns counts of exposed nodes, data stores, and toxic combinations added.
    Never raises into the builder.
    """
    nodes = list(graph.nodes.values())
    cloud_resources = [n for n in nodes if n.entity_type in (EntityType.CLOUD_RESOURCE, EntityType.RESOURCE, EntityType.SERVER)]
    misconfigs = [n for n in nodes if n.entity_type == EntityType.MISCONFIGURATION]

    # Resource id → set of vulnerability node ids affecting it (via VULNERABLE_TO).
    vulnerable_resources: set[str] = set()
    for edge in graph.edges:
        if edge.relationship == RelationshipType.VULNERABLE_TO:
            vulnerable_resources.add(edge.source)

    # Map a misconfiguration to the resources it AFFECTS so exposure can attach
    # to the real asset rather than the finding node.
    affected_by_misconfig: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.relationship == RelationshipType.AFFECTS:
            affected_by_misconfig.setdefault(edge.source, []).append(edge.target)

    exposed_ids: set[str] = set()
    for mc in misconfigs:
        if not _matches(_text_of(mc), _EXPOSURE_KEYWORDS):
            continue
        for target_id in affected_by_misconfig.get(mc.id, []):
            node = graph.nodes.get(target_id)
            if node is not None:
                node.attributes["internet_exposed"] = True
                exposed_ids.add(target_id)
    # Also mark cloud resources whose own attributes/label signal public exposure.
    for node in cloud_resources:
        if node.attributes.get("internet_exposed") or _matches(_text_of(node), _EXPOSURE_KEYWORDS):
            node.attributes["internet_exposed"] = True
            exposed_ids.add(node.id)

    # Classify data stores and attach a DATA_STORE companion node.
    data_stores_added = 0
    data_store_for_resource: dict[str, str] = {}
    for node in cloud_resources:
        if node.entity_type == EntityType.SERVER:
            continue
        if not _matches(_text_of(node), _DATA_STORE_KEYWORDS):
            continue
        ds_id = f"data_store:{node.id}"
        data_store_for_resource[node.id] = ds_id
        if ds_id not in graph.nodes:
            graph.add_node(
                UnifiedNode(
                    id=ds_id,
                    entity_type=EntityType.DATA_STORE,
                    label=f"data: {node.label}",
                    severity="info",
                    data_sources=[_OVERLAY_SOURCE],
                    attributes={"backed_by": node.id, "internet_exposed": bool(node.attributes.get("internet_exposed"))},
                )
            )
            data_stores_added += 1
        graph.add_edge(
            UnifiedEdge(
                source=node.id,
                target=ds_id,
                relationship=RelationshipType.STORES,
                provenance={"source": _OVERLAY_SOURCE},
            )
        )

    # EXPOSED_TO: an internet-exposed resource reaches the data stores it backs.
    for resource_id in exposed_ids:
        exposed_ds = data_store_for_resource.get(resource_id)
        if exposed_ds:
            graph.add_edge(
                UnifiedEdge(
                    source=resource_id,
                    target=exposed_ds,
                    relationship=RelationshipType.EXPOSED_TO,
                    weight=6.0,
                    provenance={"source": _OVERLAY_SOURCE},
                    evidence={"reason": "internet_exposed_data_store"},
                )
            )

    # Toxic combinations: internet-exposed AND vulnerable.
    toxic = 0
    for resource_id in sorted(exposed_ids & vulnerable_resources):
        node = graph.nodes.get(resource_id)
        if node is None:
            continue
        node.attributes["toxic_exposed_vulnerable"] = True
        if node.risk_score < 9.0:
            node.risk_score = 9.0
        node.status = NodeStatus.VULNERABLE
        graph.interaction_risks.append(
            InteractionRisk(
                pattern="internet_exposed_vulnerable",
                agents=[node.label],
                risk_score=9.5,
                description=f"{node.label} is internet-exposed and carries a known vulnerability (toxic combination).",
                owasp_agentic_tag=None,
            )
        )
        toxic += 1

    return {"exposed_nodes": len(exposed_ids), "data_stores_added": data_stores_added, "toxic_combinations": toxic}
