"""Cloud evidence normalization and identity context shared by graph projections.

These helpers preserve recorded provider inputs, unknown exposure and ownership
semantics. They do not query providers or establish effective authorization.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.cloud.aws_iam_evidence import EvidenceCompleteness, normalize_iam_policy_document
from agent_bom.cloud.normalization import coerce_bool_or_none
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.identity_nodes import identity_node_id as _identity_node_id
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge, _normalized_environment
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part
from agent_bom.security import sanitize_sensitive_payload

_PRINCIPAL_TYPE_TO_ENTITY: dict[str, EntityType] = {
    "account": EntityType.ACCOUNT,
    "aws-account": EntityType.ACCOUNT,
    "cloud-account": EntityType.ACCOUNT,
    "federated": EntityType.FEDERATED_IDENTITY,
    "federated-identity": EntityType.FEDERATED_IDENTITY,
    "federated-user": EntityType.FEDERATED_IDENTITY,
    "group": EntityType.GROUP,
    "iam-role": EntityType.ROLE,
    "managed-identity": EntityType.MANAGED_IDENTITY,
    "oidc": EntityType.FEDERATED_IDENTITY,
    "policy": EntityType.POLICY,
    "role": EntityType.ROLE,
    "saml": EntityType.FEDERATED_IDENTITY,
    "service-account": EntityType.SERVICE_ACCOUNT,
    "service-principal": EntityType.SERVICE_PRINCIPAL,
    "serviceprincipal": EntityType.SERVICE_PRINCIPAL,
    "user": EntityType.USER,
}


def _identity_entity_type(raw_type: Any) -> EntityType:
    principal_type = _clean_graph_part(raw_type).lower().replace("_", "-").replace(" ", "-")
    return _PRINCIPAL_TYPE_TO_ENTITY.get(principal_type, EntityType.SERVICE_ACCOUNT)


def _first_cloud_scope_value(scope: dict[str, Any], *keys: str) -> tuple[str, str]:
    for key in keys:
        value = _clean_graph_part(scope.get(key))
        if value:
            return key, value
    return "", ""


def _policy_entries(principal: dict[str, Any]) -> list[dict[str, Any]]:
    raw_policies = principal.get("policies") or principal.get("attached_policies") or principal.get("policy_ids") or []
    if isinstance(raw_policies, (str, bytes)):
        raw_policies = [raw_policies]
    if not isinstance(raw_policies, list):
        return []

    policies: list[dict[str, Any]] = []
    for raw_policy in raw_policies:
        privilege_level = "unknown"
        document: Any = None
        if isinstance(raw_policy, dict):
            policy_id = _clean_graph_part(raw_policy.get("policy_id")) or _clean_graph_part(raw_policy.get("arn"))
            policy_name = _clean_graph_part(raw_policy.get("policy_name")) or _clean_graph_part(raw_policy.get("name")) or policy_id
            privilege_level = str(raw_policy.get("privilege_level") or "unknown")
            # Discovery may carry the raw IAM policy document (``policy_document``,
            # or the AWS API ``PolicyDocument``); pass it through so the POLICY node
            # can carry it and the effective-permissions overlay can evaluate it.
            document = raw_policy.get("policy_document")
            if document is None:
                document = raw_policy.get("PolicyDocument")
        else:
            policy_id = _clean_graph_part(raw_policy)
            policy_name = policy_id
        if policy_id:
            entry: dict[str, Any] = {"id": policy_id, "name": policy_name or policy_id, "privilege_level": privilege_level}
            if isinstance(document, dict) and document:
                entry["policy_document"] = document
            policies.append(entry)
    return policies


def _policy_document_attrs(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Return ``{"policy_document": <doc>}`` for a parseable IAM policy, else ``{}``.

    The raw document is what the effective-permissions overlay expects on the
    POLICY node — it re-normalizes at evaluation time. We validate here with
    ``normalize_iam_policy_document`` and only attach documents that parse to at
    least one statement, so unparseable/empty payloads never bloat the graph.
    """
    document = policy.get("policy_document")
    if not isinstance(document, Mapping) or not document:
        return {}
    if normalize_iam_policy_document(document).completeness is EvidenceCompleteness.UNAVAILABLE:
        return {}
    return {"policy_document": dict(document)}


def _trust_entries(principal: dict[str, Any]) -> list[dict[str, str]]:
    raw_trusts = principal.get("trust_principals") or []
    if isinstance(raw_trusts, dict):
        raw_trusts = [raw_trusts]
    if not isinstance(raw_trusts, list):
        return []

    trusts: list[dict[str, str]] = []
    for raw_trust in raw_trusts:
        if not isinstance(raw_trust, dict):
            continue
        principal_id = _clean_graph_part(raw_trust.get("principal_id")) or _clean_graph_part(raw_trust.get("arn"))
        if not principal_id:
            continue
        trusts.append(
            {
                "id": principal_id,
                "name": _clean_graph_part(raw_trust.get("principal_name")) or principal_id,
                "type": _clean_graph_part(raw_trust.get("principal_type")) or "federated-identity",
                "relationship": _clean_graph_part(raw_trust.get("relationship")) or "trusts",
                "source_field": _clean_graph_part(raw_trust.get("source_field")),
            }
        )
    return trusts


def _prepare_cloud_payload(payload: Any, data_source: str, *tags: str) -> tuple[str, list[str]] | None:
    """Shared guard for the cloud ``_add_*`` layers.

    Returns ``None`` when *payload* is not a status-ok dict (the universal no-op
    guard), otherwise ``(account, data_sources)`` where ``account`` is the
    cleaned ``account`` field and ``data_sources`` is the sorted, blank-stripped
    union of *data_source* and *tags*.
    """
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return None
    account = _clean_graph_part(payload.get("account"))
    data_sources = sorted({data_source, *tags} - {""})
    return account, data_sources


def _add_identity_node(
    graph: UnifiedGraph,
    entity_type: EntityType,
    identity_id: str,
    provider: str,
    data_sources: list[str],
    *,
    label: str | None = None,
    surface: str = "identity",
    **attrs: Any,
) -> str:
    """Add an identity-surface node (account/role/user/OU/...) and return its id.

    Mirrors the repeated cloud identity-node construction: id from
    ``_identity_node_id``, ``surface`` dimensions on *provider* (default
    ``"identity"``), and the caller's attributes verbatim. The ``cloud_provider``
    attribute is passed as a keyword like any other (it is *not* derived from
    *provider*) so call sites stay byte-identical.
    """
    node_id = _identity_node_id(entity_type, provider, identity_id)
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=entity_type,
            label=label if label is not None else identity_id,
            attributes=attrs,
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider=provider, surface=surface),
        )
    )
    return node_id


def _environment_from_tags(tags: object) -> str:
    """Promote common cloud tag keys onto the environment dimension."""
    if not isinstance(tags, dict):
        return ""
    for key in ("environment", "Environment", "env", "Env", "ENVIRONMENT"):
        if key in tags:
            return _normalized_environment(tags.get(key))
    return ""


def _resource_environment(item: object) -> str:
    """Return the environment a cloud resource is tagged/labelled with.

    ``environment`` is a first-class leg of the estate hierarchy
    (provider / account / region / environment) and is what
    :func:`agent_bom.graph.scope.select_observed_scope` and
    ``/v1/inventory?environment=`` key off. Every provider spells the key/value
    metadata that carries it differently: AWS and Azure use ``tags``, GCP uses
    ``labels``. Reading only ``tags`` made the environment drill-down return
    Azure's estate while silently dropping the identically-tagged AWS and GCP
    one.

    GCE ``network_tags`` is deliberately NOT consulted — those are firewall
    targeting labels (a bare list, no values), not resource metadata.
    """
    if not isinstance(item, dict):
        return ""
    return _environment_from_tags(item.get("tags")) or _environment_from_tags(item.get("labels"))


def _add_account_resource_hierarchy(
    graph: UnifiedGraph,
    account_node_id: str,
    resource_node_id: str,
    *,
    evidence: dict[str, Any] | None = None,
) -> None:
    """Link account → resource as both ``OWNS`` and ``CONTAINS``.

    Cloud inventory and Snowflake object layers historically emitted ``OWNS``
    only. Estate rollup special-cases that edge, but attack-path fusion and cost
    subtrees walk ``CONTAINS``. Dual-emit keeps ownership semantics while making
    the account hierarchy traversable for kill-chains — matching cloud-origin
    lineage which already emits ``CONTAINS``.
    """
    if not account_node_id or not resource_node_id:
        return
    payload = dict(evidence or {})
    _add_rel_edge(graph, account_node_id, resource_node_id, RelationshipType.OWNS, payload)
    contains_evidence = {**payload, "hierarchy": "account_contains_resource"}
    _add_rel_edge(graph, account_node_id, resource_node_id, RelationshipType.CONTAINS, contains_evidence)
    _stamp_owning_account(graph, account_node_id, resource_node_id)


def _stamp_owning_account(graph: UnifiedGraph, account_node_id: str, resource_node_id: str) -> None:
    """Copy the owning account's id onto a resource that lacks it.

    ``account_id`` is the attribute :func:`agent_bom.graph.scope.select_observed_scope`
    matches for ``kind="account"``, so a resource without it drops out of the
    org → account → resource drill-down even though the graph holds an explicit
    ``OWNS``/``CONTAINS`` edge proving the membership. The cloud-inventory loops
    set it inline; the Snowflake object/services/pipeline layers did not, which
    collapsed the Snowflake account view to the bare ACCOUNT node.

    Derived only from the persisted ownership edge just written — never guessed —
    and never overwrites an id the emitting lane already set.
    """
    account = graph.nodes.get(account_node_id)
    resource = graph.nodes.get(resource_node_id)
    if account is None or resource is None:
        return
    account_id = _clean_graph_part(account.attributes.get("account_id"))
    if not account_id or _clean_graph_part(resource.attributes.get("account_id")):
        return
    resource.attributes["account_id"] = account_id


def _iter_cloud_inventories(raw: Any) -> list[dict[str, Any]]:
    """Yield each cloud-inventory payload from a single dict or a list.

    The ``cloud_inventory`` report section may carry one provider's payload
    (AWS, the original shape) or a list of per-provider payloads (AWS + Azure +
    GCP). Non-dict entries are ignored.
    """
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    return []


def _recorded_exposure_attributes(record: Mapping[str, Any], *fields: str) -> dict[str, Any]:
    """Preserve provider flag inputs and keep absent/unknown observations nullable."""
    inputs = {name: record[name] for name in fields if name in record}
    values = [coerce_bool_or_none(value) for value in inputs.values()]
    exposed = True if True in values else False if values and all(value is False for value in values) else None
    return {
        "internet_exposed": exposed,
        "internet_exposure_evidence": {
            "source": "cloud-inventory",
            "basis": "recorded_attributes",
            "inputs": sanitize_sensitive_payload(inputs),
        },
    }


def _normalize_cloud_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    """Map a per-provider inventory payload onto the canonical builder shape.

    AWS payloads already use the canonical keys (``buckets`` / ``instances`` /
    ``security_groups`` / ``roles`` / ``users``). Azure and GCP payloads carry
    provider-native keys (``storage_accounts`` / ``firewalls`` /
    ``managed_identities`` / ``service_accounts`` …); this translates them into
    the same lists, tagging each resource with ``_service`` / ``_kind`` /
    ``_label`` / ``_resource_type`` so node IDs and the CNAPP data-store keyword
    match stay provider-accurate. Unknown providers pass through untouched.
    """
    provider = _clean_graph_part(inventory.get("provider")).lower()
    if provider == "azure":
        return _normalize_azure_inventory(inventory)
    if provider == "gcp":
        return _normalize_gcp_inventory(inventory)
    return inventory


def _normalize_azure_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    """Translate an Azure inventory payload into the canonical builder shape."""
    buckets: list[dict[str, Any]] = []
    for account in inventory.get("storage_accounts", []) or []:
        if not isinstance(account, dict):
            continue
        buckets.append(
            {
                **account,
                "_service": "storage",
                "_kind": "azure-storage-account",
                # "storage account" is a CNAPP data-store keyword.
                "_label": "storage account",
            }
        )
    groups: list[dict[str, Any]] = []
    for nsg in inventory.get("security_groups", []) or []:
        if not isinstance(nsg, dict):
            continue
        groups.append({**nsg, "_service": "network", "_kind": "azure-nsg", "_resource_type": "network-security-group"})
    instances: list[dict[str, Any]] = []
    for vm in inventory.get("instances", []) or []:
        if not isinstance(vm, dict):
            continue
        instances.append({**vm, "_service": "compute", "_kind": "azure-vm", "_label": "vm"})
    principals = [p for p in inventory.get("managed_identities", []) or [] if isinstance(p, dict)]
    principals.extend(p for p in inventory.get("service_principals", []) or [] if isinstance(p, dict))
    identity_groups = [g for g in inventory.get("entra_groups", []) or [] if isinstance(g, dict)]
    return {
        **inventory,
        "buckets": buckets,
        "security_groups": groups,
        "instances": instances,
        "roles": [],
        "users": principals,
        "groups": identity_groups,
    }


def _normalize_gcp_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    """Translate a GCP inventory payload into the canonical builder shape."""
    buckets: list[dict[str, Any]] = []
    for bucket in inventory.get("buckets", []) or []:
        if not isinstance(bucket, dict):
            continue
        # "bucket" is already a CNAPP data-store keyword; keep gcs service tag.
        buckets.append({**bucket, "_service": "gcs", "_kind": "gcs-bucket", "_label": "gcs bucket"})
    groups: list[dict[str, Any]] = []
    for firewall in inventory.get("firewalls", []) or []:
        if not isinstance(firewall, dict):
            continue
        groups.append({**firewall, "_service": "compute", "_kind": "gcp-firewall", "_resource_type": "firewall"})
    instances: list[dict[str, Any]] = []
    for instance in inventory.get("instances", []) or []:
        if not isinstance(instance, dict):
            continue
        instances.append({**instance, "_service": "compute", "_kind": "gce-instance", "_label": "gce"})
    principals = [p for p in inventory.get("service_accounts", []) or [] if isinstance(p, dict)]
    identity_groups = [g for g in inventory.get("groups", []) or [] if isinstance(g, dict)]
    return {
        **inventory,
        "buckets": buckets,
        "security_groups": groups,
        "instances": instances,
        "roles": [],
        "users": principals,
        "groups": identity_groups,
    }
