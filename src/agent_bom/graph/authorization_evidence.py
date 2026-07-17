"""Project proven Azure/GCP authorization decisions into the unified graph.

The provider collectors and normalizers own evidence completeness.  This module
only emits traversable graph edges when the fail-closed evaluator returns an
explicit ``ALLOW`` for a concrete action and resource.  Partial, conditional,
stale, truncated, or otherwise unresolved evidence is retained as a typed graph
analysis status and never converted into reachability.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.cloud.authorization_evaluator import evaluate_authorization
from agent_bom.cloud.authorization_evidence import (
    AuthorizationBinding,
    AuthorizationDecision,
    AuthorizationEvidenceBundle,
    AuthorizationPlane,
    AuthorizationProvider,
    AuthorizationRequest,
)
from agent_bom.cloud.azure_rbac_evidence import normalize_azure_rbac_inventory
from agent_bom.cloud.gcp_iam_evidence import normalize_gcp_iam_inventory
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

_SOURCE = "authorization-evidence"
_MAX_EVALUATIONS = 100_000

_PRINCIPAL_TYPES: dict[str, EntityType] = {
    "group": EntityType.GROUP,
    "managedidentity": EntityType.MANAGED_IDENTITY,
    "managed-identity": EntityType.MANAGED_IDENTITY,
    "public": EntityType.FEDERATED_IDENTITY,
    "serviceaccount": EntityType.SERVICE_ACCOUNT,
    "service-account": EntityType.SERVICE_ACCOUNT,
    "serviceprincipal": EntityType.SERVICE_PRINCIPAL,
    "service-principal": EntityType.SERVICE_PRINCIPAL,
    "user": EntityType.USER,
}

_PRINCIPAL_PREFIX: dict[EntityType, str] = {
    EntityType.GROUP: "group",
    EntityType.MANAGED_IDENTITY: "managed_identity",
    EntityType.FEDERATED_IDENTITY: "federated_identity",
    EntityType.SERVICE_ACCOUNT: "service_account",
    EntityType.SERVICE_PRINCIPAL: "service_principal",
    EntityType.USER: "user",
}


def has_authoritative_authorization_evidence(inventory: Any) -> bool:
    """Return whether *inventory* carries the authoritative collector contract."""
    if not isinstance(inventory, Mapping):
        return False
    provider = str(inventory.get("provider") or "").strip().lower()
    marker = inventory.get("authorization_evidence")
    if not isinstance(marker, Mapping):
        return False
    if provider == AuthorizationProvider.AZURE.value:
        return isinstance(inventory.get("authorization_sources"), list)
    if provider == AuthorizationProvider.GCP.value:
        return isinstance(inventory.get("iam_sources"), list)
    return False


def _bundle(inventory: Mapping[str, Any]) -> AuthorizationEvidenceBundle | None:
    provider = str(inventory.get("provider") or "").strip().lower()
    if provider == AuthorizationProvider.AZURE.value:
        return normalize_azure_rbac_inventory(inventory)
    if provider == AuthorizationProvider.GCP.value:
        return normalize_gcp_iam_inventory(inventory)
    return None


def _principal_type(binding: AuthorizationBinding) -> EntityType:
    key = binding.principal_type.strip().lower().replace("_", "")
    return _PRINCIPAL_TYPES.get(key, EntityType.SERVICE_ACCOUNT)


def _principal_node(graph: UnifiedGraph, binding: AuthorizationBinding, provider: str) -> str:
    principal_id = binding.principal_id.strip()
    normalized = _principal_aliases(principal_id)
    for node in graph.nodes.values():
        if str(node.attributes.get("cloud_provider") or "").casefold() != provider:
            continue
        candidates: set[str] = set()
        for key in ("principal_id", "principal_name", "directory_principal_id", "principal_email"):
            candidates.update(_principal_aliases(str(node.attributes.get(key) or "")))
        if normalized & candidates:
            return node.id

    entity_type = _principal_type(binding)
    prefix = _PRINCIPAL_PREFIX.get(entity_type, "identity")
    node_id = f"{prefix}:{provider}:{principal_id}"
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=entity_type,
            label=principal_id,
            attributes={
                "principal_id": principal_id,
                "principal_type": binding.principal_type,
                "cloud_provider": provider,
                "authorization_evidence_state": "observed",
            },
            data_sources=[_SOURCE],
            dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
        )
    )
    return node_id


def _principal_aliases(value: str) -> set[str]:
    normalized = value.strip().casefold()
    if not normalized:
        return set()
    aliases = {normalized}
    prefix, separator, suffix = normalized.partition(":")
    if separator and prefix in {"group", "serviceaccount", "user"} and suffix:
        aliases.add(suffix)
    return aliases


def _canonical_resource(node: UnifiedNode, bundle: AuthorizationEvidenceBundle) -> str:
    resource_id = str(node.attributes.get("resource_id") or "").strip().rstrip("/")
    if node.entity_type is EntityType.ACCOUNT:
        account_id = str(node.attributes.get("account_id") or "").strip()
        if bundle.provider is AuthorizationProvider.AZURE and account_id:
            return f"/subscriptions/{account_id}"
        if bundle.provider is AuthorizationProvider.GCP and account_id:
            return f"projects/{account_id}"
    if bundle.provider is AuthorizationProvider.AZURE:
        return resource_id if resource_id.casefold().startswith("/subscriptions/") else ""
    return resource_id if resource_id.startswith(("projects/", "folders/", "organizations/", "//")) else ""


def _resource_nodes(graph: UnifiedGraph, bundle: AuthorizationEvidenceBundle) -> list[tuple[UnifiedNode, str]]:
    provider = bundle.provider.value
    candidates: list[tuple[UnifiedNode, str]] = []
    for node in graph.nodes.values():
        if node.entity_type not in {EntityType.ACCOUNT, EntityType.CLOUD_RESOURCE, EntityType.DATA_STORE, EntityType.RESOURCE}:
            continue
        if str(node.attributes.get("cloud_provider") or "").strip().lower() != provider:
            continue
        resource = _canonical_resource(node, bundle)
        if resource:
            candidates.append((node, resource))
    return sorted(candidates, key=lambda item: item[0].id)


def _permission_values(bundle: AuthorizationEvidenceBundle, binding: AuthorizationBinding) -> tuple[str, ...]:
    role = bundle.role_definition(binding.role_id) if binding.role_id else None
    values = binding.permissions + binding.data_permissions + (role.permissions if role else ()) + (role.data_permissions if role else ())
    return tuple(sorted({value.strip() for value in values if value.strip()}))


def _service_tokens(node: UnifiedNode) -> set[str]:
    attrs = node.attributes
    return {
        str(attrs.get("cloud_service") or "").strip().lower(),
        str(attrs.get("resource_type") or "").strip().lower(),
        str(attrs.get("resource_kind") or "").strip().lower(),
        node.label.lower(),
    }


def _action_relevant(provider: AuthorizationProvider, action: str, node: UnifiedNode) -> bool:
    """Conservatively associate a provider action with its resource family."""
    tokens = " ".join(_service_tokens(node))
    if node.entity_type is EntityType.ACCOUNT:
        if provider is AuthorizationProvider.AZURE:
            return action.casefold().startswith(("microsoft.resources/", "microsoft.authorization/"))
        return action.startswith("resourcemanager.")
    if provider is AuthorizationProvider.AZURE:
        namespace = action.partition("/")[0].casefold().removeprefix("microsoft.")
        aliases = {
            "storage": ("storage", "bucket", "disk"),
            "compute": ("compute", "vm", "instance", "disk"),
            "keyvault": ("key vault", "secret"),
            "containerregistry": ("registry",),
            "containerservice": ("kubernetes", "container"),
            "sql": ("database", "sql"),
            "network": ("network", "firewall", "load balancer", "public ip"),
            "managedidentity": ("identity",),
        }
        return any(alias in tokens for alias in aliases.get(namespace, (namespace,)))
    service = action.partition(".")[0].lower()
    aliases = {
        "storage": ("gcs", "storage", "bucket", "disk"),
        "compute": ("compute", "instance", "disk", "network", "firewall"),
        "container": ("gke", "container", "kubernetes"),
        "run": ("cloud run", "function"),
        "cloudfunctions": ("cloud function", "function"),
        "cloudsql": ("cloud sql", "database"),
        "pubsub": ("pubsub", "messaging"),
    }
    return any(alias in tokens for alias in aliases.get(service, (service,)))


def _concrete_actions(bundle: AuthorizationEvidenceBundle, binding: AuthorizationBinding, node: UnifiedNode) -> tuple[str, ...]:
    permissions = _permission_values(bundle, binding)
    # Exact permissions are directly provable. Wildcards are not requests, so
    # probe a small provider/resource-specific catalog only when the evaluator
    # can verify that concrete probe against the wildcard and all deny/boundary
    # evidence. This keeps the edge concrete and reviewable.
    exact = {action for action in permissions if "*" not in action and _action_relevant(bundle.provider, action, node)}
    probes = _RESOURCE_PROBES.get(bundle.provider, ())
    for action in probes:
        if not _action_relevant(bundle.provider, action, node):
            continue
        if any(_pattern_allows(bundle.provider, action, pattern) for pattern in permissions if "*" in pattern):
            exact.add(action)
    return tuple(sorted(exact))


def _pattern_allows(provider: AuthorizationProvider, action: str, pattern: str) -> bool:
    from fnmatch import fnmatchcase

    if provider is AuthorizationProvider.AZURE:
        return fnmatchcase(action.casefold(), pattern.casefold())
    return fnmatchcase(action, pattern)


_RESOURCE_PROBES: dict[AuthorizationProvider, tuple[str, ...]] = {
    AuthorizationProvider.AZURE: (
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/virtualMachines/write",
        "Microsoft.KeyVault/vaults/read",
        "Microsoft.Storage/storageAccounts/listKeys/action",
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Storage/storageAccounts/write",
    ),
    AuthorizationProvider.GCP: (
        "cloudsql.instances.get",
        "compute.instances.get",
        "compute.instances.setIamPolicy",
        "container.clusters.get",
        "pubsub.topics.get",
        "resourcemanager.projects.get",
        "resourcemanager.projects.setIamPolicy",
        "storage.buckets.get",
        "storage.objects.create",
        "storage.objects.get",
    ),
}

_ASSUME_PROBES: dict[AuthorizationProvider, tuple[str, ...]] = {
    AuthorizationProvider.AZURE: ("Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",),
    AuthorizationProvider.GCP: ("iam.serviceAccounts.actAs",),
}


def _assumable_principals(
    graph: UnifiedGraph,
    bundle: AuthorizationEvidenceBundle,
) -> list[tuple[UnifiedNode, str]]:
    candidates: list[tuple[UnifiedNode, str]] = []
    for node in graph.nodes.values():
        if str(node.attributes.get("cloud_provider") or "").strip().lower() != bundle.provider.value:
            continue
        principal_id = str(node.attributes.get("principal_id") or "").strip()
        if bundle.provider is AuthorizationProvider.GCP and node.entity_type is EntityType.SERVICE_ACCOUNT:
            email = str(node.attributes.get("principal_email") or "").strip()
            if not email and "@" in principal_id:
                email = principal_id.removeprefix("serviceAccount:")
            if email:
                candidates.append((node, f"{bundle.scope.rstrip('/')}/serviceAccounts/{email}"))
        elif bundle.provider is AuthorizationProvider.AZURE and node.entity_type is EntityType.MANAGED_IDENTITY:
            resource_id = str(node.attributes.get("principal_resource_id") or "").strip()
            if resource_id.casefold().startswith("/subscriptions/"):
                candidates.append((node, resource_id.rstrip("/")))
    return sorted(candidates, key=lambda item: item[0].id)


def _assume_actions(bundle: AuthorizationEvidenceBundle, binding: AuthorizationBinding) -> tuple[str, ...]:
    permissions = _permission_values(bundle, binding)
    actions: set[str] = set()
    for probe in _ASSUME_PROBES[bundle.provider]:
        if probe in permissions or any(_pattern_allows(bundle.provider, probe, pattern) for pattern in permissions if "*" in pattern):
            actions.add(probe)
    return tuple(sorted(actions))


def apply_authorization_evidence(graph: UnifiedGraph, inventory: Any) -> dict[str, int]:
    """Emit evaluator-proven access edges and a secret-safe execution status."""
    if not has_authoritative_authorization_evidence(inventory):
        return {}
    assert isinstance(inventory, Mapping)
    bundle = _bundle(inventory)
    if bundle is None:
        return {}

    evaluated = 0
    allow_edges = 0
    denied = 0
    indeterminate = 0
    unmapped = 0
    capped = False
    seen_requests: set[tuple[str, str, str]] = set()
    resources = _resource_nodes(graph, bundle)
    assumable_principals = _assumable_principals(graph, bundle)
    provider = bundle.provider.value

    for binding in bundle.bindings:
        if binding.effect.value != "allow":
            continue
        principal_node_id = _principal_node(graph, binding, provider)
        matched_resource = False
        assume_actions = _assume_actions(bundle, binding)
        for resource_node, resource in resources:
            actions = _concrete_actions(bundle, binding, resource_node)
            if not actions:
                continue
            matched_resource = True
            for action in actions:
                key = (binding.principal_id.casefold(), action.casefold(), resource.casefold())
                if key in seen_requests:
                    continue
                if evaluated >= _MAX_EVALUATIONS:
                    capped = True
                    break
                seen_requests.add(key)
                evaluated += 1
                result = evaluate_authorization(
                    bundle,
                    AuthorizationRequest(
                        provider=bundle.provider,
                        principal_id=binding.principal_id,
                        action=action,
                        resource=resource,
                        # ANY evaluates both control- and data-plane grants. The
                        # provider normalizers already preserve those planes;
                        # classifying a GCP permission name by string would lose
                        # valid storage data access because GCP roles expose one
                        # unified permission list.
                        plane=AuthorizationPlane.ANY,
                    ),
                )
                if result.decision is AuthorizationDecision.ALLOW:
                    before = len(graph.edges)
                    graph.add_edge(
                        UnifiedEdge(
                            source=principal_node_id,
                            target=resource_node.id,
                            relationship=RelationshipType.CAN_ACCESS,
                            weight=4.0,
                            confidence=1.0,
                            provenance={"source": _SOURCE},
                            evidence={
                                "source": _SOURCE,
                                "provider": provider,
                                "decision": result.decision.value,
                                "action": action,
                                "resource": resource,
                                "binding_ids": list(result.matched_allow_bindings),
                                "observed_at": bundle.observed_at.isoformat() if bundle.observed_at else None,
                            },
                        )
                    )
                    if len(graph.edges) > before:
                        allow_edges += 1
                elif result.decision in {AuthorizationDecision.EXPLICIT_DENY, AuthorizationDecision.IMPLICIT_DENY}:
                    denied += 1
                else:
                    indeterminate += 1
            if capped:
                break
        if not matched_resource and not assume_actions:
            unmapped += 1
        if capped:
            break

        # A provider-native impersonation primitive is the only authorization
        # evidence that becomes ASSUMES. Role names, owner labels, and broad
        # admin classifications never create this escalation hop.
        for action in assume_actions:
            for target_node, resource in assumable_principals:
                if target_node.id == principal_node_id:
                    continue
                key = (binding.principal_id.casefold(), action.casefold(), resource.casefold())
                if key in seen_requests:
                    continue
                if evaluated >= _MAX_EVALUATIONS:
                    capped = True
                    break
                seen_requests.add(key)
                evaluated += 1
                result = evaluate_authorization(
                    bundle,
                    AuthorizationRequest(
                        provider=bundle.provider,
                        principal_id=binding.principal_id,
                        action=action,
                        resource=resource,
                        plane=AuthorizationPlane.ANY,
                    ),
                )
                if result.decision is AuthorizationDecision.ALLOW:
                    before = len(graph.edges)
                    graph.add_edge(
                        UnifiedEdge(
                            source=principal_node_id,
                            target=target_node.id,
                            relationship=RelationshipType.ASSUMES,
                            weight=6.0,
                            confidence=1.0,
                            provenance={"source": _SOURCE},
                            evidence={
                                "source": _SOURCE,
                                "provider": provider,
                                "decision": result.decision.value,
                                "action": action,
                                "resource": resource,
                                "binding_ids": list(result.matched_allow_bindings),
                                "observed_at": bundle.observed_at.isoformat() if bundle.observed_at else None,
                            },
                        )
                    )
                    if len(graph.edges) > before:
                        allow_edges += 1
                elif result.decision in {AuthorizationDecision.EXPLICIT_DENY, AuthorizationDecision.IMPLICIT_DENY}:
                    denied += 1
                else:
                    indeterminate += 1
            if capped:
                break
        if capped:
            break

    reason_codes: list[str] = []
    if bundle.incomplete_required_sources():
        reason_codes.append("incomplete_required_sources")
    if indeterminate:
        reason_codes.append("indeterminate_evaluations")
    if unmapped:
        reason_codes.append("unmapped_resources")
    if capped:
        reason_codes.append("evaluation_cap_exceeded")
    state = GraphAnalysisState.LIMITED if reason_codes else GraphAnalysisState.COMPLETE
    observed = {
        "allow_edges": allow_edges,
        "denied_evaluations": denied,
        "evaluated_requests": evaluated,
        "indeterminate_evaluations": indeterminate,
        "unmapped_resources": unmapped,
    }
    graph.analysis_status[f"authorization_evidence:{provider}"] = GraphAnalysisStatus(
        status=state,
        reason_codes=tuple(sorted(reason_codes)),
        limits={"max_evaluations": _MAX_EVALUATIONS},
        observed=observed,
    )
    return observed


__all__ = ["apply_authorization_evidence", "has_authoritative_authorization_evidence"]
