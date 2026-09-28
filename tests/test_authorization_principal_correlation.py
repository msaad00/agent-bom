"""Authorization proof joins on native identity, never display-name coincidence."""

import pytest

from agent_bom.cloud.authorization_evidence import AuthorizationBinding, AuthorizationEffect
from agent_bom.graph.authorization_evidence import _principal_node
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType


def _binding(principal_id="native-id", principal_type="serviceprincipal"):
    return AuthorizationBinding(
        binding_id="binding",
        effect=AuthorizationEffect.ALLOW,
        principal_id=principal_id,
        principal_type=principal_type,
        scope="/subscriptions/sub-1",
    )


def _identity(graph, node_id, *, kind=EntityType.SERVICE_PRINCIPAL, **attributes):
    graph.add_node(UnifiedNode(id=node_id, label=node_id, entity_type=kind, attributes={"cloud_provider": "azure", **attributes}))


def test_display_name_does_not_steal_native_principal_authorization():
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    _identity(graph, "decoy", principal_name="native-id", directory_principal_id="other-id")
    _identity(graph, "correct", directory_principal_id="native-id")
    assert _principal_node(graph, _binding(), "azure") == "correct"


@pytest.mark.parametrize("kind", [EntityType.CLOUD_RESOURCE, EntityType.USER, EntityType.GROUP])
def test_different_entity_kind_cannot_receive_service_principal_grants(kind):
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    _identity(graph, "decoy", kind=kind, principal_id="native-id")
    node_id = _principal_node(graph, _binding(), "azure")
    assert node_id != "decoy"
    assert graph.nodes[node_id].entity_type == EntityType.SERVICE_PRINCIPAL


def test_azure_directory_object_id_connects_managed_identity_binding():
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    _identity(
        graph,
        "managed",
        kind=EntityType.MANAGED_IDENTITY,
        principal_id="/subscriptions/sub-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/app",
        directory_principal_id="NATIVE-ID",
    )
    assert _principal_node(graph, _binding(), "azure") == "managed"


def test_gcp_service_account_email_alias_retains_native_join():
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    graph.add_node(
        UnifiedNode(
            id="account",
            label="scanner",
            entity_type=EntityType.SERVICE_ACCOUNT,
            attributes={"cloud_provider": "gcp", "principal_email": "scanner@project.iam.gserviceaccount.com"},
        )
    )
    binding = _binding("serviceAccount:scanner@project.iam.gserviceaccount.com", "serviceaccount")
    assert _principal_node(graph, binding, "gcp") == "account"


@pytest.mark.parametrize("reverse", [False, True])
def test_ambiguous_native_alias_does_not_choose_insertion_order(reverse):
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    for node_id in ("one", "two")[:: -1 if reverse else 1]:
        _identity(graph, node_id, directory_principal_id="native-id")
    result = _principal_node(graph, _binding(), "azure")
    assert result == "service_principal:azure:native-id"
    assert graph.nodes[result].attributes["authorization_evidence_state"] == "observed"


def test_inventory_name_fallback_is_not_native_authorization_evidence():
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    _identity(graph, "unresolved", principal_id="native-id", principal_name="native-id", source="cloud-inventory")
    result = _principal_node(graph, _binding(), "azure")
    assert result != "unresolved"


def test_native_binding_does_not_merge_inventory_display_name_key():
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    node_id = "service_principal:azure:native-id"
    _identity(graph, node_id, principal_id="native-id", principal_name="native-id", source="cloud-inventory")
    result = _principal_node(graph, _binding(), "azure")
    assert result != node_id
    assert "authorization_evidence_state" not in graph.nodes[node_id].attributes
