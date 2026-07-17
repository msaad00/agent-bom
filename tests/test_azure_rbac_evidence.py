from __future__ import annotations

from agent_bom.cloud.authorization_evaluator import evaluate_authorization
from agent_bom.cloud.authorization_evidence import (
    AuthorizationDecision,
    AuthorizationPlane,
    AuthorizationProvider,
    AuthorizationRequest,
    EvidenceSourceState,
)
from agent_bom.cloud.azure_rbac_evidence import normalize_azure_rbac_inventory


def test_current_azure_role_name_payload_is_partial_and_cannot_allow() -> None:
    payload = {
        "provider": "azure",
        "status": "ok",
        "subscription_id": "sub-1",
        "account_id": "sub-1",
        "role_assignments": [
            {
                "principal_id": "sp-1",
                "principal_type": "serviceprincipal",
                "role_name": "Owner",
                "scope": "/subscriptions/sub-1",
                "account_id": "sub-1",
            }
        ],
        "service_principals": [{"principal_id": "sp-1"}],
        "entra_groups": [],
        "management_groups": [],
        "warnings": [],
        "missing_permissions": [],
    }
    bundle = normalize_azure_rbac_inventory(payload)

    assert bundle.provider is AuthorizationProvider.AZURE
    assert bundle.source_state("role_assignments") is EvidenceSourceState.PARTIAL
    assert bundle.source_state("role_definitions") is EvidenceSourceState.PARTIAL
    assert bundle.source_state("deny_assignments") is EvidenceSourceState.UNSUPPORTED
    assert bundle.bindings[0].role_id == "Owner"
    assert bundle.bindings[0].permissions == ()

    result = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.AZURE,
            principal_id="sp-1",
            action="Microsoft.Authorization/roleAssignments/write",
            resource="/subscriptions/sub-1/resourceGroups/prod",
            plane=AuthorizationPlane.CONTROL,
        ),
    )
    assert result.decision is AuthorizationDecision.INDETERMINATE


def test_azure_legacy_binding_id_is_stable() -> None:
    assignment = {
        "principal_id": "sp-1",
        "principal_type": "serviceprincipal",
        "role_name": "Reader",
        "scope": "/subscriptions/sub-1",
    }
    first = normalize_azure_rbac_inventory({"status": "ok", "subscription_id": "sub-1", "role_assignments": [assignment]})
    second = normalize_azure_rbac_inventory({"status": "ok", "subscription_id": "sub-1", "role_assignments": [dict(assignment)]})

    assert first.bindings[0].binding_id == second.bindings[0].binding_id


def test_disabled_azure_inventory_preserves_disabled_source_state() -> None:
    bundle = normalize_azure_rbac_inventory({"provider": "azure", "status": "disabled", "subscription_id": "sub-1"})

    assert bundle.bindings == ()
    assert bundle.source_state("role_assignments") is EvidenceSourceState.DISABLED
