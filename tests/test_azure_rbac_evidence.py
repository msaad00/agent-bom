from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Iterable

from agent_bom.cloud.authorization_evaluator import evaluate_authorization
from agent_bom.cloud.authorization_evidence import (
    AuthorizationDecision,
    AuthorizationPlane,
    AuthorizationProvider,
    AuthorizationRequest,
    EvidenceSourceState,
)
from agent_bom.cloud.azure_authorization_collector import collect_azure_authorization
from agent_bom.cloud.azure_rbac_evidence import normalize_azure_rbac_inventory


def _assignment(principal_id: str, *, condition: str | None = None) -> Any:
    return SimpleNamespace(
        id=f"/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/{principal_id}",
        name=principal_id,
        principal_id=principal_id,
        principal_type="ServicePrincipal",
        role_definition_id="/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/reader",
        scope="/subscriptions/sub-1",
        condition=condition,
        condition_version="2.0" if condition else None,
        delegated_managed_identity_resource_id=None,
    )


class _RoleAssignments:
    def __init__(self, values: Iterable[Any]) -> None:
        self.values = values

    def list_for_subscription(self) -> Iterable[Any]:
        return self.values


class _RoleDefinitions:
    def get_by_id(self, role_id: str) -> Any:
        return SimpleNamespace(
            id=role_id,
            role_name="Storage Reader",
            role_type="CustomRole",
            assignable_scopes=["/subscriptions/sub-1"],
            permissions=[
                SimpleNamespace(
                    actions=["Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/delete"],
                    not_actions=["Microsoft.Storage/storageAccounts/delete"],
                    data_actions=["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
                    not_data_actions=[],
                )
            ],
        )


class _DenyAssignments:
    def __init__(self, values: Iterable[Any]) -> None:
        self.values = values

    def list(self) -> Iterable[Any]:
        return self.values


def _deny_assignment() -> Any:
    return SimpleNamespace(
        id="/subscriptions/sub-1/providers/Microsoft.Authorization/denyAssignments/deny-1",
        name="deny-1",
        deny_assignment_name="protect-storage",
        scope="/subscriptions/sub-1",
        principals=[SimpleNamespace(id="sp-1", type="ServicePrincipal")],
        exclude_principals=[SimpleNamespace(id="break-glass", type="ServicePrincipal")],
        permissions=[
            SimpleNamespace(
                actions=["Microsoft.Storage/storageAccounts/delete"],
                not_actions=[],
                data_actions=[],
                not_data_actions=[],
                condition=None,
                condition_version=None,
            )
        ],
        do_not_apply_to_child_scopes=False,
        is_system_protected=True,
        condition=None,
        condition_version=None,
    )


def _client(*, assignments: Iterable[Any] | None = None, denies: Iterable[Any] | None = None) -> Any:
    return SimpleNamespace(
        role_assignments=_RoleAssignments(assignments if assignments is not None else [_assignment("sp-1")]),
        role_definitions=_RoleDefinitions(),
        deny_assignments=_DenyAssignments(denies if denies is not None else [_deny_assignment()]),
    )


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


def test_complete_collector_payload_can_allow_and_explicitly_deny() -> None:
    collected = collect_azure_authorization(object(), "sub-1", client=_client(), warnings=[])
    bundle = normalize_azure_rbac_inventory({"status": "ok", "subscription_id": "sub-1", **collected})

    allowed = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.AZURE,
            principal_id="sp-1",
            action="Microsoft.Storage/storageAccounts/read",
            resource="/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data",
            plane=AuthorizationPlane.CONTROL,
        ),
    )
    excluded_allow = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.AZURE,
            principal_id="break-glass",
            action="Microsoft.Storage/storageAccounts/delete",
            resource="/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data",
            plane=AuthorizationPlane.CONTROL,
        ),
    )
    denied = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.AZURE,
            principal_id="sp-1",
            action="Microsoft.Storage/storageAccounts/delete",
            resource="/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data",
            plane=AuthorizationPlane.CONTROL,
        ),
    )
    data_allowed = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.AZURE,
            principal_id="sp-1",
            action="Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            resource="/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data",
            plane=AuthorizationPlane.DATA,
        ),
    )

    assert allowed.decision is AuthorizationDecision.ALLOW
    assert excluded_allow.decision is AuthorizationDecision.IMPLICIT_DENY
    assert denied.decision is AuthorizationDecision.EXPLICIT_DENY
    assert data_allowed.decision is AuthorizationDecision.ALLOW


def test_system_defined_all_principals_deny_matches_any_principal() -> None:
    deny = _deny_assignment()
    deny.principals = [SimpleNamespace(id="00000000-0000-0000-0000-000000000000", type="SystemDefined")]
    collected = collect_azure_authorization(
        object(),
        "sub-1",
        client=_client(assignments=[], denies=[deny]),
        warnings=[],
    )
    bundle = normalize_azure_rbac_inventory({"status": "ok", "subscription_id": "sub-1", **collected})

    result = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.AZURE,
            principal_id="arbitrary-principal",
            action="Microsoft.Storage/storageAccounts/delete",
            resource="/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data",
            plane=AuthorizationPlane.CONTROL,
        ),
    )

    assert result.decision is AuthorizationDecision.EXPLICIT_DENY


def test_role_record_without_completeness_is_not_blessed_by_complete_source() -> None:
    collected = collect_azure_authorization(object(), "sub-1", client=_client(denies=[]), warnings=[])
    del collected["role_definitions"][0]["completeness"]
    bundle = normalize_azure_rbac_inventory({"status": "ok", "subscription_id": "sub-1", **collected})

    assert bundle.role_definitions[0].completeness is EvidenceSourceState.UNAVAILABLE
    result = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.AZURE,
            principal_id="sp-1",
            action="Microsoft.Storage/storageAccounts/read",
            resource="/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data",
            plane=AuthorizationPlane.CONTROL,
        ),
    )
    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("role:/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/reader:unavailable",)


def test_truncated_collector_payload_cannot_allow() -> None:
    collected = collect_azure_authorization(
        object(),
        "sub-1",
        client=_client(assignments=[_assignment("sp-1"), _assignment("sp-2")], denies=[]),
        warnings=[],
        max_records=1,
    )
    bundle = normalize_azure_rbac_inventory({"status": "ok", "subscription_id": "sub-1", **collected})

    result = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.AZURE,
            principal_id="sp-1",
            action="Microsoft.Storage/storageAccounts/read",
            resource="/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data",
            plane=AuthorizationPlane.CONTROL,
        ),
    )

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert "role_assignments:truncated" in result.diagnostics


def test_unsupported_azure_assignment_condition_is_indeterminate() -> None:
    conditional = _assignment("sp-1", condition="@Resource[Microsoft.Storage/storageAccounts:Name] StringEquals 'prod'")
    collected = collect_azure_authorization(
        object(),
        "sub-1",
        client=_client(assignments=[conditional], denies=[]),
        warnings=[],
    )
    bundle = normalize_azure_rbac_inventory({"status": "ok", "subscription_id": "sub-1", **collected})

    result = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.AZURE,
            principal_id="sp-1",
            action="Microsoft.Storage/storageAccounts/read",
            resource="/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data",
            plane=AuthorizationPlane.CONTROL,
        ),
    )

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("unevaluated_allow_condition",)


def test_unsupported_azure_deny_condition_is_indeterminate() -> None:
    conditional_deny = _deny_assignment()
    conditional_deny.condition = "@Resource[Microsoft.Storage/storageAccounts:Name] StringEquals 'prod'"
    conditional_deny.condition_version = "2.0"
    collected = collect_azure_authorization(
        object(),
        "sub-1",
        client=_client(assignments=[], denies=[conditional_deny]),
        warnings=[],
    )
    bundle = normalize_azure_rbac_inventory({"status": "ok", "subscription_id": "sub-1", **collected})

    result = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.AZURE,
            principal_id="sp-1",
            action="Microsoft.Storage/storageAccounts/delete",
            resource="/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data",
            plane=AuthorizationPlane.CONTROL,
        ),
    )

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("unevaluated_deny_condition",)


def test_group_assignment_remains_indeterminate_without_transitive_membership() -> None:
    group_assignment = _assignment("group-1")
    group_assignment.principal_type = "Group"
    collected = collect_azure_authorization(
        object(),
        "sub-1",
        client=_client(assignments=[group_assignment], denies=[]),
        warnings=[],
    )
    bundle = normalize_azure_rbac_inventory(
        {
            "status": "ok",
            "subscription_id": "sub-1",
            "entra_groups": [{"principal_id": "group-1", "members": [{"id": "sp-1"}]}],
            **collected,
        }
    )

    result = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.AZURE,
            principal_id="sp-1",
            action="Microsoft.Storage/storageAccounts/read",
            resource="/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data",
            plane=AuthorizationPlane.CONTROL,
        ),
    )

    assert bundle.source_state("group_memberships") is EvidenceSourceState.PARTIAL
    assert result.decision is AuthorizationDecision.INDETERMINATE


def test_group_deny_cannot_fail_open_without_transitive_membership() -> None:
    deny = _deny_assignment()
    deny.principals = [SimpleNamespace(id="group-1", type="Group")]
    collected = collect_azure_authorization(
        object(),
        "sub-1",
        client=_client(assignments=[_assignment("sp-1")], denies=[deny]),
        warnings=[],
    )
    bundle = normalize_azure_rbac_inventory({"status": "ok", "subscription_id": "sub-1", **collected})

    result = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.AZURE,
            principal_id="sp-1",
            action="Microsoft.Storage/storageAccounts/read",
            resource="/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data",
            plane=AuthorizationPlane.CONTROL,
        ),
    )

    assert bundle.source_state("group_memberships") is EvidenceSourceState.UNAVAILABLE
    assert result.decision is AuthorizationDecision.INDETERMINATE
