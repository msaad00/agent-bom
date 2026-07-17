from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Iterable

from agent_bom.cloud.authorization_evidence import EvidenceSourceState
from agent_bom.cloud.azure_authorization_collector import collect_azure_authorization


class _Pager:
    def __init__(self, *pages: list[Any]) -> None:
        self.pages = pages
        self.pages_read = 0

    def __iter__(self):
        for page in self.pages:
            self.pages_read += 1
            yield from page


def _assignment(
    principal_id: str,
    role_id: str = "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/reader",
    *,
    assignment_id: str | None = None,
    condition: str | None = None,
) -> Any:
    return SimpleNamespace(
        id=assignment_id or f"/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/{principal_id}",
        name=principal_id,
        principal_id=principal_id,
        principal_type="ServicePrincipal",
        role_definition_id=role_id,
        scope="/subscriptions/sub-1",
        condition=condition,
        condition_version="2.0" if condition else None,
        delegated_managed_identity_resource_id="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/delegate",
    )


def _role_definition(role_id: str) -> Any:
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


class _RoleAssignments:
    def __init__(self, values: Iterable[Any]) -> None:
        self.values = values

    def list_for_subscription(self) -> Iterable[Any]:
        return self.values


class _RoleDefinitions:
    def get_by_id(self, role_id: str) -> Any:
        return _role_definition(role_id)


class _DenyAssignments:
    def __init__(self, values: Iterable[Any]) -> None:
        self.values = values

    def list(self) -> Iterable[Any]:
        return self.values


def _client(*, assignments: Iterable[Any] | None = None, denies: Iterable[Any] | None = None) -> Any:
    return SimpleNamespace(
        role_assignments=_RoleAssignments(assignments if assignments is not None else [_assignment("sp-1")]),
        role_definitions=_RoleDefinitions(),
        deny_assignments=_DenyAssignments(denies if denies is not None else [_deny_assignment()]),
    )


def _source_states(result: dict[str, Any]) -> dict[str, str]:
    return {source["name"]: source["state"] for source in result["authorization_sources"]}


def test_collects_complete_assignments_roles_and_denies() -> None:
    warnings: list[str] = []
    missing: list[dict[str, str]] = []

    result = collect_azure_authorization(
        object(),
        "sub-1",
        client=_client(),
        warnings=warnings,
        missing=missing,
    )

    assert _source_states(result) == {
        "deny_assignments": EvidenceSourceState.COMPLETE.value,
        "role_assignments": EvidenceSourceState.COMPLETE.value,
        "role_definitions": EvidenceSourceState.COMPLETE.value,
    }
    assignment = result["role_assignments"][0]
    assert assignment["id"].endswith("/sp-1")
    assert assignment["role_definition_id"].endswith("/reader")
    assert assignment["delegated_managed_identity_resource_id"].endswith("/delegate")
    role = result["role_definitions"][0]
    assert role["permissions"][0]["actions"] == [
        "Microsoft.Storage/storageAccounts/delete",
        "Microsoft.Storage/storageAccounts/read",
    ]
    assert role["permissions"][0]["not_actions"] == ["Microsoft.Storage/storageAccounts/delete"]
    assert role["permissions"][0]["data_actions"] == ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]
    deny = result["deny_assignments"][0]
    assert deny["principals"] == [{"id": "sp-1", "type": "serviceprincipal"}]
    assert deny["exclude_principals"] == [{"id": "break-glass", "type": "serviceprincipal"}]
    assert warnings == [] and missing == []


def test_sdk_pager_is_consumed_across_pages() -> None:
    pager = _Pager([_assignment("sp-1")], [_assignment("sp-2")])

    result = collect_azure_authorization(
        object(),
        "sub-1",
        client=_client(assignments=pager, denies=[]),
        warnings=[],
    )

    assert pager.pages_read == 2
    assert [item["principal_id"] for item in result["role_assignments"]] == ["sp-1", "sp-2"]
    assert _source_states(result)["role_assignments"] == EvidenceSourceState.COMPLETE.value


def test_cap_sets_truncated_source_state() -> None:
    result = collect_azure_authorization(
        object(),
        "sub-1",
        client=_client(assignments=[_assignment("sp-1"), _assignment("sp-2")], denies=[]),
        warnings=[],
        max_records=1,
    )

    assert len(result["role_assignments"]) == 1
    assert _source_states(result)["role_assignments"] == EvidenceSourceState.TRUNCATED.value
    assert _source_states(result)["role_definitions"] == EvidenceSourceState.TRUNCATED.value


def test_malformed_assignment_marks_assignments_and_role_set_partial() -> None:
    malformed = _assignment("sp-bad")
    malformed.role_definition_id = None

    result = collect_azure_authorization(
        object(),
        "sub-1",
        client=_client(assignments=[_assignment("sp-1"), malformed], denies=[]),
        warnings=[],
    )

    assert [item["principal_id"] for item in result["role_assignments"]] == ["sp-1"]
    assert _source_states(result)["role_assignments"] == EvidenceSourceState.PARTIAL.value
    assert _source_states(result)["role_definitions"] == EvidenceSourceState.PARTIAL.value
    assignment_source = next(source for source in result["authorization_sources"] if source["name"] == "role_assignments")
    role_source = next(source for source in result["authorization_sources"] if source["name"] == "role_definitions")
    assert assignment_source["diagnostics"] == ["dropped 1 malformed role assignment record"]
    assert role_source["diagnostics"] == ["role set incomplete because 1 malformed role assignment record was dropped"]


def test_malformed_deny_marks_deny_source_partial() -> None:
    malformed = _deny_assignment()
    malformed.scope = None

    result = collect_azure_authorization(
        object(),
        "sub-1",
        client=_client(denies=[_deny_assignment(), malformed]),
        warnings=[],
    )

    assert len(result["deny_assignments"]) == 1
    assert _source_states(result)["deny_assignments"] == EvidenceSourceState.PARTIAL.value
    deny_source = next(source for source in result["authorization_sources"] if source["name"] == "deny_assignments")
    assert deny_source["diagnostics"] == ["dropped 1 malformed deny assignment record"]


class _DeniedError(Exception):
    status_code = 403


class _DeniedRoleAssignments:
    def list_for_subscription(self) -> Iterable[Any]:
        raise _DeniedError("AuthorizationFailed: forbidden")


class _DeniedRoleDefinitions:
    def get_by_id(self, role_id: str) -> Any:
        raise _DeniedError("AuthorizationFailed: forbidden")


class _DeniedDenyAssignments:
    def list(self) -> Iterable[Any]:
        raise _DeniedError("AuthorizationFailed: forbidden")


def test_role_assignment_access_denied_is_structured() -> None:
    warnings: list[str] = []
    missing: list[dict[str, str]] = []
    client = _client(denies=[])
    client.role_assignments = _DeniedRoleAssignments()

    result = collect_azure_authorization(object(), "sub-1", client=client, warnings=warnings, missing=missing)

    assert _source_states(result)["role_assignments"] == EvidenceSourceState.ACCESS_DENIED.value
    assert missing == [
        {
            "cloud": "azure",
            "permission": "Microsoft.Authorization/roleAssignments/read",
            "resource_type": "Azure role assignments",
        }
    ]
    assert any("role lacks Microsoft.Authorization/roleAssignments/read" in warning for warning in warnings)


def test_role_definition_access_denied_is_structured() -> None:
    warnings: list[str] = []
    missing: list[dict[str, str]] = []
    client = _client(denies=[])
    client.role_definitions = _DeniedRoleDefinitions()

    result = collect_azure_authorization(object(), "sub-1", client=client, warnings=warnings, missing=missing)

    assert _source_states(result)["role_definitions"] == EvidenceSourceState.ACCESS_DENIED.value
    assert missing == [
        {
            "cloud": "azure",
            "permission": "Microsoft.Authorization/roleDefinitions/read",
            "resource_type": "Azure role definition",
        }
    ]


def test_deny_assignment_access_denied_is_structured() -> None:
    warnings: list[str] = []
    missing: list[dict[str, str]] = []
    client = _client()
    client.deny_assignments = _DeniedDenyAssignments()

    result = collect_azure_authorization(object(), "sub-1", client=client, warnings=warnings, missing=missing)

    assert _source_states(result)["deny_assignments"] == EvidenceSourceState.ACCESS_DENIED.value
    assert missing == [
        {
            "cloud": "azure",
            "permission": "Microsoft.Authorization/denyAssignments/read",
            "resource_type": "Azure deny assignments",
        }
    ]
