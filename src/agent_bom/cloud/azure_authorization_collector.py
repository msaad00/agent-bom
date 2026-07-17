"""Decision-capable, read-only Azure RBAC evidence collection.

The collector keeps provider I/O separate from authorization evaluation and
records a state for every required feed.  A missing permission, partial role
definition lookup, or collection cap is therefore evidence of uncertainty,
not an empty policy set.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any, Iterable

from agent_bom.cloud.authorization_evidence import EvidenceSourceState

from .aws_inventory import is_access_denied_error, record_discovery_failure

_DEFAULT_MAX_RECORDS = int(os.environ.get("AGENT_BOM_AZURE_AUTHORIZATION_MAX_RECORDS", "50000") or "50000")


def _text(value: Any) -> str:
    return str(value or "").strip()


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    return sorted({_text(item) for item in value if _text(item)})


def _source(
    name: str,
    state: EvidenceSourceState,
    *,
    diagnostics: Iterable[str] = (),
    provenance: Iterable[str] = (),
) -> dict[str, Any]:
    return {
        "name": name,
        "state": state.value,
        "diagnostics": sorted({_text(item) for item in diagnostics if _text(item)}),
        "provenance": sorted({_text(item) for item in provenance if _text(item)}),
    }


def _bounded(values: Iterable[Any], maximum: int) -> tuple[list[Any], bool]:
    records: list[Any] = []
    for value in values:
        if len(records) >= maximum:
            return records, True
        records.append(value)
    return records, False


def _assignment_record(assignment: Any, subscription_id: str) -> dict[str, Any] | None:
    principal_id = _text(getattr(assignment, "principal_id", None))
    scope = _text(getattr(assignment, "scope", None))
    role_definition_id = _text(getattr(assignment, "role_definition_id", None))
    if not principal_id or not scope or not role_definition_id:
        return None
    return {
        "id": _text(getattr(assignment, "id", None)),
        "name": _text(getattr(assignment, "name", None)),
        "principal_id": principal_id,
        "principal_type": _text(getattr(assignment, "principal_type", None)).lower(),
        "role_definition_id": role_definition_id,
        "role_name": "",
        "scope": scope,
        "condition": _text(getattr(assignment, "condition", None)) or None,
        "condition_version": _text(getattr(assignment, "condition_version", None)) or None,
        "delegated_managed_identity_resource_id": (_text(getattr(assignment, "delegated_managed_identity_resource_id", None)) or None),
        "account_id": subscription_id,
    }


def _permission_record(permission: Any) -> dict[str, Any]:
    return {
        "actions": _strings(getattr(permission, "actions", None)),
        "not_actions": _strings(getattr(permission, "not_actions", None)),
        "data_actions": _strings(getattr(permission, "data_actions", None)),
        "not_data_actions": _strings(getattr(permission, "not_data_actions", None)),
        "condition": _text(getattr(permission, "condition", None)) or None,
        "condition_version": _text(getattr(permission, "condition_version", None)) or None,
    }


def _role_record(role: Any, role_id: str) -> dict[str, Any]:
    return {
        "id": _text(getattr(role, "id", None)) or role_id,
        "role_name": _text(getattr(role, "role_name", None)),
        "role_type": _text(getattr(role, "role_type", None)),
        "assignable_scopes": _strings(getattr(role, "assignable_scopes", None)),
        "permissions": [_permission_record(permission) for permission in (getattr(role, "permissions", None) or [])],
        "completeness": EvidenceSourceState.COMPLETE.value,
    }


def _principal_records(values: Any) -> list[dict[str, str]]:
    principals: list[dict[str, str]] = []
    for value in values or []:
        principal_id = _text(getattr(value, "id", None))
        if principal_id:
            principals.append({"id": principal_id, "type": _text(getattr(value, "type", None)).lower()})
    return sorted(principals, key=lambda item: (item["id"].casefold(), item["type"]))


def _deny_record(assignment: Any) -> dict[str, Any] | None:
    scope = _text(getattr(assignment, "scope", None))
    if not scope:
        return None
    return {
        "id": _text(getattr(assignment, "id", None)),
        "name": _text(getattr(assignment, "name", None)),
        "deny_assignment_name": _text(getattr(assignment, "deny_assignment_name", None)),
        "scope": scope,
        "principals": _principal_records(getattr(assignment, "principals", None)),
        "exclude_principals": _principal_records(getattr(assignment, "exclude_principals", None)),
        "permissions": [_permission_record(permission) for permission in (getattr(assignment, "permissions", None) or [])],
        "do_not_apply_to_child_scopes": bool(getattr(assignment, "do_not_apply_to_child_scopes", False)),
        "is_system_protected": bool(getattr(assignment, "is_system_protected", False)),
        "condition": _text(getattr(assignment, "condition", None)) or None,
        "condition_version": _text(getattr(assignment, "condition_version", None)) or None,
    }


def collect_azure_authorization(
    credential: Any,
    subscription_id: str,
    *,
    client: Any = None,
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
    max_records: int | None = None,
) -> dict[str, Any]:
    """Collect Azure role assignments, complete role controls, and denies.

    ``max_records`` is applied independently to assignment and deny streams.
    One extra item is read to prove truncation; Azure SDK pageable iterators
    continue across all service pages until that bound is reached.
    """
    maximum = _DEFAULT_MAX_RECORDS if max_records is None else max_records
    if maximum < 1:
        raise ValueError("max_records must be at least 1")

    observed_at = datetime.now(UTC).isoformat()
    if client is None:
        try:
            from azure.mgmt.authorization import AuthorizationManagementClient
        except ImportError:
            warnings.append("azure-mgmt-authorization not installed. Skipping Azure authorization evidence.")
            sources = [
                _source(name, EvidenceSourceState.SDK_MISSING, diagnostics=("azure-mgmt-authorization not installed",))
                for name in ("role_assignments", "role_definitions", "deny_assignments")
            ]
            return {
                "authorization_observed_at": observed_at,
                "role_assignments": [],
                "role_definitions": [],
                "deny_assignments": [],
                "authorization_sources": sources,
            }
        client = AuthorizationManagementClient(credential, subscription_id)

    assignment_state = EvidenceSourceState.COMPLETE
    assignment_diagnostics: list[str] = []
    raw_assignments: list[Any] = []
    try:
        raw_assignments, assignments_truncated = _bounded(client.role_assignments.list_for_subscription(), maximum)
        if assignments_truncated:
            assignment_state = EvidenceSourceState.TRUNCATED
            assignment_diagnostics.append(f"collection capped at {maximum} records")
    except Exception as exc:  # noqa: BLE001 - provider failures become explicit evidence states
        assignment_state = EvidenceSourceState.ACCESS_DENIED if is_access_denied_error(exc) else EvidenceSourceState.UNAVAILABLE
        assignment_diagnostics.append(type(exc).__name__)
        record_discovery_failure(
            exc=exc,
            resource_type="Azure role assignments",
            permission="Microsoft.Authorization/roleAssignments/read",
            cloud="azure",
            warnings=warnings,
            missing=missing,
        )

    assignments: list[dict[str, Any]] = []
    dropped_assignments = 0
    for item in raw_assignments:
        record = _assignment_record(item, subscription_id)
        if record is None:
            dropped_assignments += 1
        else:
            assignments.append(record)
    if dropped_assignments:
        noun = "record" if dropped_assignments == 1 else "records"
        assignment_diagnostics.append(f"dropped {dropped_assignments} malformed role assignment {noun}")
        if assignment_state is EvidenceSourceState.COMPLETE:
            assignment_state = EvidenceSourceState.PARTIAL

    role_ids = sorted({item["role_definition_id"] for item in assignments}, key=str.casefold)
    roles: list[dict[str, Any]] = []
    role_state = EvidenceSourceState.COMPLETE
    role_diagnostics: list[str] = []
    if assignment_state is EvidenceSourceState.TRUNCATED:
        role_state = EvidenceSourceState.TRUNCATED
        role_diagnostics.append("role set is bounded by truncated assignments")
    elif dropped_assignments:
        role_state = EvidenceSourceState.PARTIAL
        noun = "record was" if dropped_assignments == 1 else "records were"
        role_diagnostics.append(f"role set incomplete because {dropped_assignments} malformed role assignment {noun} dropped")
    elif assignment_state is not EvidenceSourceState.COMPLETE:
        role_state = assignment_state
        role_diagnostics.append("role assignment feed is unavailable")

    for role_id in role_ids:
        try:
            role = _role_record(client.role_definitions.get_by_id(role_id), role_id)
            roles.append(role)
        except Exception as exc:  # noqa: BLE001 - one missing definition makes the role feed incomplete
            denied = is_access_denied_error(exc)
            if denied:
                role_state = EvidenceSourceState.ACCESS_DENIED
            elif role_state is not EvidenceSourceState.ACCESS_DENIED:
                role_state = EvidenceSourceState.PARTIAL
            role_diagnostics.append(f"unresolved role definition: {role_id}")
            record_discovery_failure(
                exc=exc,
                resource_type="Azure role definition",
                permission="Microsoft.Authorization/roleDefinitions/read",
                cloud="azure",
                warnings=warnings,
                missing=missing,
            )

    role_names = {item["id"].casefold(): item["role_name"] for item in roles}
    for assignment in assignments:
        assignment["role_name"] = role_names.get(assignment["role_definition_id"].casefold(), "")

    deny_state = EvidenceSourceState.COMPLETE
    deny_diagnostics: list[str] = []
    raw_denies: list[Any] = []
    try:
        raw_denies, denies_truncated = _bounded(client.deny_assignments.list(), maximum)
        if denies_truncated:
            deny_state = EvidenceSourceState.TRUNCATED
            deny_diagnostics.append(f"collection capped at {maximum} records")
    except Exception as exc:  # noqa: BLE001 - provider failures become explicit evidence states
        deny_state = EvidenceSourceState.ACCESS_DENIED if is_access_denied_error(exc) else EvidenceSourceState.UNAVAILABLE
        deny_diagnostics.append(type(exc).__name__)
        record_discovery_failure(
            exc=exc,
            resource_type="Azure deny assignments",
            permission="Microsoft.Authorization/denyAssignments/read",
            cloud="azure",
            warnings=warnings,
            missing=missing,
        )
    denies: list[dict[str, Any]] = []
    dropped_denies = 0
    for item in raw_denies:
        record = _deny_record(item)
        if record is None:
            dropped_denies += 1
        else:
            denies.append(record)
    if dropped_denies:
        noun = "record" if dropped_denies == 1 else "records"
        deny_diagnostics.append(f"dropped {dropped_denies} malformed deny assignment {noun}")
        if deny_state is EvidenceSourceState.COMPLETE:
            deny_state = EvidenceSourceState.PARTIAL

    return {
        "authorization_observed_at": observed_at,
        "role_assignments": sorted(assignments, key=lambda item: (item["id"], item["principal_id"])),
        "role_definitions": sorted(roles, key=lambda item: item["id"].casefold()),
        "deny_assignments": sorted(denies, key=lambda item: (item["id"], item["scope"])),
        "authorization_sources": [
            _source(
                "role_assignments",
                assignment_state,
                diagnostics=assignment_diagnostics,
                provenance=("azure.roleAssignments.listForSubscription",),
            ),
            _source(
                "role_definitions",
                role_state,
                diagnostics=role_diagnostics,
                provenance=("azure.roleDefinitions.getById",),
            ),
            _source(
                "deny_assignments",
                deny_state,
                diagnostics=deny_diagnostics,
                provenance=("azure.denyAssignments.list",),
            ),
        ],
    }


__all__ = ["collect_azure_authorization"]
