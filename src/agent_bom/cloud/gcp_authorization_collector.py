"""Read-only, decision-oriented GCP IAM evidence collection."""

from __future__ import annotations

import base64
import os
from datetime import UTC, datetime
from hashlib import sha256
from types import SimpleNamespace
from typing import Any, Iterable, Mapping
from urllib.parse import quote

from agent_bom.cloud.authorization_evidence import EvidenceSourceState

from .aws_inventory import is_access_denied_error, record_discovery_failure

_DEFAULT_MAX_RECORDS = int(os.environ.get("AGENT_BOM_GCP_AUTHORIZATION_MAX_RECORDS", "50000") or "50000")


def _get(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _strings(value: Any) -> list[str]:
    return sorted({_text(item) for item in (value or []) if _text(item)})


def _etag(value: Any) -> str:
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    return _text(value)


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


def _condition(value: Any) -> dict[str, Any] | None:
    expression = _text(_get(value, "expression"))
    if not expression:
        return None
    return {
        "expression": expression,
        "title": _text(_get(value, "title")),
        "description": _text(_get(value, "description")),
        "location": _text(_get(value, "location")),
    }


def _bindings(policy: Any, resource: str) -> tuple[list[dict[str, Any]], int]:
    bindings: list[dict[str, Any]] = []
    dropped = 0
    for raw in _get(policy, "bindings", []) or []:
        role = _text(_get(raw, "role"))
        members = _strings(_get(raw, "members", []))
        if not role or not members:
            dropped += 1
            continue
        condition = _condition(_get(raw, "condition"))
        digest = sha256("\x1f".join((resource, role, *members, condition["expression"] if condition else "")).encode()).hexdigest()[:24]
        bindings.append(
            {
                "id": f"gcp:iam-binding:{digest}",
                "role": role,
                "members": members,
                "condition": condition,
            }
        )
    return sorted(bindings, key=lambda item: item["id"]), dropped


def _policy_record(resource: str, policy: Any, *, asset_type: str, ancestors: Any = None) -> dict[str, Any]:
    bindings, dropped = _bindings(policy, resource)
    return {
        "resource": resource,
        "asset_type": asset_type,
        "ancestors": _strings(ancestors),
        "version": int(_get(policy, "version", 0) or 0),
        "etag": _etag(_get(policy, "etag")),
        "bindings": bindings,
        "dropped_bindings": dropped,
    }


def _role_record(role: Any, role_id: str) -> dict[str, Any]:
    return {
        "id": _text(_get(role, "name")) or role_id,
        "title": _text(_get(role, "title")),
        "description": _text(_get(role, "description")),
        "stage": _text(_get(role, "stage")),
        "deleted": bool(_get(role, "deleted", False)),
        "permissions": _strings(_get(role, "included_permissions", [])),
        "completeness": EvidenceSourceState.COMPLETE.value,
    }


def _deny_rule(rule: Any) -> dict[str, Any]:
    return {
        "denied_principals": _strings(_get(rule, "denied_principals", [])),
        "exception_principals": _strings(_get(rule, "exception_principals", [])),
        "denied_permissions": _strings(_get(rule, "denied_permissions", [])),
        "exception_permissions": _strings(_get(rule, "exception_permissions", [])),
        "condition": _condition(_get(rule, "denial_condition")),
    }


def _deny_record(policy: Any, attachment_point: str) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    for wrapper in _get(policy, "rules", []) or []:
        rule = _get(wrapper, "deny_rule", wrapper)
        rules.append(_deny_rule(rule))
    return {
        "name": _text(_get(policy, "name")),
        "uid": _text(_get(policy, "uid")),
        "display_name": _text(_get(policy, "display_name")),
        "attachment_point": attachment_point,
        "rules": rules,
    }


def _pab_record(policy: Any) -> dict[str, Any]:
    details = _get(policy, "details")
    rules = [
        {
            "description": _text(_get(rule, "description")),
            "resources": _strings(_get(rule, "resources", [])),
            "effect": _text(_get(rule, "effect")),
        }
        for rule in (_get(details, "rules", []) or [])
    ]
    return {
        "name": _text(_get(policy, "name")),
        "uid": _text(_get(policy, "uid")),
        "display_name": _text(_get(policy, "display_name")),
        "enforcement_version": _text(_get(details, "enforcement_version")),
        "rules": rules,
    }


def _pab_binding_record(binding: Any) -> dict[str, Any]:
    target = _get(binding, "target")
    return {
        "name": _text(_get(binding, "name")),
        "uid": _text(_get(binding, "uid")),
        "target": _text(_get(target, "principal_set")),
        "policy_kind": _text(_get(binding, "policy_kind")),
        "policy": _text(_get(binding, "policy")),
        "policy_uid": _text(_get(binding, "policy_uid")),
        "condition": _condition(_get(binding, "condition")),
    }


def _load_clients(credentials: Any) -> Any:
    from google.cloud import asset_v1, iam_admin_v1, iam_v2, iam_v3, resourcemanager_v3

    return SimpleNamespace(
        assets=asset_v1.AssetServiceClient(credentials=credentials),
        projects=resourcemanager_v3.ProjectsClient(credentials=credentials),
        folders=resourcemanager_v3.FoldersClient(credentials=credentials),
        organizations=resourcemanager_v3.OrganizationsClient(credentials=credentials),
        roles=iam_admin_v1.IAMClient(credentials=credentials),
        denies=iam_v2.PoliciesClient(credentials=credentials),
        pabs=iam_v3.PrincipalAccessBoundaryPoliciesClient(credentials=credentials),
        policy_bindings=iam_v3.PolicyBindingsClient(credentials=credentials),
    )


def _failure_state(exc: BaseException) -> EvidenceSourceState:
    return EvidenceSourceState.ACCESS_DENIED if is_access_denied_error(exc) else EvidenceSourceState.UNAVAILABLE


def _merge_state(current: EvidenceSourceState, incoming: EvidenceSourceState) -> EvidenceSourceState:
    severity = {
        EvidenceSourceState.COMPLETE: 0,
        EvidenceSourceState.PARTIAL: 1,
        EvidenceSourceState.TRUNCATED: 2,
        EvidenceSourceState.UNAVAILABLE: 3,
        EvidenceSourceState.ACCESS_DENIED: 4,
        EvidenceSourceState.SDK_MISSING: 5,
    }
    return incoming if severity[incoming] > severity[current] else current


def collect_gcp_authorization(
    credentials: Any,
    project_id: str,
    *,
    clients: Any = None,
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
    max_records: int | None = None,
) -> dict[str, Any]:
    """Collect pageable allow, role, deny, hierarchy, and PAB evidence."""
    maximum = _DEFAULT_MAX_RECORDS if max_records is None else max_records
    if maximum < 1:
        raise ValueError("max_records must be at least 1")
    observed_at = datetime.now(UTC).isoformat()
    if clients is None:
        try:
            clients = _load_clients(credentials)
        except ImportError:
            warnings.append("GCP IAM evidence SDKs are incomplete. Install with: pip install 'agent-bom[gcp]'")
            return {
                "iam_observed_at": observed_at,
                "iam_hierarchy": [f"projects/{project_id}"],
                "allow_policies": [],
                "role_definitions": [],
                "deny_policies": [],
                "pab_policies": [],
                "pab_bindings": [],
                "iam_sources": [
                    _source(name, EvidenceSourceState.SDK_MISSING)
                    for name in (
                        "allow_policies",
                        "role_definitions",
                        "resource_hierarchy",
                        "deny_policies",
                        "principal_access_boundaries",
                    )
                ],
            }

    project_scope = f"projects/{project_id}"
    hierarchy = [project_scope]
    hierarchy_state = EvidenceSourceState.COMPLETE
    hierarchy_diagnostics: list[str] = []
    try:
        project = clients.projects.get_project(request={"name": project_scope})
        parent = _text(_get(project, "parent"))
        while parent:
            hierarchy.append(parent)
            if parent.startswith("folders/"):
                folder = clients.folders.get_folder(request={"name": parent})
                parent = _text(_get(folder, "parent"))
            elif parent.startswith("organizations/"):
                break
            else:
                hierarchy_state = EvidenceSourceState.PARTIAL
                hierarchy_diagnostics.append(f"unsupported hierarchy parent: {parent}")
                break
    except Exception as exc:  # noqa: BLE001
        hierarchy_state = _failure_state(exc)
        hierarchy_diagnostics.append(type(exc).__name__)
        record_discovery_failure(
            exc=exc,
            resource_type="GCP resource hierarchy",
            permission="resourcemanager.projects.get",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )

    allow_policies: dict[str, dict[str, Any]] = {}
    allow_state = EvidenceSourceState.COMPLETE
    allow_diagnostics: list[str] = []
    dropped_allow_records = 0
    try:
        assets, truncated = _bounded(
            clients.assets.list_assets(
                request={"parent": project_scope, "content_type": "IAM_POLICY", "page_size": min(maximum + 1, 1000)}
            ),
            maximum,
        )
        for asset in assets:
            resource = _text(_get(asset, "name"))
            policy = _get(asset, "iam_policy")
            if resource and policy is not None:
                record = _policy_record(
                    resource,
                    policy,
                    asset_type=_text(_get(asset, "asset_type")),
                    ancestors=_get(asset, "ancestors", []),
                )
                dropped_allow_records += record["dropped_bindings"]
                allow_policies[resource] = record
            else:
                dropped_allow_records += 1
        if truncated:
            allow_state = EvidenceSourceState.TRUNCATED
            allow_diagnostics.append(f"resource-local policy collection capped at {maximum} records")
    except Exception as exc:  # noqa: BLE001
        allow_state = _failure_state(exc)
        allow_diagnostics.append(type(exc).__name__)
        record_discovery_failure(
            exc=exc,
            resource_type="GCP resource-local IAM policies",
            permission="cloudasset.assets.listIamPolicy",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )

    hierarchy_policy_failed = False
    for scope in hierarchy:
        try:
            if scope.startswith("projects/"):
                client = clients.projects
            elif scope.startswith("folders/"):
                client = clients.folders
            else:
                client = clients.organizations
            policy = client.get_iam_policy(request={"resource": scope, "options": {"requested_policy_version": 3}})
            record = _policy_record(scope, policy, asset_type="cloudresourcemanager.googleapis.com/Hierarchy")
            dropped_allow_records += record["dropped_bindings"]
            allow_policies[scope] = record
        except Exception as exc:  # noqa: BLE001
            hierarchy_policy_failed = True
            state = _failure_state(exc)
            if state is EvidenceSourceState.ACCESS_DENIED or allow_state is EvidenceSourceState.COMPLETE:
                allow_state = state
            hierarchy_state = state
            allow_diagnostics.append(f"unreadable hierarchy policy: {scope}")
            record_discovery_failure(
                exc=exc,
                resource_type=f"GCP IAM policy for {scope}",
                permission=f"resourcemanager.{scope.split('/', 1)[0]}.getIamPolicy",
                cloud="gcp",
                warnings=warnings,
                missing=missing,
            )
    if hierarchy_state is not EvidenceSourceState.COMPLETE and allow_state is EvidenceSourceState.COMPLETE:
        allow_state = hierarchy_state
        allow_diagnostics.append("parent hierarchy unavailable; inherited allow policies may be missing")
    if dropped_allow_records and allow_state is EvidenceSourceState.COMPLETE:
        allow_state = EvidenceSourceState.PARTIAL
        allow_diagnostics.append(f"dropped {dropped_allow_records} malformed allow policy records")
    if hierarchy_policy_failed:
        hierarchy_diagnostics.append("one or more hierarchy policies were unavailable")

    role_ids = sorted(
        {binding["role"] for policy in allow_policies.values() for binding in policy["bindings"]},
        key=str.casefold,
    )
    role_state = allow_state if allow_state is not EvidenceSourceState.COMPLETE else EvidenceSourceState.COMPLETE
    role_diagnostics: list[str] = []
    if role_state is not EvidenceSourceState.COMPLETE:
        role_diagnostics.append("role set incomplete because allow-policy evidence is incomplete")
    roles: list[dict[str, Any]] = []
    for role_id in role_ids:
        try:
            roles.append(_role_record(clients.roles.get_role(request={"name": role_id}), role_id))
        except Exception as exc:  # noqa: BLE001
            state = _failure_state(exc)
            if state is EvidenceSourceState.ACCESS_DENIED:
                role_state = state
            elif role_state is EvidenceSourceState.COMPLETE:
                role_state = EvidenceSourceState.PARTIAL
            role_diagnostics.append(f"unresolved role definition: {role_id}")
            record_discovery_failure(
                exc=exc,
                resource_type="GCP IAM role definition",
                permission="iam.roles.get",
                cloud="gcp",
                warnings=warnings,
                missing=missing,
            )

    deny_state = EvidenceSourceState.COMPLETE
    deny_diagnostics: list[str] = []
    deny_records: dict[str, dict[str, Any]] = {}
    deny_count = 0
    for scope in hierarchy:
        attachment = f"cloudresourcemanager.googleapis.com/{scope}"
        parent = f"policies/{quote(attachment, safe='')}/denypolicies"
        try:
            for policy in clients.denies.list_policies(request={"parent": parent, "page_size": min(maximum + 1, 1000)}):
                if deny_count >= maximum:
                    deny_state = EvidenceSourceState.TRUNCATED
                    deny_diagnostics.append(f"deny policy collection capped at {maximum} records")
                    break
                record = _deny_record(policy, attachment)
                deny_records[record["name"] or f"{attachment}:{deny_count}"] = record
                deny_count += 1
        except Exception as exc:  # noqa: BLE001
            state = _failure_state(exc)
            if state is EvidenceSourceState.ACCESS_DENIED or deny_state is EvidenceSourceState.COMPLETE:
                deny_state = state
            deny_diagnostics.append(f"unreadable deny policies: {scope}")
            record_discovery_failure(
                exc=exc,
                resource_type=f"GCP deny policies for {scope}",
                permission="iam.denypolicies.list",
                cloud="gcp",
                warnings=warnings,
                missing=missing,
            )
    deny_state = _merge_state(deny_state, hierarchy_state)
    if hierarchy_state is not EvidenceSourceState.COMPLETE:
        deny_diagnostics.append("parent hierarchy unavailable; inherited deny policies may be missing")

    pab_state = EvidenceSourceState.COMPLETE
    pab_diagnostics: list[str] = []
    pab_records: dict[str, dict[str, Any]] = {}
    pab_bindings: dict[str, dict[str, Any]] = {}
    organization_scope = next((scope for scope in hierarchy if scope.startswith("organizations/")), "")
    if organization_scope:
        try:
            for policy in clients.pabs.list_principal_access_boundary_policies(
                request={"parent": f"{organization_scope}/locations/global", "page_size": min(maximum + 1, 1000)}
            ):
                if len(pab_records) >= maximum:
                    pab_state = EvidenceSourceState.TRUNCATED
                    pab_diagnostics.append(f"PAB policy collection capped at {maximum} records")
                    break
                record = _pab_record(policy)
                pab_records[record["name"]] = record
        except Exception as exc:  # noqa: BLE001
            pab_state = _failure_state(exc)
            pab_diagnostics.append("PAB policy list unavailable")
            record_discovery_failure(
                exc=exc,
                resource_type="GCP principal access boundary policies",
                permission="iam.principalaccessboundarypolicies.list",
                cloud="gcp",
                warnings=warnings,
                missing=missing,
            )
    for scope in hierarchy:
        try:
            for binding in clients.policy_bindings.list_policy_bindings(
                request={"parent": f"{scope}/locations/global", "page_size": min(maximum + 1, 1000)}
            ):
                if len(pab_bindings) >= maximum:
                    pab_state = EvidenceSourceState.TRUNCATED
                    pab_diagnostics.append(f"PAB binding collection capped at {maximum} records")
                    break
                record = _pab_binding_record(binding)
                pab_bindings[record["name"]] = record
        except Exception as exc:  # noqa: BLE001
            state = _failure_state(exc)
            if state is EvidenceSourceState.ACCESS_DENIED or pab_state is EvidenceSourceState.COMPLETE:
                pab_state = state
            pab_diagnostics.append(f"PAB bindings unavailable: {scope}")
            record_discovery_failure(
                exc=exc,
                resource_type=f"GCP policy bindings for {scope}",
                permission="iam.policybindings.list",
                cloud="gcp",
                warnings=warnings,
                missing=missing,
            )
    pab_state = _merge_state(pab_state, hierarchy_state)
    if hierarchy_state is not EvidenceSourceState.COMPLETE:
        pab_diagnostics.append("parent hierarchy unavailable; organization PAB evidence may be missing")
    if pab_state is EvidenceSourceState.COMPLETE and (pab_records or pab_bindings):
        pab_state = EvidenceSourceState.PARTIAL
        pab_diagnostics.append("PAB evidence is preserved but boundary evaluation is not implemented")

    return {
        "iam_observed_at": observed_at,
        "iam_hierarchy": hierarchy,
        "allow_policies": sorted(allow_policies.values(), key=lambda item: item["resource"]),
        "role_definitions": sorted(roles, key=lambda item: item["id"].casefold()),
        "deny_policies": sorted(deny_records.values(), key=lambda item: (item["attachment_point"], item["name"])),
        "pab_policies": sorted(pab_records.values(), key=lambda item: item["name"]),
        "pab_bindings": sorted(pab_bindings.values(), key=lambda item: item["name"]),
        "iam_sources": [
            _source(
                "allow_policies",
                allow_state,
                diagnostics=allow_diagnostics,
                provenance=("cloudasset.assets.list(IAM_POLICY)", "resourcemanager.getIamPolicy(version=3)"),
            ),
            _source(
                "role_definitions",
                role_state,
                diagnostics=role_diagnostics,
                provenance=("iam.roles.get",),
            ),
            _source(
                "resource_hierarchy",
                hierarchy_state,
                diagnostics=hierarchy_diagnostics,
                provenance=("resourcemanager.projects.get", "resourcemanager.folders.get"),
            ),
            _source(
                "deny_policies",
                deny_state,
                diagnostics=deny_diagnostics,
                provenance=("iam.v2.policies.list",),
            ),
            _source(
                "principal_access_boundaries",
                pab_state,
                diagnostics=pab_diagnostics,
                provenance=("iam.v3.principalAccessBoundaryPolicies.list", "iam.v3.policyBindings.list"),
            ),
        ],
    }


__all__ = ["collect_gcp_authorization"]
