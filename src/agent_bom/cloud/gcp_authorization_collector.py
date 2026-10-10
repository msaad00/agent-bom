"""Read-only, decision-oriented GCP IAM evidence collection."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, Iterable
from urllib.parse import quote

from agent_bom.cloud.authorization_evidence import EvidenceSourceState

from .aws_inventory import is_access_denied_error, record_discovery_failure
from .gcp_authorization_records import _deny_record, _get, _pab_binding_record, _pab_record, _policy_record, _role_record, _text

_DEFAULT_MAX_RECORDS = int(os.environ.get("AGENT_BOM_GCP_AUTHORIZATION_MAX_RECORDS", "50000") or "50000")

# Evidence sources in report order, with the read-only API calls backing each one.
_SOURCE_PROVENANCE: dict[str, tuple[str, ...]] = {
    "allow_policies": ("cloudasset.assets.list(IAM_POLICY)", "resourcemanager.getIamPolicy(version=3)"),
    "role_definitions": ("iam.roles.get",),
    "resource_hierarchy": ("resourcemanager.projects.get", "resourcemanager.folders.get"),
    "deny_policies": ("iam.v2.policies.list",),
    "principal_access_boundaries": ("iam.v3.principalAccessBoundaryPolicies.list", "iam.v3.policyBindings.list"),
}


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


def _client_class(module: Any, attribute: str) -> Any:
    """Return ``module.attribute``, or raise ``ImportError`` when the SDK lacks it.

    ``google.cloud`` is a namespace package assembled from one distribution per
    service, so the modules can import while still missing the client classes we
    need — a partial ``[gcp]`` install, or a version predating a client. That is
    the same operator condition as an absent SDK, so it is reported the same way:
    the caller's ``ImportError`` handler degrades to ``SDK_MISSING``. Letting the
    raw ``AttributeError`` escape would abort the whole GCP inventory walk, whose
    call site does not guard it.
    """
    try:
        return getattr(module, attribute)
    except AttributeError as exc:
        raise ImportError(
            f"{getattr(module, '__name__', module)} has no {attribute} — the installed "
            "google-cloud SDKs are incomplete. Install with: pip install 'agent-bom[gcp]'"
        ) from exc


def _load_clients(credentials: Any) -> Any:
    from google.cloud import (  # type: ignore[attr-defined]  # namespace package exports
        asset_v1,
        iam_admin_v1,
        iam_v2,
        iam_v3,
        resourcemanager_v3,
    )

    return SimpleNamespace(
        assets=_client_class(asset_v1, "AssetServiceClient")(credentials=credentials),
        projects=_client_class(resourcemanager_v3, "ProjectsClient")(credentials=credentials),
        folders=_client_class(resourcemanager_v3, "FoldersClient")(credentials=credentials),
        organizations=_client_class(resourcemanager_v3, "OrganizationsClient")(credentials=credentials),
        roles=_client_class(iam_admin_v1, "IAMClient")(credentials=credentials),
        denies=_client_class(iam_v2, "PoliciesClient")(credentials=credentials),
        pabs=_client_class(iam_v3, "PrincipalAccessBoundaryPoliciesClient")(credentials=credentials),
        policy_bindings=_client_class(iam_v3, "PolicyBindingsClient")(credentials=credentials),
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


def _record_failure(
    exc: BaseException,
    resource_type: str,
    permission: str,
    warnings: list[str],
    missing: list[dict[str, str]] | None,
) -> None:
    record_discovery_failure(
        exc=exc,
        resource_type=resource_type,
        permission=permission,
        cloud="gcp",
        warnings=warnings,
        missing=missing,
    )


def _sdk_missing_result(project_id: str, observed_at: str) -> dict[str, Any]:
    return {
        "iam_observed_at": observed_at,
        "iam_scope": f"projects/{project_id}",
        "iam_hierarchy": [f"projects/{project_id}"],
        "allow_policies": [],
        "role_definitions": [],
        "deny_policies": [],
        "pab_policies": [],
        "pab_bindings": [],
        "iam_sources": [_source(name, EvidenceSourceState.SDK_MISSING) for name in _SOURCE_PROVENANCE],
    }


def _collect_hierarchy(
    clients: Any,
    requested_project_scope: str,
    warnings: list[str],
    missing: list[dict[str, str]] | None,
) -> tuple[str, list[str], EvidenceSourceState, list[str]]:
    """Resolve the canonical project scope and walk its folder/organization ancestry."""
    project_scope = requested_project_scope
    hierarchy = [project_scope]
    hierarchy_state = EvidenceSourceState.COMPLETE
    hierarchy_diagnostics: list[str] = []
    try:
        project = clients.projects.get_project(request={"name": requested_project_scope})
        canonical_project_scope = _text(_get(project, "name"))
        if canonical_project_scope.startswith("projects/"):
            project_scope = canonical_project_scope
            hierarchy[0] = project_scope
        else:
            hierarchy_state = EvidenceSourceState.PARTIAL
            hierarchy_diagnostics.append("project response omitted canonical resource name")
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
        _record_failure(exc, "GCP resource hierarchy", "resourcemanager.projects.get", warnings, missing)
    return project_scope, hierarchy, hierarchy_state, hierarchy_diagnostics


def _collect_asset_policies(
    clients: Any,
    requested_project_scope: str,
    maximum: int,
    warnings: list[str],
    missing: list[dict[str, str]] | None,
) -> tuple[dict[str, dict[str, Any]], EvidenceSourceState, list[str], int]:
    """Page resource-local allow policies from Cloud Asset Inventory, capped at ``maximum``."""
    allow_policies: dict[str, dict[str, Any]] = {}
    allow_state = EvidenceSourceState.COMPLETE
    allow_diagnostics: list[str] = []
    dropped_allow_records = 0
    try:
        assets, truncated = _bounded(
            clients.assets.list_assets(
                request={
                    "parent": requested_project_scope,
                    "content_type": "IAM_POLICY",
                    "page_size": min(maximum + 1, 1000),
                }
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
        _record_failure(exc, "GCP resource-local IAM policies", "cloudasset.assets.listIamPolicy", warnings, missing)
    return allow_policies, allow_state, allow_diagnostics, dropped_allow_records


def _collect_hierarchy_policies(
    clients: Any,
    hierarchy: list[str],
    allow_policies: dict[str, dict[str, Any]],
    allow_state: EvidenceSourceState,
    hierarchy_state: EvidenceSourceState,
    allow_diagnostics: list[str],
    warnings: list[str],
    missing: list[dict[str, str]] | None,
) -> tuple[EvidenceSourceState, EvidenceSourceState, int, bool]:
    """Read the version-3 allow policy of every project/folder/organization ancestor."""
    dropped_allow_records = 0
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
            permission = f"resourcemanager.{scope.split('/', 1)[0]}.getIamPolicy"
            _record_failure(exc, f"GCP IAM policy for {scope}", permission, warnings, missing)
    return allow_state, hierarchy_state, dropped_allow_records, hierarchy_policy_failed


def _collect_allow_evidence(
    clients: Any,
    requested_project_scope: str,
    hierarchy: list[str],
    hierarchy_state: EvidenceSourceState,
    hierarchy_diagnostics: list[str],
    maximum: int,
    warnings: list[str],
    missing: list[dict[str, str]] | None,
) -> tuple[dict[str, dict[str, Any]], EvidenceSourceState, list[str], EvidenceSourceState]:
    """Collect resource-local and inherited allow policies and grade their completeness."""
    allow_policies, allow_state, allow_diagnostics, dropped_allow_records = _collect_asset_policies(
        clients, requested_project_scope, maximum, warnings, missing
    )
    allow_state, hierarchy_state, dropped_hierarchy_records, hierarchy_policy_failed = _collect_hierarchy_policies(
        clients, hierarchy, allow_policies, allow_state, hierarchy_state, allow_diagnostics, warnings, missing
    )
    dropped_allow_records += dropped_hierarchy_records
    if hierarchy_state is not EvidenceSourceState.COMPLETE and allow_state is EvidenceSourceState.COMPLETE:
        allow_state = hierarchy_state
        allow_diagnostics.append("parent hierarchy unavailable; inherited allow policies may be missing")
    if dropped_allow_records and allow_state is EvidenceSourceState.COMPLETE:
        allow_state = EvidenceSourceState.PARTIAL
        allow_diagnostics.append(f"dropped {dropped_allow_records} malformed allow policy records")
    if hierarchy_policy_failed:
        hierarchy_diagnostics.append("one or more hierarchy policies were unavailable")
    return allow_policies, allow_state, allow_diagnostics, hierarchy_state


def _collect_role_definitions(
    clients: Any,
    allow_policies: dict[str, dict[str, Any]],
    allow_state: EvidenceSourceState,
    warnings: list[str],
    missing: list[dict[str, str]] | None,
) -> tuple[list[dict[str, Any]], EvidenceSourceState, list[str]]:
    """Resolve every role referenced by an allow binding into its permission set."""
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
            _record_failure(exc, "GCP IAM role definition", "iam.roles.get", warnings, missing)
    return roles, role_state, role_diagnostics


def _collect_deny_policies(
    clients: Any,
    hierarchy: list[str],
    hierarchy_state: EvidenceSourceState,
    maximum: int,
    warnings: list[str],
    missing: list[dict[str, str]] | None,
) -> tuple[dict[str, dict[str, Any]], EvidenceSourceState, list[str]]:
    """Page IAM v2 deny policies attached at each hierarchy level, capped at ``maximum``."""
    deny_state = EvidenceSourceState.COMPLETE
    deny_diagnostics: list[str] = []
    deny_records: dict[str, dict[str, Any]] = {}
    deny_count = 0
    malformed_deny_rules = 0
    for scope in hierarchy:
        attachment = f"cloudresourcemanager.googleapis.com/{scope}"
        parent = f"policies/{quote(attachment, safe='')}/denypolicies"
        try:
            for policy in clients.denies.list_policies(request={"parent": parent, "page_size": min(maximum + 1, 1000)}):
                if deny_count >= maximum:
                    deny_state = EvidenceSourceState.TRUNCATED
                    deny_diagnostics.append(f"deny policy collection capped at {maximum} records")
                    break
                deny_record, dropped = _deny_record(policy, attachment)
                malformed_deny_rules += dropped
                if deny_record is not None:
                    deny_records[deny_record["name"]] = deny_record
                deny_count += 1
        except Exception as exc:  # noqa: BLE001
            state = _failure_state(exc)
            if state is EvidenceSourceState.ACCESS_DENIED or deny_state is EvidenceSourceState.COMPLETE:
                deny_state = state
            deny_diagnostics.append(f"unreadable deny policies: {scope}")
            _record_failure(exc, f"GCP deny policies for {scope}", "iam.denypolicies.list", warnings, missing)
    deny_state = _merge_state(deny_state, hierarchy_state)
    if malformed_deny_rules and deny_state is EvidenceSourceState.COMPLETE:
        deny_state = EvidenceSourceState.PARTIAL
        suffix = "rule" if malformed_deny_rules == 1 else "rules"
        deny_diagnostics.append(f"dropped {malformed_deny_rules} malformed deny {suffix}")
    if hierarchy_state is not EvidenceSourceState.COMPLETE:
        deny_diagnostics.append("parent hierarchy unavailable; inherited deny policies may be missing")
    return deny_records, deny_state, deny_diagnostics


def _collect_pab_policies(
    clients: Any,
    hierarchy: list[str],
    maximum: int,
    warnings: list[str],
    missing: list[dict[str, str]] | None,
) -> tuple[dict[str, dict[str, Any]], EvidenceSourceState, list[str]]:
    """Page organization-level principal access boundary policies, capped at ``maximum``."""
    pab_state = EvidenceSourceState.COMPLETE
    pab_diagnostics: list[str] = []
    pab_records: dict[str, dict[str, Any]] = {}
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
            permission = "iam.principalaccessboundarypolicies.list"
            _record_failure(exc, "GCP principal access boundary policies", permission, warnings, missing)
    return pab_records, pab_state, pab_diagnostics


def _collect_pab_bindings(
    clients: Any,
    hierarchy: list[str],
    maximum: int,
    pab_state: EvidenceSourceState,
    pab_diagnostics: list[str],
    warnings: list[str],
    missing: list[dict[str, str]] | None,
) -> tuple[dict[str, dict[str, Any]], EvidenceSourceState]:
    """Page IAM v3 policy bindings at each hierarchy level, capped at ``maximum``."""
    pab_bindings: dict[str, dict[str, Any]] = {}
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
            _record_failure(exc, f"GCP policy bindings for {scope}", "iam.policybindings.list", warnings, missing)
    return pab_bindings, pab_state


def _collect_pab_evidence(
    clients: Any,
    hierarchy: list[str],
    hierarchy_state: EvidenceSourceState,
    maximum: int,
    warnings: list[str],
    missing: list[dict[str, str]] | None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], EvidenceSourceState, list[str]]:
    """Collect PAB policies and bindings and grade their completeness."""
    pab_records, pab_state, pab_diagnostics = _collect_pab_policies(clients, hierarchy, maximum, warnings, missing)
    pab_bindings, pab_state = _collect_pab_bindings(clients, hierarchy, maximum, pab_state, pab_diagnostics, warnings, missing)
    pab_state = _merge_state(pab_state, hierarchy_state)
    if hierarchy_state is not EvidenceSourceState.COMPLETE:
        pab_diagnostics.append("parent hierarchy unavailable; organization PAB evidence may be missing")
    if pab_state is EvidenceSourceState.COMPLETE and (pab_records or pab_bindings):
        pab_state = EvidenceSourceState.PARTIAL
        pab_diagnostics.append("PAB evidence is preserved but target principal sets are not resolved")
    return pab_records, pab_bindings, pab_state, pab_diagnostics


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
            return _sdk_missing_result(project_id, observed_at)

    requested_project_scope = f"projects/{project_id}"
    project_scope, hierarchy, hierarchy_state, hierarchy_diagnostics = _collect_hierarchy(
        clients, requested_project_scope, warnings, missing
    )
    allow_policies, allow_state, allow_diagnostics, hierarchy_state = _collect_allow_evidence(
        clients, requested_project_scope, hierarchy, hierarchy_state, hierarchy_diagnostics, maximum, warnings, missing
    )
    roles, role_state, role_diagnostics = _collect_role_definitions(clients, allow_policies, allow_state, warnings, missing)
    deny_records, deny_state, deny_diagnostics = _collect_deny_policies(clients, hierarchy, hierarchy_state, maximum, warnings, missing)
    pab_records, pab_bindings, pab_state, pab_diagnostics = _collect_pab_evidence(
        clients, hierarchy, hierarchy_state, maximum, warnings, missing
    )
    source_states = {
        "allow_policies": (allow_state, allow_diagnostics),
        "role_definitions": (role_state, role_diagnostics),
        "resource_hierarchy": (hierarchy_state, hierarchy_diagnostics),
        "deny_policies": (deny_state, deny_diagnostics),
        "principal_access_boundaries": (pab_state, pab_diagnostics),
    }
    return {
        "iam_observed_at": observed_at,
        "iam_scope": project_scope,
        "iam_hierarchy": hierarchy,
        "allow_policies": sorted(allow_policies.values(), key=lambda item: item["resource"]),
        "role_definitions": sorted(roles, key=lambda item: item["id"].casefold()),
        "deny_policies": sorted(deny_records.values(), key=lambda item: (item["attachment_point"], item["name"])),
        "pab_policies": sorted(pab_records.values(), key=lambda item: item["name"]),
        "pab_bindings": sorted(pab_bindings.values(), key=lambda item: item["name"]),
        "iam_sources": [
            _source(name, state, diagnostics=diagnostics, provenance=_SOURCE_PROVENANCE[name])
            for name, (state, diagnostics) in source_states.items()
        ],
    }


__all__ = ["collect_gcp_authorization"]
