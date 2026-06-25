"""GCP Organization inventory — org → folders → projects → IAM/org-policies.

Answers "what does our GCP estate look like" for a CISO or an agent: the resource
hierarchy (Organization → Folders → Projects), the org/folder-level IAM bindings
that grant DOWN to every child project, and the organization policies that bound
them. Emitted as ORG / FOLDER / PROJECT(ACCOUNT) graph nodes with a ``CONTAINS``
hierarchy so the estate is traversable top-down then drill-down — the GCP analogue
of the AWS Organizations OU tree and the Azure management-group hierarchy.

Trust posture: read-only (Cloud Resource Manager ``search`` / ``list`` /
``getIamPolicy`` and Org Policy ``getEffectiveOrgPolicy`` only — no writes,
agentless, token / ADC only, never passwords). A standalone project (not in an
org) degrades to ``status: "not_in_org"``; missing SDK / credentials degrade to a
clear status, never a crash.

Authentication mirrors :mod:`agent_bom.cloud.gcp_inventory`: when
``AGENT_BOM_GCP_IMPERSONATE_SA`` names a read-only service account, every call
runs as short-lived impersonated credentials for that SA.

Requires ``google-cloud-resource-manager`` (and optionally
``google-cloud-org-policy``). Install with::

    pip install 'agent-bom[gcp]'
"""

from __future__ import annotations

import logging
import os
from typing import Any

from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode

from .gcp_inventory import (
    INVENTORY_ENV_FLAG,
    _classify_role_privilege,
    _policy_bindings,
    _resolve_impersonation,
    inventory_enabled,
)
from .normalization import sanitize_discovery_warning

logger = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}

# Read-only IAM permissions this discoverer is allowed to exercise. Kept here so
# the per-run discovery envelope ``permissions_used`` stays honest: the producer
# owns the catalog, not external docs.
_GCP_ORG_PERMISSIONS: tuple[str, ...] = (
    "resourcemanager.organizations.get",
    "resourcemanager.organizations.getIamPolicy",
    "resourcemanager.folders.list",
    "resourcemanager.folders.getIamPolicy",
    "resourcemanager.projects.list",
    "resourcemanager.projects.getIamPolicy",
    "orgpolicy.policies.list",
)

# Cap the folder recursion defensively for very large orgs (GCP allows folder
# nesting up to 10 deep; 12 leaves headroom while bounding pathological input).
_MAX_FOLDER_DEPTH = 12
# Cap total folders/projects walked so a huge estate can't run unbounded.
_MAX_NODES = int(os.environ.get("AGENT_BOM_GCP_MAX_PROJECTS", "200") or "200")


def discover_organization(credentials: Any = None, *, force: bool = False) -> dict[str, Any]:
    """Enumerate the GCP Organization: folders, projects, IAM bindings, org policies.

    Returns a payload destined for ``report_json`` (carried on the GCP inventory
    payload under ``gcp_organization``) with a ``status``:

    - ``"disabled"``     — the feature flag is off and ``force`` was not set.
    - ``"sdk_missing"``  — google-cloud-resource-manager is not installed.
    - ``"not_in_org"``   — no organization is visible (a standalone project).
    - ``"ok"``           — enumeration ran (possibly with per-call warnings).

    Read-only and crash-safe: SDK absence, missing credentials, and per-call
    access denials all degrade to a clear status plus warnings. Never raises.
    """
    result: dict[str, Any] = {
        "status": "disabled",
        "org_id": "",
        "org_name": "",
        "folders": [],
        "projects": [],
        "iam_bindings": [],
        "org_policies": [],
        "findings": [],
        "warnings": [],
        "discovery_envelope": None,
    }
    if not force and not inventory_enabled():
        return result

    try:
        from google.cloud import resourcemanager_v3  # noqa: F401
    except ImportError:
        result["status"] = "sdk_missing"
        result["warnings"] = ["google-cloud-resource-manager is required for GCP org inventory. Install with: pip install 'agent-bom[gcp]'"]
        return result

    warnings: list[str] = result["warnings"]
    credentials = _resolve_impersonation(credentials, warnings)

    org_id, org_name = _search_organization(credentials, warnings)
    if not org_id:
        result["status"] = "not_in_org"
        return result
    result["org_id"] = org_id
    result["org_name"] = org_name

    org_resource = f"organizations/{org_id}"
    # Recursive folder tree under the organization.
    _walk_folders(credentials, org_resource, parent_id=org_resource, depth=0, result=result, warnings=warnings)

    # Projects directly under the org + under each discovered folder.
    parents = [org_resource] + [f["id"] for f in result["folders"]]
    for parent in parents:
        if len(result["projects"]) >= _MAX_NODES:
            break
        _list_projects(credentials, parent, result=result, warnings=warnings)

    # Org/folder-level IAM bindings (these grant DOWN to all child projects).
    iam_scopes = [(org_resource, "organization")] + [(f["id"], "folder") for f in result["folders"]]
    for scope_resource, scope_level in iam_scopes:
        _collect_iam_bindings(credentials, scope_resource, scope_level, result=result, warnings=warnings)

    # Organization policies / constraints (the AWS-SCP equivalent), best-effort.
    org_policy_scopes = [org_resource] + [f["id"] for f in result["folders"]]
    _collect_org_policies(credentials, org_policy_scopes, result=result, warnings=warnings)

    _derive_findings(result)

    result["status"] = "ok"
    result["discovery_envelope"] = DiscoveryEnvelope(
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=(f"gcp:organization/{org_id}",),
        permissions_used=_GCP_ORG_PERMISSIONS,
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    ).to_dict()
    return result


def discover_organization_tree(credentials: Any = None, *, force: bool = False) -> dict[str, Any]:
    """Alias for :func:`discover_organization` (explicit-tree-intent call site)."""
    return discover_organization(credentials, force=force)


# ---------------------------------------------------------------------------
# Organization search
# ---------------------------------------------------------------------------


def _search_organization(credentials: Any, warnings: list[str]) -> tuple[str, str]:
    """Return ``(org_id, display_name)`` for the visible organization, else ``("", "")``.

    Uses Cloud Resource Manager v3 ``organizations.search`` — the credential's
    accessible org. Degrades to ``("", "")`` (a standalone project, no org access)
    with a warning on any error; never raises.
    """
    try:
        from google.cloud import resourcemanager_v3
    except ImportError:
        return "", ""
    try:
        client = resourcemanager_v3.OrganizationsClient(credentials=credentials)
        for org in client.search_organizations(request={}):
            name = str(getattr(org, "name", "") or "")  # "organizations/123456789"
            org_id = name.rsplit("/", 1)[-1] if "/" in name else name
            if org_id:
                return org_id, str(getattr(org, "display_name", "") or "")
    except Exception as exc:  # noqa: BLE001 — no org / no access is not an error
        warnings.append(f"Could not search organizations: {sanitize_discovery_warning(exc)}")
    return "", ""


# ---------------------------------------------------------------------------
# Folder tree (recursive)
# ---------------------------------------------------------------------------


def _walk_folders(
    credentials: Any,
    parent: str,
    *,
    parent_id: str,
    depth: int,
    result: dict[str, Any],
    warnings: list[str],
) -> None:
    """Recursively list folders under *parent* (an ``organizations/`` or ``folders/`` name)."""
    if depth > _MAX_FOLDER_DEPTH or len(result["folders"]) >= _MAX_NODES:
        return
    try:
        from google.cloud import resourcemanager_v3
    except ImportError:
        return
    try:
        client = resourcemanager_v3.FoldersClient(credentials=credentials)
        for folder in client.list_folders(request={"parent": parent}):
            folder_name = str(getattr(folder, "name", "") or "")  # "folders/456"
            if not folder_name:
                continue
            result["folders"].append(
                {
                    "id": folder_name,
                    "name": str(getattr(folder, "display_name", "") or "") or folder_name,
                    "parent_id": parent_id,
                }
            )
            if len(result["folders"]) >= _MAX_NODES:
                return
            _walk_folders(
                credentials,
                folder_name,
                parent_id=folder_name,
                depth=depth + 1,
                result=result,
                warnings=warnings,
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list folders under {parent}: {sanitize_discovery_warning(exc)}")


# ---------------------------------------------------------------------------
# Projects (per parent)
# ---------------------------------------------------------------------------


def _list_projects(credentials: Any, parent: str, *, result: dict[str, Any], warnings: list[str]) -> None:
    """List ACTIVE projects directly under *parent*, placing each under its parent."""
    try:
        from google.cloud import resourcemanager_v3
    except ImportError:
        return
    seen = {p["id"] for p in result["projects"]}
    try:
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        for project in client.list_projects(request={"parent": parent}):
            project_id = str(getattr(project, "project_id", "") or "").strip()
            if not project_id or project_id in seen:
                continue
            state = str(getattr(getattr(project, "state", None), "name", "") or getattr(project, "state", "") or "")
            if state and state.upper() not in ("ACTIVE", "STATE_UNSPECIFIED"):
                continue
            seen.add(project_id)
            result["projects"].append(
                {
                    "id": project_id,
                    "name": str(getattr(project, "display_name", "") or "") or project_id,
                    "number": str(getattr(project, "name", "") or "").rsplit("/", 1)[-1],
                    "parent_id": parent,
                    "state": state,
                }
            )
            if len(result["projects"]) >= _MAX_NODES:
                return
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list projects under {parent}: {sanitize_discovery_warning(exc)}")


def list_project_ids(credentials: Any = None, *, force: bool = False) -> list[str]:
    """Return every ACTIVE project id reachable in the org/folder tree (read-only).

    The fan-out source for :func:`agent_bom.cloud.gcp_inventory.discover_all_project_inventories`.
    Falls back to the ambient ``GOOGLE_CLOUD_PROJECT`` (a standalone project not in
    an org) when no org tree is visible. Never raises.
    """
    org = discover_organization(credentials, force=force)
    project_ids = [str(p.get("id", "")).strip() for p in org.get("projects", []) if str(p.get("id", "")).strip()]
    if project_ids:
        return project_ids[:_MAX_NODES]
    single = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
    return [single] if single else []


# ---------------------------------------------------------------------------
# IAM bindings (org + folder level — inherited DOWN to child projects)
# ---------------------------------------------------------------------------


def _collect_iam_bindings(
    credentials: Any,
    scope_resource: str,
    scope_level: str,
    *,
    result: dict[str, Any],
    warnings: list[str],
) -> None:
    """Read the org/folder IAM policy → role + members bindings (inherited down).

    A binding at the organization or a folder grants its role to its members on
    EVERY descendant project — the inheritance the graph models as a
    ``HAS_PERMISSION`` edge from the principal to the org/folder scope node, with
    the privilege classified by the shared GCP role classifier.
    """
    try:
        if scope_level == "organization":
            from google.cloud import resourcemanager_v3

            client: Any = resourcemanager_v3.OrganizationsClient(credentials=credentials)
        else:
            from google.cloud import resourcemanager_v3

            client = resourcemanager_v3.FoldersClient(credentials=credentials)
        from google.iam.v1 import iam_policy_pb2

        policy = client.get_iam_policy(request=iam_policy_pb2.GetIamPolicyRequest(resource=scope_resource))
    except ImportError:
        warnings.append("google-cloud-resource-manager not installed. Skipping org/folder IAM-binding discovery.")
        return
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not read IAM policy for {scope_resource}: {sanitize_discovery_warning(exc)}")
        return

    for binding in _policy_bindings(policy):
        role = str(binding.get("role", "") or "").strip()
        if not role:
            continue
        members = [str(m).strip() for m in (binding.get("members", []) or []) if str(m).strip()]
        if not members:
            continue
        result["iam_bindings"].append(
            {
                "scope_id": scope_resource,
                "scope_level": scope_level,
                "role": role,
                "members": members,
                "privilege_level": _classify_role_privilege(role),
            }
        )


# ---------------------------------------------------------------------------
# Organization policies / constraints (AWS-SCP equivalent), best-effort
# ---------------------------------------------------------------------------


def _collect_org_policies(
    credentials: Any,
    scopes: list[str],
    *,
    result: dict[str, Any],
    warnings: list[str],
) -> None:
    """List org-policy constraints set on the org/folders (read-only, best-effort).

    The GCP analogue of AWS Service Control Policies: each policy applies a
    constraint (e.g. ``constraints/iam.disableServiceAccountKeyCreation``) to a
    scope and inherits down. Degrades silently when the Org Policy API / SDK is
    unavailable — the org tree is still useful without it.
    """
    try:
        from google.cloud import orgpolicy_v2
    except ImportError:
        warnings.append("google-cloud-org-policy not installed. Skipping org-policy constraint discovery.")
        return
    try:
        client = orgpolicy_v2.OrgPolicyClient(credentials=credentials)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not initialise the Org Policy client: {sanitize_discovery_warning(exc)}")
        return

    seen: set[str] = set()
    for scope in scopes:
        try:
            for policy in client.list_policies(request={"parent": scope}):
                name = str(getattr(policy, "name", "") or "")
                constraint = name.rsplit("/", 1)[-1] if "/" in name else name
                if not constraint:
                    continue
                key = f"{scope}|{constraint}"
                if key in seen:
                    continue
                seen.add(key)
                result["org_policies"].append(
                    {
                        "id": name or constraint,
                        "constraint": constraint,
                        "scope_id": scope,
                    }
                )
        except Exception as exc:  # noqa: BLE001 — per-scope access denial degrades
            warnings.append(f"Could not list org policies for {scope}: {sanitize_discovery_warning(exc)}")


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def _derive_findings(result: dict[str, Any]) -> None:
    """Flag estate-shape risks, mirroring the AWS-org findings (read-only signal)."""
    if not result["org_policies"] and result["projects"]:
        result["findings"].append(
            {
                "severity": "medium",
                "title": "No organization policy constraints",
                "detail": (
                    f"{len(result['projects'])} projects, no org-policy constraints — "
                    "no org-wide guardrails (the AWS-SCP equivalent) apply."
                ),
            }
        )
    if result["projects"] and not result["folders"]:
        result["findings"].append(
            {
                "severity": "low",
                "title": "Flat organization (no folders)",
                "detail": (f"{len(result['projects'])} projects sit directly under the org with no folders — no tiered guardrails."),
            }
        )


__all__ = [
    "INVENTORY_ENV_FLAG",
    "discover_organization",
    "discover_organization_tree",
    "list_project_ids",
]
