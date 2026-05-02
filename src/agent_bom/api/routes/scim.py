"""SCIM 2.0 lifecycle endpoints for enterprise identity provisioning."""

from __future__ import annotations

import re
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response

from agent_bom.api.audit_log import log_action
from agent_bom.api.scim import extract_scim_roles, scim_base_path, scim_enabled_from_env, scim_role_attribute
from agent_bom.api.scim_store import SCIMGroup, SCIMUser
from agent_bom.api.stores import _get_scim_store
from agent_bom.platform_invariants import now_utc_iso

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_SERVICE_PROVIDER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCIM_SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"
SCIM_RESOURCE_TYPE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCIM_AGENT_BOM_USER_EXTENSION = "urn:agent-bom:params:scim:schemas:extension:identity:1.0:User"
router = APIRouter(prefix=scim_base_path(), tags=["scim"])
_FILTER_RE = re.compile(r'^\s*(userName|displayName|externalId|id)\s+eq\s+"([^"]{1,512})"\s*$')
# `active` is a boolean filter — admins use `?filter=active eq false` to audit
# deactivated users (Okta/Azure AD deprovisioning verification). The regex
# accepts an optional quoted form so SCIM clients that always quote literals
# still work.
_ACTIVE_FILTER_RE = re.compile(r'^\s*active\s+eq\s+"?(true|false)"?\s*$', re.IGNORECASE)


def _tenant_id(request: Request) -> str:
    return str(getattr(request.state, "tenant_id", "") or "default")


def _actor(request: Request) -> str:
    return str(getattr(request.state, "api_key_name", None) or "scim-provisioner")


def _require_scim(request: Request) -> None:
    if getattr(request.state, "auth_method", None) != "scim_bearer":
        raise HTTPException(status_code=401, detail="SCIM bearer token required")


def _parse_filter(raw: str | None) -> tuple[str | None, str | None]:
    if not raw:
        return None, None
    match = _FILTER_RE.match(raw)
    if match:
        return match.group(1), match.group(2)
    active = _ACTIVE_FILTER_RE.match(raw)
    if active:
        return "active", active.group(1).lower()
    raise HTTPException(status_code=400, detail="Unsupported SCIM filter")


def _paginate(items: list[Any], start_index: int, count: int) -> list[Any]:
    offset = max(start_index, 1) - 1
    return items[offset : offset + max(min(count, 500), 0)]


def _location(request: Request, kind: str, resource_id: str) -> str:
    return str(request.url_for(f"scim_get_{kind}", **{f"{kind}_id": resource_id}))


def _optional_str(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _user_from_payload(tenant_id: str, body: dict[str, Any], *, existing: SCIMUser | None = None) -> SCIMUser:
    user_name = str(body.get("userName") or (existing.user_name if existing else "")).strip()
    if not user_name:
        raise HTTPException(status_code=400, detail="userName is required")
    display_name = str(body.get("displayName") or "").strip()
    if not display_name and isinstance(body.get("name"), dict):
        display_name = str(body["name"].get("formatted") or "").strip()
    if existing and not display_name:
        display_name = existing.display_name
    emails = body.get("emails", existing.emails if existing else [])
    if not isinstance(emails, list):
        raise HTTPException(status_code=400, detail="emails must be a list")
    groups = [str(group.get("value", "")).strip() for group in body.get("groups", []) if isinstance(group, dict) and group.get("value")]
    external_id = _optional_str(body.get("externalId"))
    if external_id is None and existing is not None:
        external_id = existing.external_id
    return SCIMUser(
        tenant_id=tenant_id,
        user_id=existing.user_id if existing else str(body.get("id") or uuid.uuid4()),
        external_id=external_id,
        user_name=user_name,
        display_name=display_name,
        active=bool(body.get("active", existing.active if existing else True)),
        roles=extract_scim_roles(body, existing_roles=existing.roles if existing else None),
        emails=[entry for entry in emails if isinstance(entry, dict)],
        groups=groups or (existing.groups if existing else []),
        raw=dict(body),
        created_at=existing.created_at if existing else now_utc_iso(),
        updated_at=now_utc_iso(),
    )


def _group_from_payload(tenant_id: str, body: dict[str, Any], *, existing: SCIMGroup | None = None) -> SCIMGroup:
    display_name = str(body.get("displayName") or (existing.display_name if existing else "")).strip()
    if not display_name:
        raise HTTPException(status_code=400, detail="displayName is required")
    members = body.get("members", existing.members if existing else [])
    if not isinstance(members, list):
        raise HTTPException(status_code=400, detail="members must be a list")
    external_id = _optional_str(body.get("externalId"))
    if external_id is None and existing is not None:
        external_id = existing.external_id
    return SCIMGroup(
        tenant_id=tenant_id,
        group_id=existing.group_id if existing else str(body.get("id") or uuid.uuid4()),
        external_id=external_id,
        display_name=display_name,
        members=[entry for entry in members if isinstance(entry, dict)],
        raw=dict(body),
        created_at=existing.created_at if existing else now_utc_iso(),
        updated_at=now_utc_iso(),
    )


def _user_to_scim(user: SCIMUser, request: Request) -> dict[str, Any]:
    memberships = [
        {
            "tenantId": user.tenant_id,
            "role": role,
            "active": user.active,
            "source": "scim",
        }
        for role in user.roles
    ]
    return {
        "schemas": [SCIM_USER_SCHEMA, SCIM_AGENT_BOM_USER_EXTENSION],
        "id": user.user_id,
        "externalId": user.external_id,
        "userName": user.user_name,
        "displayName": user.display_name,
        "active": user.active,
        "roles": [{"value": role, "display": role, "type": "agent_bom"} for role in user.roles],
        "emails": user.emails,
        "groups": [{"value": group_id} for group_id in user.groups],
        SCIM_AGENT_BOM_USER_EXTENSION: {
            "tenantId": user.tenant_id,
            "tenantIdSource": "AGENT_BOM_SCIM_TENANT_ID",
            "roles": user.roles,
            "memberships": memberships,
            "runtimeAuthEnforced": scim_enabled_from_env(),
        },
        "meta": {
            "resourceType": "User",
            "created": user.created_at,
            "lastModified": user.updated_at,
            "location": _location(request, "user", user.user_id),
        },
    }


def _group_to_scim(group: SCIMGroup, request: Request) -> dict[str, Any]:
    return {
        "schemas": [SCIM_GROUP_SCHEMA],
        "id": group.group_id,
        "externalId": group.external_id,
        "displayName": group.display_name,
        "members": group.members,
        "meta": {
            "resourceType": "Group",
            "created": group.created_at,
            "lastModified": group.updated_at,
            "location": _location(request, "group", group.group_id),
        },
    }


def _apply_user_patch(user: SCIMUser, body: dict[str, Any]) -> SCIMUser:
    operations = body.get("Operations", [])
    if not isinstance(operations, list):
        raise HTTPException(status_code=400, detail="Operations must be a list")
    role_attribute = scim_role_attribute()
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        op = str(operation.get("op", "replace")).lower()
        path = str(operation.get("path", "")).strip()
        value = operation.get("value")
        if op not in {"add", "replace"}:
            raise HTTPException(status_code=400, detail="Only add and replace patch operations are supported")
        if isinstance(value, dict) and not path:
            if "active" in value:
                user.active = bool(value["active"])
            if "displayName" in value:
                user.display_name = str(value["displayName"]).strip()
            if "userName" in value:
                user.user_name = str(value["userName"]).strip()
            if "emails" in value and isinstance(value["emails"], list):
                user.emails = [entry for entry in value["emails"] if isinstance(entry, dict)]
            if "roles" in value or role_attribute in value:
                user.roles = extract_scim_roles(value, existing_roles=user.roles)
            continue
        if path == "active":
            user.active = bool(value)
        elif path == "displayName":
            user.display_name = str(value or "").strip()
        elif path == "userName":
            user.user_name = str(value or "").strip()
        elif path == "emails" and isinstance(value, list):
            user.emails = [entry for entry in value if isinstance(entry, dict)]
        elif path in {"roles", role_attribute}:
            user.roles = extract_scim_roles({path: value}, existing_roles=user.roles)
        else:
            raise HTTPException(status_code=400, detail="Unsupported user patch path")
    if not user.user_name:
        raise HTTPException(status_code=400, detail="userName is required")
    user.updated_at = now_utc_iso()
    return user


def _apply_group_patch(group: SCIMGroup, body: dict[str, Any]) -> SCIMGroup:
    operations = body.get("Operations", [])
    if not isinstance(operations, list):
        raise HTTPException(status_code=400, detail="Operations must be a list")
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        op = str(operation.get("op", "replace")).lower()
        path = str(operation.get("path", "")).strip()
        value = operation.get("value")
        if op not in {"add", "replace", "remove"}:
            raise HTTPException(status_code=400, detail="Only add, replace, and remove patch operations are supported")
        if op == "remove" and path.startswith("members"):
            group.members = []
        elif path == "displayName":
            group.display_name = str(value or "").strip()
        elif path == "members" and isinstance(value, list):
            group.members = [entry for entry in value if isinstance(entry, dict)]
        elif isinstance(value, dict) and not path:
            if "displayName" in value:
                group.display_name = str(value["displayName"]).strip()
            if "members" in value and isinstance(value["members"], list):
                group.members = [entry for entry in value["members"] if isinstance(entry, dict)]
        else:
            raise HTTPException(status_code=400, detail="Unsupported group patch path")
    if not group.display_name:
        raise HTTPException(status_code=400, detail="displayName is required")
    group.updated_at = now_utc_iso()
    return group


@router.get("/ServiceProviderConfig", name="scim_service_provider_config")
async def service_provider_config(request: Request) -> dict[str, Any]:
    _require_scim(request)
    return {
        "schemas": [SCIM_SERVICE_PROVIDER_SCHEMA],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 500},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer", "primary": True}],
    }


@router.get("/Schemas", name="scim_schemas")
async def schemas(request: Request) -> dict[str, Any]:
    _require_scim(request)
    resources = [
        {
            "schemas": [SCIM_SCHEMA_SCHEMA],
            "id": SCIM_USER_SCHEMA,
            "name": "User",
            "description": "Agent BOM provisioned user",
            "attributes": [
                {"name": "userName", "type": "string", "required": True, "mutability": "readWrite"},
                {"name": "displayName", "type": "string", "required": False, "mutability": "readWrite"},
                {"name": "active", "type": "boolean", "required": False, "mutability": "readWrite"},
                {"name": "roles", "type": "complex", "multiValued": True, "required": False, "mutability": "readWrite"},
                {"name": "emails", "type": "complex", "multiValued": True, "required": False, "mutability": "readWrite"},
                {"name": "groups", "type": "complex", "multiValued": True, "required": False, "mutability": "readOnly"},
            ],
        },
        {
            "schemas": [SCIM_SCHEMA_SCHEMA],
            "id": SCIM_GROUP_SCHEMA,
            "name": "Group",
            "description": "Agent BOM provisioned group",
            "attributes": [
                {"name": "displayName", "type": "string", "required": True, "mutability": "readWrite"},
                {"name": "members", "type": "complex", "multiValued": True, "required": False, "mutability": "readWrite"},
            ],
        },
        {
            "schemas": [SCIM_SCHEMA_SCHEMA],
            "id": SCIM_AGENT_BOM_USER_EXTENSION,
            "name": "Agent BOM Tenant Membership",
            "description": "Agent BOM tenant-bound role and membership metadata derived from SCIM provisioning.",
            "attributes": [
                {"name": "tenantId", "type": "string", "required": True, "mutability": "readOnly"},
                {"name": "tenantIdSource", "type": "string", "required": True, "mutability": "readOnly"},
                {"name": "roles", "type": "string", "multiValued": True, "required": False, "mutability": "readWrite"},
                {"name": "memberships", "type": "complex", "multiValued": True, "required": False, "mutability": "readOnly"},
                {"name": "runtimeAuthEnforced", "type": "boolean", "required": True, "mutability": "readOnly"},
            ],
        },
    ]
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": len(resources),
        "startIndex": 1,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


@router.get("/ResourceTypes", name="scim_resource_types")
async def resource_types(request: Request) -> dict[str, Any]:
    _require_scim(request)
    resources = [
        {
            "schemas": [SCIM_RESOURCE_TYPE_SCHEMA],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": SCIM_USER_SCHEMA,
        },
        {
            "schemas": [SCIM_RESOURCE_TYPE_SCHEMA],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "schema": SCIM_GROUP_SCHEMA,
        },
    ]
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": len(resources),
        "startIndex": 1,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


@router.get("/Users", name="scim_list_users")
async def list_users(
    request: Request,
    scim_filter: str | None = Query(default=None, alias="filter"),
    start_index: int = Query(default=1, alias="startIndex", ge=1),
    count: int = Query(default=100, ge=0, le=500),
) -> dict[str, Any]:
    _require_scim(request)
    attr, value = _parse_filter(scim_filter)
    if attr == "active":
        # `?filter=active eq true|false` — caller wants only active or only
        # deactivated. Resolve the boolean here and let the store honour it.
        want_active = value == "true"
        all_users = _get_scim_store().list_users(_tenant_id(request), include_inactive=True)
        users = [u for u in all_users if u.active == want_active]
    else:
        users = _get_scim_store().list_users(_tenant_id(request), filter_attr=attr, filter_value=value)
    page = _paginate(users, start_index, count)
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": len(users),
        "startIndex": start_index,
        "itemsPerPage": len(page),
        "Resources": [_user_to_scim(user, request) for user in page],
    }


@router.post("/Users", status_code=201, name="scim_create_user")
async def create_user(request: Request, body: dict[str, Any]) -> dict[str, Any]:
    _require_scim(request)
    tenant_id = _tenant_id(request)
    store = _get_scim_store()
    user = _user_from_payload(tenant_id, body)
    # Duplicate check must include deactivated users so re-creating a
    # deprovisioned userName doesn't silently shadow the deactivated record.
    if store.list_users(tenant_id, filter_attr="userName", filter_value=user.user_name, include_inactive=True):
        raise HTTPException(status_code=409, detail="User already exists")
    if user.external_id and store.list_users(tenant_id, filter_attr="externalId", filter_value=user.external_id, include_inactive=True):
        raise HTTPException(status_code=409, detail="User already exists")
    saved = store.put_user(user)
    log_action(
        "scim.user_created",
        actor=_actor(request),
        resource=f"scim/user/{saved.user_id}",
        tenant_id=tenant_id,
        user_name=saved.user_name,
    )
    return _user_to_scim(saved, request)


@router.get("/Users/{user_id}", name="scim_get_user")
async def get_user(request: Request, user_id: str) -> dict[str, Any]:
    _require_scim(request)
    user = _get_scim_store().get_user(_tenant_id(request), user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_scim(user, request)


@router.patch("/Users/{user_id}", name="scim_patch_user")
async def patch_user(request: Request, user_id: str, body: dict[str, Any]) -> dict[str, Any]:
    _require_scim(request)
    tenant_id = _tenant_id(request)
    store = _get_scim_store()
    user = store.get_user(tenant_id, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    saved = store.put_user(_apply_user_patch(user, body))
    log_action(
        "scim.user_patched",
        actor=_actor(request),
        resource=f"scim/user/{saved.user_id}",
        tenant_id=tenant_id,
        user_name=saved.user_name,
    )
    return _user_to_scim(saved, request)


@router.put("/Users/{user_id}", name="scim_replace_user")
async def replace_user(request: Request, user_id: str, body: dict[str, Any]) -> dict[str, Any]:
    _require_scim(request)
    tenant_id = _tenant_id(request)
    store = _get_scim_store()
    existing = store.get_user(tenant_id, user_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="User not found")
    saved = store.put_user(_user_from_payload(tenant_id, body, existing=existing))
    log_action(
        "scim.user_replaced",
        actor=_actor(request),
        resource=f"scim/user/{saved.user_id}",
        tenant_id=tenant_id,
        user_name=saved.user_name,
    )
    return _user_to_scim(saved, request)


@router.delete("/Users/{user_id}", status_code=204, name="scim_delete_user")
async def delete_user(request: Request, user_id: str) -> Response:
    _require_scim(request)
    tenant_id = _tenant_id(request)
    user = _get_scim_store().deactivate_user(tenant_id, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    log_action(
        "scim.user_deactivated",
        actor=_actor(request),
        resource=f"scim/user/{user.user_id}",
        tenant_id=tenant_id,
        user_name=user.user_name,
    )
    return Response(status_code=204)


@router.get("/Groups", name="scim_list_groups")
async def list_groups(
    request: Request,
    scim_filter: str | None = Query(default=None, alias="filter"),
    start_index: int = Query(default=1, alias="startIndex", ge=1),
    count: int = Query(default=100, ge=0, le=500),
) -> dict[str, Any]:
    _require_scim(request)
    attr, value = _parse_filter(scim_filter)
    groups = _get_scim_store().list_groups(_tenant_id(request), filter_attr=attr, filter_value=value)
    page = _paginate(groups, start_index, count)
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": len(groups),
        "startIndex": start_index,
        "itemsPerPage": len(page),
        "Resources": [_group_to_scim(group, request) for group in page],
    }


@router.post("/Groups", status_code=201, name="scim_create_group")
async def create_group(request: Request, body: dict[str, Any]) -> dict[str, Any]:
    _require_scim(request)
    tenant_id = _tenant_id(request)
    store = _get_scim_store()
    group = _group_from_payload(tenant_id, body)
    if store.list_groups(tenant_id, filter_attr="displayName", filter_value=group.display_name):
        raise HTTPException(status_code=409, detail="Group already exists")
    if group.external_id and store.list_groups(tenant_id, filter_attr="externalId", filter_value=group.external_id):
        raise HTTPException(status_code=409, detail="Group already exists")
    saved = store.put_group(group)
    log_action(
        "scim.group_created",
        actor=_actor(request),
        resource=f"scim/group/{saved.group_id}",
        tenant_id=tenant_id,
        display_name=saved.display_name,
    )
    return _group_to_scim(saved, request)


@router.get("/Groups/{group_id}", name="scim_get_group")
async def get_group(request: Request, group_id: str) -> dict[str, Any]:
    _require_scim(request)
    group = _get_scim_store().get_group(_tenant_id(request), group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found")
    return _group_to_scim(group, request)


@router.patch("/Groups/{group_id}", name="scim_patch_group")
async def patch_group(request: Request, group_id: str, body: dict[str, Any]) -> dict[str, Any]:
    _require_scim(request)
    tenant_id = _tenant_id(request)
    store = _get_scim_store()
    group = store.get_group(tenant_id, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found")
    saved = store.put_group(_apply_group_patch(group, body))
    log_action(
        "scim.group_patched",
        actor=_actor(request),
        resource=f"scim/group/{saved.group_id}",
        tenant_id=tenant_id,
        display_name=saved.display_name,
    )
    return _group_to_scim(saved, request)


@router.put("/Groups/{group_id}", name="scim_replace_group")
async def replace_group(request: Request, group_id: str, body: dict[str, Any]) -> dict[str, Any]:
    _require_scim(request)
    tenant_id = _tenant_id(request)
    store = _get_scim_store()
    existing = store.get_group(tenant_id, group_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Group not found")
    saved = store.put_group(_group_from_payload(tenant_id, body, existing=existing))
    log_action(
        "scim.group_replaced",
        actor=_actor(request),
        resource=f"scim/group/{saved.group_id}",
        tenant_id=tenant_id,
        display_name=saved.display_name,
    )
    return _group_to_scim(saved, request)


@router.delete("/Groups/{group_id}", status_code=204, name="scim_delete_group")
async def delete_group(request: Request, group_id: str) -> Response:
    _require_scim(request)
    tenant_id = _tenant_id(request)
    deleted = _get_scim_store().delete_group(tenant_id, group_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Group not found")
    log_action("scim.group_deleted", actor=_actor(request), resource=f"scim/group/{group_id}", tenant_id=tenant_id)
    return Response(status_code=204)
