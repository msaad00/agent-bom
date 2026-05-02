from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_bom.api import server as api_server
from agent_bom.api.scim_store import InMemorySCIMStore
from agent_bom.api.server import app
from agent_bom.api.stores import _get_scim_store, set_scim_store


@pytest.fixture
def scim_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "scim-secret")
    monkeypatch.setenv("AGENT_BOM_SCIM_TENANT_ID", "tenant-alpha")
    set_scim_store(InMemorySCIMStore())
    api_server.configure_api(api_key=None)
    return TestClient(app)


def _headers(token: str = "scim-secret") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


AGENT_BOM_USER_EXTENSION = "urn:agent-bom:params:scim:schemas:extension:identity:1.0:User"


def test_scim_requires_dedicated_bearer_token(scim_client: TestClient) -> None:
    missing = scim_client.get("/scim/v2/Users")
    assert missing.status_code == 401

    wrong = scim_client.get("/scim/v2/Users", headers=_headers("wrong"))
    assert wrong.status_code == 401

    allowed = scim_client.get("/scim/v2/Users", headers=_headers())
    assert allowed.status_code == 200
    assert allowed.json()["totalResults"] == 0


def test_scim_discovery_endpoints(scim_client: TestClient) -> None:
    service_provider = scim_client.get("/scim/v2/ServiceProviderConfig", headers=_headers())
    assert service_provider.status_code == 200
    assert service_provider.json()["patch"]["supported"] is True

    schemas = scim_client.get("/scim/v2/Schemas", headers=_headers())
    assert schemas.status_code == 200
    schema_ids = {resource["id"] for resource in schemas.json()["Resources"]}
    assert "urn:ietf:params:scim:schemas:core:2.0:User" in schema_ids
    assert "urn:ietf:params:scim:schemas:core:2.0:Group" in schema_ids
    assert AGENT_BOM_USER_EXTENSION in schema_ids

    resource_types = scim_client.get("/scim/v2/ResourceTypes", headers=_headers())
    assert resource_types.status_code == 200
    assert {resource["id"] for resource in resource_types.json()["Resources"]} == {"User", "Group"}


def test_scim_user_create_list_patch_and_deactivate(scim_client: TestClient) -> None:
    created = scim_client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json={
            "userName": "alice@example.com",
            "externalId": "emp-123",
            "displayName": "Alice Example",
            "active": True,
            "emails": [{"value": "alice@example.com", "primary": True}],
            "tenant_id": "attacker-tenant",
        },
    )
    assert created.status_code == 201
    user = created.json()
    user_id = user["id"]
    assert user["userName"] == "alice@example.com"
    assert user["active"] is True
    assert user["roles"] == [{"value": "viewer", "display": "viewer", "type": "agent_bom"}]
    assert user[AGENT_BOM_USER_EXTENSION]["tenantId"] == "tenant-alpha"
    assert user[AGENT_BOM_USER_EXTENSION]["tenantIdSource"] == "AGENT_BOM_SCIM_TENANT_ID"
    assert user[AGENT_BOM_USER_EXTENSION]["runtimeAuthEnforced"] is True
    assert user[AGENT_BOM_USER_EXTENSION]["memberships"] == [
        {"tenantId": "tenant-alpha", "role": "viewer", "active": True, "source": "scim"}
    ]

    duplicate = scim_client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json={"userName": "alice@example.com", "externalId": "emp-123"},
    )
    assert duplicate.status_code == 409

    listed = scim_client.get('/scim/v2/Users?filter=userName eq "alice@example.com"', headers=_headers())
    assert listed.status_code == 200
    assert listed.json()["totalResults"] == 1
    assert listed.json()["Resources"][0]["id"] == user_id

    patched = scim_client.patch(
        f"/scim/v2/Users/{user_id}",
        headers=_headers(),
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
    )
    assert patched.status_code == 200
    assert patched.json()["active"] is False

    replaced = scim_client.put(
        f"/scim/v2/Users/{user_id}",
        headers=_headers(),
        json={
            "userName": "alice.renamed@example.com",
            "externalId": "emp-123",
            "displayName": "Alice Renamed",
            "active": True,
        },
    )
    assert replaced.status_code == 200
    assert replaced.json()["userName"] == "alice.renamed@example.com"
    assert replaced.json()["active"] is True

    deleted = scim_client.delete(f"/scim/v2/Users/{user_id}", headers=_headers())
    assert deleted.status_code == 204

    # Per #2196 audit, the SCIM DELETE soft-deletes via active=false. The user
    # MUST disappear from default list responses so Okta/Azure AD see the
    # deprovisioning land. GET by id still works (so IdPs can verify the
    # deactivation worked) and shows active=false.
    fetched = scim_client.get(f"/scim/v2/Users/{user_id}", headers=_headers())
    assert fetched.status_code == 200
    assert fetched.json()["active"] is False
    assert fetched.json()[AGENT_BOM_USER_EXTENSION]["memberships"][0]["active"] is False

    # Default list excludes deactivated users -- this is the audit-blocking
    # IdP deprovisioning fix (#2196).
    default_list = scim_client.get("/scim/v2/Users", headers=_headers())
    assert default_list.status_code == 200
    listed_ids = [r["id"] for r in default_list.json()["Resources"]]
    assert user_id not in listed_ids
    assert default_list.json()["totalResults"] == len(listed_ids)

    # Filter `active eq false` surfaces deactivated users so admins can audit.
    inactive_list = scim_client.get("/scim/v2/Users?filter=active eq false", headers=_headers())
    assert inactive_list.status_code == 200
    assert any(r["id"] == user_id for r in inactive_list.json()["Resources"])

    # Re-creating a userName for a deactivated user still 409s (the
    # duplicate check looks at the full set, including inactive).
    re_created = scim_client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json={"userName": "alice.renamed@example.com"},
    )
    assert re_created.status_code == 409


def test_scim_user_roles_are_normalized_and_tenant_bound(
    scim_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_SCIM_ROLE_ATTRIBUTE", "agent_bom_role")

    created = scim_client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json={
            "userName": "admin@example.com",
            "externalId": "emp-admin",
            "displayName": "Admin Example",
            "agent_bom_role": "admin",
            "tenant_id": "payload-tenant-must-not-win",
        },
    )
    assert created.status_code == 201
    user = created.json()
    assert user["roles"] == [{"value": "admin", "display": "admin", "type": "agent_bom"}]
    assert user[AGENT_BOM_USER_EXTENSION]["tenantId"] == "tenant-alpha"
    assert user[AGENT_BOM_USER_EXTENSION]["memberships"] == [
        {"tenantId": "tenant-alpha", "role": "admin", "active": True, "source": "scim"}
    ]

    patched = scim_client.patch(
        f"/scim/v2/Users/{user['id']}",
        headers=_headers(),
        json={"Operations": [{"op": "replace", "path": "agent_bom_role", "value": "contributor"}]},
    )
    assert patched.status_code == 200
    assert patched.json()["roles"] == [{"value": "analyst", "display": "analyst", "type": "agent_bom"}]
    assert patched.json()[AGENT_BOM_USER_EXTENSION]["memberships"][0]["role"] == "analyst"


def test_scim_group_create_patch_and_delete(scim_client: TestClient) -> None:
    user = scim_client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json={"userName": "bob@example.com", "externalId": "emp-456"},
    ).json()
    created = scim_client.post(
        "/scim/v2/Groups",
        headers=_headers(),
        json={
            "displayName": "Agent Operators",
            "externalId": "grp-ops",
            "members": [{"value": user["id"], "display": "bob@example.com"}],
        },
    )
    assert created.status_code == 201
    group_id = created.json()["id"]

    listed = scim_client.get('/scim/v2/Groups?filter=displayName eq "Agent Operators"', headers=_headers())
    assert listed.status_code == 200
    assert listed.json()["totalResults"] == 1

    patched = scim_client.patch(
        f"/scim/v2/Groups/{group_id}",
        headers=_headers(),
        json={"Operations": [{"op": "replace", "path": "displayName", "value": "Agent Security Operators"}]},
    )
    assert patched.status_code == 200
    assert patched.json()["displayName"] == "Agent Security Operators"

    replaced = scim_client.put(
        f"/scim/v2/Groups/{group_id}",
        headers=_headers(),
        json={"displayName": "Identity Operators", "members": []},
    )
    assert replaced.status_code == 200
    assert replaced.json()["displayName"] == "Identity Operators"
    assert replaced.json()["members"] == []

    deleted = scim_client.delete(f"/scim/v2/Groups/{group_id}", headers=_headers())
    assert deleted.status_code == 204
    assert scim_client.get(f"/scim/v2/Groups/{group_id}", headers=_headers()).status_code == 404


@pytest.mark.parametrize(
    ("idp_name", "payload", "patch_body", "expected_created_display", "expected_patched_display"),
    [
        (
            "okta",
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "okta.user@example.com",
                "externalId": "00u-okta-user",
                "displayName": "Okta User",
                "active": True,
                "emails": [{"value": "okta.user@example.com", "type": "work", "primary": True}],
                "groups": [{"value": "grp-okta", "$ref": "/Groups/grp-okta", "display": "Agent BOM Admins"}],
                "tenant_id": "payload-tenant-must-not-win",
            },
            {"Operations": [{"op": "replace", "path": "active", "value": False}]},
            "Okta User",
            "Okta User",
        ),
        (
            "microsoft_entra_id",
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "entra.user@example.com",
                "externalId": "entra-object-id",
                "displayName": "Entra User",
                "active": True,
                "emails": [{"value": "entra.user@example.com", "type": "work", "primary": True}],
            },
            {"Operations": [{"op": "Replace", "value": {"displayName": "Entra User Renamed", "active": False}}]},
            "Entra User",
            "Entra User Renamed",
        ),
        (
            "google_cloud_identity",
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "google.user@example.com",
                "externalId": "google-directory-id",
                "name": {"formatted": "Google User"},
                "active": True,
                "emails": [{"value": "google.user@example.com", "type": "work", "primary": True}],
            },
            {"Operations": [{"op": "replace", "path": "active", "value": False}]},
            "Google User",
            "Google User",
        ),
    ],
)
def test_scim_user_lifecycle_accepts_common_idp_payloads(
    scim_client: TestClient,
    idp_name: str,
    payload: dict,
    patch_body: dict,
    expected_created_display: str,
    expected_patched_display: str,
) -> None:
    created = scim_client.post("/scim/v2/Users", headers=_headers(), json=payload)
    assert created.status_code == 201, idp_name
    user = created.json()
    assert user["userName"] == payload["userName"]
    assert user["displayName"] == expected_created_display
    assert user["externalId"] == payload["externalId"]

    patched = scim_client.patch(f"/scim/v2/Users/{user['id']}", headers=_headers(), json=patch_body)
    assert patched.status_code == 200, idp_name
    assert patched.json()["displayName"] == expected_patched_display
    assert patched.json()["active"] is False

    listed = scim_client.get(f'/scim/v2/Users?filter=externalId eq "{payload["externalId"]}"', headers=_headers())
    assert listed.status_code == 200
    assert listed.json()["totalResults"] == 1


def test_scim_group_lifecycle_accepts_common_idp_members(scim_client: TestClient) -> None:
    user = scim_client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json={"userName": "member@example.com", "externalId": "member-1", "displayName": "Member One"},
    ).json()
    created = scim_client.post(
        "/scim/v2/Groups",
        headers=_headers(),
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Agent BOM Reviewers",
            "externalId": "idp-group-reviewers",
            "members": [{"value": user["id"], "display": "Member One", "$ref": f"/scim/v2/Users/{user['id']}"}],
        },
    )
    assert created.status_code == 201
    group_id = created.json()["id"]
    assert created.json()["members"][0]["value"] == user["id"]

    patched = scim_client.patch(
        f"/scim/v2/Groups/{group_id}",
        headers=_headers(),
        json={"Operations": [{"op": "remove", "path": f'members[value eq "{user["id"]}"]'}]},
    )
    assert patched.status_code == 200
    assert patched.json()["members"] == []


def test_scim_store_fails_closed_without_postgres_for_multi_replica(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "scim-secret")
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "2")
    set_scim_store(None)

    with pytest.raises(RuntimeError, match="AGENT_BOM_POSTGRES_URL"):
        _get_scim_store()
