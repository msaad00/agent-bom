"""Regression tests for identity/SCIM governance (#3687)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_bom.api.auth import KeyStore, Role, create_api_key_record, get_key_store, resolve_scim_subject_binding, set_key_store
from agent_bom.api.routes.scim import SCIMGroup, _apply_group_patch
from agent_bom.api.scim import revoke_credentials_for_scim_user


@pytest.fixture
def isolated_key_store():
    original = get_key_store()
    store = KeyStore()
    set_key_store(store)
    try:
        yield store
    finally:
        set_key_store(original)


def test_scim_group_remove_members_value_list_subtracts_only_named() -> None:
    group = SCIMGroup(
        group_id="g1",
        tenant_id="default",
        display_name="ops",
        members=[
            {"value": "u1", "display": "alice"},
            {"value": "u2", "display": "bob"},
            {"value": "u3", "display": "carol"},
        ],
    )
    updated = _apply_group_patch(
        group,
        {
            "Operations": [
                {
                    "op": "remove",
                    "path": "members",
                    "value": [{"value": "u2", "display": "bob"}],
                }
            ]
        },
    )
    assert {m["value"] for m in updated.members} == {"u1", "u3"}


def test_scim_group_add_members_implicit_path_appends() -> None:
    group = SCIMGroup(
        group_id="g1",
        tenant_id="default",
        display_name="ops",
        members=[{"value": "u1", "display": "alice"}],
    )
    updated = _apply_group_patch(
        group,
        {"Operations": [{"op": "add", "value": {"members": [{"value": "u2", "display": "bob"}]}}]},
    )
    assert {m["value"] for m in updated.members} == {"u1", "u2"}


def test_resolve_scim_subject_binding_prefers_explicit() -> None:
    request = SimpleNamespace(state=SimpleNamespace(scim_user_id="runtime-id"))
    assert resolve_scim_subject_binding(request, "explicit-id") == "explicit-id"


def test_resolve_scim_subject_binding_uses_runtime_scim_user_id() -> None:
    request = SimpleNamespace(state=SimpleNamespace(scim_user_id="scim-user-1"))
    assert resolve_scim_subject_binding(request, None) == "scim-user-1"


@pytest.mark.asyncio
async def test_create_key_auto_binds_scim_subject_from_request_state(isolated_key_store) -> None:
    from agent_bom.api.models import CreateKeyRequest
    from agent_bom.api.routes import enterprise

    request = SimpleNamespace(
        state=SimpleNamespace(
            tenant_id="tenant-alpha",
            api_key_name="alice",
            scim_user_id="scim-user-42",
        )
    )
    created = await enterprise.create_key(request, CreateKeyRequest(name="ci-deploy", role="analyst"))
    key = isolated_key_store.get(created["key_id"])
    assert key is not None
    assert key.name == "ci-deploy"
    assert key.scim_subject_id == "scim-user-42"


def test_scim_revoke_removes_free_form_named_key_with_subject_binding(monkeypatch) -> None:
    store = KeyStore()
    set_key_store(store)
    monkeypatch.setattr("agent_bom.api.auth.get_key_store", lambda: store)
    try:
        bound = create_api_key_record(
            "abom_test_bound_key_123456789012",
            name="ci-deploy",
            role=Role.ANALYST,
            tenant_id="default",
            scim_subject_id="user-abc",
        )
        store.add(bound)
        user = SimpleNamespace(user_id="user-abc", user_name="alice", external_id=None)
        revoked = revoke_credentials_for_scim_user("default", user)
        assert revoked == 1
        assert bound.is_revoked()
    finally:
        set_key_store(KeyStore())
