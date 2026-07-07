"""Regression tests for post-#3626 P3 audit backlog fixes."""

from __future__ import annotations

from agent_bom.api.auth import KeyStore, Role, create_api_key_record, get_key_store, set_key_store
from agent_bom.api.scim import revoke_credentials_for_scim_user


def test_scim_revoke_includes_rotation_replacement_key(monkeypatch) -> None:
    store = KeyStore()
    original = get_key_store()
    set_key_store(store)
    monkeypatch.setattr("agent_bom.api.auth.get_key_store", lambda: store)
    try:
        rotating = create_api_key_record(
            "abom_test_rotating_key_12345678901",
            name="alice@example.com",
            role=Role.VIEWER,
            tenant_id="default",
            scim_subject_id="user-abc",
        )
        replacement = create_api_key_record(
            "abom_test_replacement_key_1234567890",
            name="alice@example.com",
            role=Role.VIEWER,
            tenant_id="default",
            scim_subject_id="user-abc",
        )
        rotating.replacement_key_id = replacement.key_id
        store.add(rotating)
        store.add(replacement)

        class _User:
            user_id = "user-abc"
            user_name = "alice@example.com"
            external_id = None

        revoked = revoke_credentials_for_scim_user("default", _User())
        assert revoked == 2
        assert rotating.is_revoked()
        assert replacement.is_revoked()
    finally:
        set_key_store(original)
