"""Tests for RBAC and API key management."""

from __future__ import annotations

from datetime import datetime

from agent_bom.api.auth import (
    KeyStore,
    Role,
    create_api_key,
    get_key_store,
    set_key_store,
    verify_api_key,
)

# ---------------------------------------------------------------------------
# Role hierarchy
# ---------------------------------------------------------------------------


class TestRoleHierarchy:
    def test_admin_has_all_roles(self):
        _, key = create_api_key("admin", Role.ADMIN)
        assert key.has_role(Role.ADMIN)
        assert key.has_role(Role.ANALYST)
        assert key.has_role(Role.VIEWER)

    def test_analyst_has_analyst_and_viewer(self):
        _, key = create_api_key("analyst", Role.ANALYST)
        assert not key.has_role(Role.ADMIN)
        assert key.has_role(Role.ANALYST)
        assert key.has_role(Role.VIEWER)

    def test_viewer_only_viewer(self):
        _, key = create_api_key("viewer", Role.VIEWER)
        assert not key.has_role(Role.ADMIN)
        assert not key.has_role(Role.ANALYST)
        assert key.has_role(Role.VIEWER)


# ---------------------------------------------------------------------------
# API key creation
# ---------------------------------------------------------------------------


class TestCreateApiKey:
    def test_returns_raw_key_and_record(self):
        raw, key = create_api_key("test-key", Role.ANALYST)
        assert raw.startswith("abom_")
        assert len(raw) > 20
        assert key.name == "test-key"
        assert key.role == Role.ANALYST

    def test_key_prefix_matches_raw(self):
        raw, key = create_api_key("pfx", Role.VIEWER)
        assert key.key_prefix == raw[:12]

    def test_key_hash_is_sha256(self):
        _, key = create_api_key("hash-test", Role.ADMIN)
        assert len(key.key_hash) == 64  # SHA-256 hex length

    def test_key_id_generated(self):
        _, key = create_api_key("id-test", Role.VIEWER)
        assert len(key.key_id) == 16  # hex(8 bytes)

    def test_created_at_set(self):
        _, key = create_api_key("ts-test", Role.VIEWER)
        assert key.created_at
        # Verify ISO 8601
        datetime.fromisoformat(key.created_at)

    def test_scopes_default_empty(self):
        _, key = create_api_key("scope-test", Role.ANALYST)
        assert key.scopes == []

    def test_scopes_custom(self):
        _, key = create_api_key("scope-test", Role.ANALYST, scopes=["scan", "vex"])
        assert key.scopes == ["scan", "vex"]

    def test_expires_at_optional(self):
        _, key = create_api_key("no-expire", Role.VIEWER)
        assert key.expires_at is None

    def test_expires_at_set(self):
        exp = "2099-12-31T23:59:59+00:00"
        _, key = create_api_key("expire-test", Role.VIEWER, expires_at=exp)
        assert key.expires_at == exp


# ---------------------------------------------------------------------------
# API key verification
# ---------------------------------------------------------------------------


class TestVerifyApiKey:
    def test_valid_key_returns_record(self):
        raw, key = create_api_key("verify-test", Role.ANALYST)
        result = verify_api_key(raw, [key])
        assert result is not None
        assert result.key_id == key.key_id

    def test_invalid_key_returns_none(self):
        _, key = create_api_key("miss", Role.VIEWER)
        result = verify_api_key("abom_wrong_key_value", [key])
        assert result is None

    def test_expired_key_returns_none(self):
        raw, key = create_api_key("expired", Role.ADMIN, expires_at="2020-01-01T00:00:00+00:00")
        result = verify_api_key(raw, [key])
        assert result is None

    def test_not_expired_key_works(self):
        raw, key = create_api_key("future", Role.ADMIN, expires_at="2099-12-31T23:59:59+00:00")
        result = verify_api_key(raw, [key])
        assert result is not None

    def test_multiple_stored_keys(self):
        raw1, key1 = create_api_key("key1", Role.ADMIN)
        raw2, key2 = create_api_key("key2", Role.VIEWER)
        assert verify_api_key(raw1, [key1, key2]) is not None
        assert verify_api_key(raw2, [key1, key2]) is not None
        assert verify_api_key("abom_nope", [key1, key2]) is None


# ---------------------------------------------------------------------------
# ApiKey.is_expired
# ---------------------------------------------------------------------------


class TestApiKeyExpiry:
    def test_no_expiry_not_expired(self):
        _, key = create_api_key("no-exp", Role.VIEWER)
        assert not key.is_expired()

    def test_past_expiry_is_expired(self):
        _, key = create_api_key("past", Role.VIEWER, expires_at="2020-01-01T00:00:00+00:00")
        assert key.is_expired()

    def test_future_expiry_not_expired(self):
        _, key = create_api_key("future", Role.VIEWER, expires_at="2099-12-31T23:59:59+00:00")
        assert not key.is_expired()


# ---------------------------------------------------------------------------
# ApiKey.to_dict
# ---------------------------------------------------------------------------


class TestApiKeyToDict:
    def test_to_dict_structure(self):
        _, key = create_api_key("dict-test", Role.ANALYST, scopes=["scan"])
        d = key.to_dict()
        assert d["name"] == "dict-test"
        assert d["role"] == "analyst"
        assert d["scopes"] == ["scan"]
        assert "key_hash" not in d  # Hash should NOT be exposed


# ---------------------------------------------------------------------------
# KeyStore
# ---------------------------------------------------------------------------


class TestKeyStore:
    def test_add_and_list(self):
        store = KeyStore()
        _, key = create_api_key("store-test", Role.ADMIN)
        store.add(key)
        assert len(store.list_keys()) == 1

    def test_remove(self):
        store = KeyStore()
        _, key = create_api_key("rm-test", Role.VIEWER)
        store.add(key)
        assert store.remove(key.key_id)
        assert len(store.list_keys()) == 0

    def test_remove_nonexistent(self):
        store = KeyStore()
        assert not store.remove("nonexistent")

    def test_verify(self):
        store = KeyStore()
        raw, key = create_api_key("v-test", Role.ANALYST)
        store.add(key)
        assert store.verify(raw) is not None
        assert store.verify("abom_wrong") is None

    def test_has_keys(self):
        store = KeyStore()
        assert not store.has_keys()
        _, key = create_api_key("hk", Role.VIEWER)
        store.add(key)
        assert store.has_keys()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_key_store_returns_same_instance(self):
        s1 = get_key_store()
        s2 = get_key_store()
        assert s1 is s2

    def test_set_key_store_replaces(self):
        original = get_key_store()
        new_store = KeyStore()
        set_key_store(new_store)
        assert get_key_store() is new_store
        # Restore
        set_key_store(original)
