"""Tests for RBAC and API key management."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.api.auth import (
    ApiKey,
    ApiKeyPolicy,
    KeyStore,
    Role,
    create_api_key,
    get_key_store,
    normalize_api_key_expiry,
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

    def test_key_hash_is_scrypt_derived(self):
        _, key = create_api_key("hash-test", Role.ADMIN)
        assert len(key.key_hash) == 64  # scrypt dklen=32 → 64 hex chars
        assert len(key.key_salt) == 32  # 16 random bytes → 32 hex chars

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

    def test_expires_at_defaults_under_rotation_policy(self):
        _, key = create_api_key("no-expire", Role.VIEWER)
        assert key.expires_at is not None

    def test_expires_at_set(self):
        exp = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
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
        raw, fresh = create_api_key("expired", Role.ADMIN)
        key = ApiKey(
            key_id=fresh.key_id,
            key_hash=fresh.key_hash,
            key_salt=fresh.key_salt,
            key_prefix=fresh.key_prefix,
            name=fresh.name,
            role=fresh.role,
            created_at=fresh.created_at,
            expires_at="2020-01-01T00:00:00+00:00",
            scopes=fresh.scopes,
            tenant_id=fresh.tenant_id,
        )
        result = verify_api_key(raw, [key])
        assert result is None

    def test_not_expired_key_works(self):
        exp = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        raw, key = create_api_key("future", Role.ADMIN, expires_at=exp)
        result = verify_api_key(raw, [key])
        assert result is not None

    def test_multiple_stored_keys(self):
        raw1, key1 = create_api_key("key1", Role.ADMIN)
        raw2, key2 = create_api_key("key2", Role.VIEWER)
        assert verify_api_key(raw1, [key1, key2]) is not None
        assert verify_api_key(raw2, [key1, key2]) is not None
        assert verify_api_key("abom_nope", [key1, key2]) is None

    def test_prefix_narrows_candidates_before_scrypt(self, monkeypatch):
        raw1, key1 = create_api_key("key1", Role.ADMIN)
        _, key2 = create_api_key("key2", Role.VIEWER)
        calls: list[str] = []

        from agent_bom.api import auth as auth_module

        original = auth_module._derive_key

        def tracked(raw_key: str, salt: bytes) -> str:
            calls.append(salt.hex())
            return original(raw_key, salt)

        monkeypatch.setattr(auth_module, "_derive_key", tracked)
        assert verify_api_key(raw1, [key1, key2]) is not None
        assert calls == [key1.key_salt]


# ---------------------------------------------------------------------------
# ApiKey.is_expired
# ---------------------------------------------------------------------------


class TestApiKeyExpiry:
    def test_default_expiry_not_expired(self):
        _, key = create_api_key("no-exp", Role.VIEWER)
        assert key.expires_at is not None
        assert not key.is_expired()

    def test_past_expiry_is_expired(self):
        _, fresh = create_api_key("past", Role.VIEWER)
        key = ApiKey(
            key_id=fresh.key_id,
            key_hash=fresh.key_hash,
            key_salt=fresh.key_salt,
            key_prefix=fresh.key_prefix,
            name=fresh.name,
            role=fresh.role,
            created_at=fresh.created_at,
            expires_at="2020-01-01T00:00:00+00:00",
            scopes=fresh.scopes,
            tenant_id=fresh.tenant_id,
        )
        assert key.is_expired()

    def test_future_expiry_not_expired(self):
        exp = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        _, key = create_api_key("future", Role.VIEWER, expires_at=exp)
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
        assert "key_salt" not in d  # Salt should NOT be exposed


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


class TestApiKeyRotationPolicy:
    def test_normalize_expiry_applies_default_ttl(self):
        now = datetime(2026, 4, 17, 18, 0, tzinfo=timezone.utc)
        expiry = normalize_api_key_expiry(None, now=now, policy=ApiKeyPolicy(default_ttl_seconds=300, max_ttl_seconds=600))
        assert expiry == (now + timedelta(seconds=300)).isoformat()

    def test_normalize_expiry_rejects_past(self):
        now = datetime(2026, 4, 17, 18, 0, tzinfo=timezone.utc)
        with pytest.raises(ValueError, match="in the future"):
            normalize_api_key_expiry(
                "2026-04-17T17:59:00+00:00",
                now=now,
                policy=ApiKeyPolicy(default_ttl_seconds=300, max_ttl_seconds=600),
            )

    def test_normalize_expiry_rejects_over_max(self):
        now = datetime(2026, 4, 17, 18, 0, tzinfo=timezone.utc)
        with pytest.raises(ValueError, match="maximum allowed API key lifetime"):
            normalize_api_key_expiry(
                "2026-04-17T18:20:01+00:00",
                now=now,
                policy=ApiKeyPolicy(default_ttl_seconds=300, max_ttl_seconds=1200),
            )
