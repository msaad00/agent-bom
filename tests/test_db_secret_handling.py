"""No-passwords-for-the-DB-tier hardening.

Covers three opt-in-safe changes:

(a) The Postgres password is kept OUT of the conninfo/DSN and passed to the
    pool via connection kwargs instead.
(b) ``AGENT_BOM_AUDIT_HMAC_KEY`` accepts a comma-separated rotation list:
    sign with the first key, verify against any key (single key stays
    back-compatible).
(c) A pluggable Postgres auth-token provider (AWS RDS IAM) issues a
    short-lived token in place of a static password when
    ``AGENT_BOM_POSTGRES_AUTH_MODE=iam``.
"""

import sys
import types

import pytest

from agent_bom import audit_integrity
from agent_bom.api import postgres_common

# --------------------------------------------------------------------------- #
# (a) Postgres password kept out of the DSN
# --------------------------------------------------------------------------- #


class _RoleCursor:
    def fetchone(self):
        # NOSUPERUSER NOBYPASSRLS role so the RLS startup guard passes.
        return (False, False, "agent_bom_app")


class _RoleConnection:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        return _RoleCursor()


def _fake_pool_factory(captured):
    class _FakePool:
        def __init__(self, conninfo=None, **kwargs):
            captured["conninfo"] = conninfo
            captured["kwargs"] = kwargs

        def connection(self):
            return _RoleConnection()

    return _FakePool


def test_get_pool_password_via_kwargs_not_dsn(monkeypatch, tmp_path):
    """The secret rides in pool kwargs; the conninfo string carries no password."""
    postgres_common.reset_pool()
    secret = tmp_path / "postgres_app_password"
    secret.write_text("s3cret-value", encoding="utf-8")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom_app@postgres:5432/agent_bom")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", str(secret))
    monkeypatch.delenv("AGENT_BOM_POSTGRES_AUTH_MODE", raising=False)

    captured: dict = {}
    monkeypatch.setitem(
        sys.modules,
        "psycopg_pool",
        types.SimpleNamespace(ConnectionPool=_fake_pool_factory(captured)),
    )
    try:
        postgres_common._get_pool()
    finally:
        postgres_common.reset_pool()

    assert captured["conninfo"] == "postgresql://agent_bom_app@postgres:5432/agent_bom"
    assert "s3cret-value" not in captured["conninfo"]
    # psycopg forwards the per-connection kwargs under the "kwargs" key.
    assert captured["kwargs"]["kwargs"]["password"] == "s3cret-value"


def test_resolve_postgres_url_strips_embedded_password(monkeypatch):
    """A password embedded directly in the URL is moved to the secret resolver."""
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom_app:inline-pw@postgres:5432/agent_bom")
    monkeypatch.delenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_AUTH_MODE", raising=False)

    url = postgres_common.resolve_postgres_url()
    assert "inline-pw" not in url
    assert url == "postgresql://agent_bom_app@postgres:5432/agent_bom"
    assert postgres_common.resolve_postgres_secret() == "inline-pw"


def test_resolve_postgres_url_still_rejects_privileged_role(monkeypatch):
    """The privileged-role rejection is preserved by the refactor."""
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://postgres@db:5432/agent_bom")
    with pytest.raises(ValueError, match="privileged role"):
        postgres_common.resolve_postgres_url()
    with pytest.raises(ValueError, match="privileged role"):
        postgres_common.resolve_postgres_secret()


# --------------------------------------------------------------------------- #
# (b) Audit-HMAC multi-key rotation
# --------------------------------------------------------------------------- #


def _reset_audit_env(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_AUDIT_HMAC_KEY_FILE", raising=False)
    monkeypatch.delenv("AGENT_BOM_REQUIRE_AUDIT_HMAC", raising=False)
    monkeypatch.setattr(audit_integrity, "_AUDIT_CHAIN_EPHEMERAL_KEY", None, raising=False)


def test_audit_hmac_single_key_backcompat(monkeypatch):
    _reset_audit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY", "solo-key")

    assert audit_integrity.audit_chain_keys() == [b"solo-key"]
    assert audit_integrity.audit_chain_key() == b"solo-key"


def test_audit_hmac_signs_with_first_verifies_with_any(monkeypatch):
    _reset_audit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY", "primary-key, secondary-key")

    assert audit_integrity.audit_chain_keys() == [b"primary-key", b"secondary-key"]

    payload = {"action": "revoke", "actor": "ops"}
    prev = "PREVHASH"

    # Signing uses the FIRST (primary) key only.
    signed = audit_integrity.compute_audit_record_mac(payload, prev)
    assert signed == audit_integrity.compute_audit_record_mac_with_key(payload, prev, b"primary-key")
    assert signed != audit_integrity.compute_audit_record_mac_with_key(payload, prev, b"secondary-key")

    # Verification accepts a record signed under EITHER key in the list.
    assert audit_integrity.verify_audit_record_mac(payload, prev, signed)
    mac_secondary = audit_integrity.compute_audit_record_mac_with_key(payload, prev, b"secondary-key")
    assert audit_integrity.verify_audit_record_mac(payload, prev, mac_secondary)


def test_audit_hmac_rotation_old_key_still_verifies(monkeypatch):
    _reset_audit_env(monkeypatch)

    payload = {"event": "deprovision"}
    prev = ""
    # Records written while "old-key" was the primary.
    old_mac = audit_integrity.compute_audit_record_mac_with_key(payload, prev, b"old-key")

    # Rotate: prepend the new primary, keep the old key for verification.
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY", "new-key,old-key")
    assert audit_integrity.verify_audit_record_mac(payload, prev, old_mac)

    # New records sign under the new primary and still verify.
    new_mac = audit_integrity.compute_audit_record_mac(payload, prev)
    assert new_mac == audit_integrity.compute_audit_record_mac_with_key(payload, prev, b"new-key")
    assert audit_integrity.verify_audit_record_mac(payload, prev, new_mac)

    # Once the retired key is dropped from the list it no longer verifies.
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY", "new-key")
    assert not audit_integrity.verify_audit_record_mac(payload, prev, old_mac)


def test_resolve_verifier_chain_keys_lists_rotation(monkeypatch, tmp_path):
    _reset_audit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY", "a-key,b-key")

    log_path = tmp_path / "audit.jsonl"
    keys = audit_integrity.resolve_verifier_chain_keys(log_path)
    assert keys == [
        audit_integrity._normalize_cmac_key(b"a-key"),
        audit_integrity._normalize_cmac_key(b"b-key"),
    ]
    # The singular accessor returns the primary for back-compat.
    assert audit_integrity.resolve_verifier_chain_key(log_path) == keys[0]


# --------------------------------------------------------------------------- #
# (c) Pluggable Postgres auth-token provider (AWS RDS IAM)
# --------------------------------------------------------------------------- #


def _install_fake_boto3(monkeypatch, *, token="iam-token", capture=None):
    fake = types.ModuleType("boto3")

    class _Client:
        def generate_db_auth_token(self, **kwargs):
            if capture is not None:
                capture.update(kwargs)
            return token

    def _client(service, region_name=None):
        if capture is not None:
            capture["service"] = service
            capture["region_name"] = region_name
        return _Client()

    fake.client = _client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", fake)
    return fake


def test_rds_iam_provider_generates_token(monkeypatch):
    from agent_bom.api.postgres_auth import RdsIamAuthTokenProvider

    capture: dict = {}
    _install_fake_boto3(monkeypatch, token="tok-123", capture=capture)

    provider = RdsIamAuthTokenProvider(region="us-east-1")
    token = provider.get_auth_token(host="db.example.com", port=5432, username="agent_bom_app")

    assert token == "tok-123"
    assert capture["service"] == "rds"
    assert capture["region_name"] == "us-east-1"
    assert capture["DBHostname"] == "db.example.com"
    assert capture["Port"] == 5432
    assert capture["DBUsername"] == "agent_bom_app"
    assert capture["Region"] == "us-east-1"


def test_rds_iam_provider_requires_boto3(monkeypatch):
    from agent_bom.api.postgres_auth import PostgresAuthError, RdsIamAuthTokenProvider

    # Setting the module to None makes ``import boto3`` raise ImportError.
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(PostgresAuthError, match="boto3 is required"):
        RdsIamAuthTokenProvider().get_auth_token(host="h", port=5432, username="u")


def test_unknown_iam_provider_fails_closed(monkeypatch):
    from agent_bom.api.postgres_auth import PostgresAuthError, resolve_postgres_auth_token_provider

    monkeypatch.setenv("AGENT_BOM_POSTGRES_IAM_PROVIDER", "made-up")
    with pytest.raises(PostgresAuthError, match="not a supported"):
        resolve_postgres_auth_token_provider()


def test_resolve_postgres_secret_iam_mode(monkeypatch):
    """AUTH_MODE=iam resolves a short-lived token; the DSN never carries it."""
    capture: dict = {}
    _install_fake_boto3(monkeypatch, token="iam-token", capture=capture)

    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom_app@db.example.com:5432/agent_bom")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_AUTH_MODE", "iam")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_IAM_REGION", "eu-west-1")
    monkeypatch.delenv("AGENT_BOM_POSTGRES_IAM_PROVIDER", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", raising=False)

    assert postgres_common.resolve_postgres_secret() == "iam-token"
    assert capture["DBUsername"] == "agent_bom_app"
    assert capture["DBHostname"] == "db.example.com"
    assert capture["Region"] == "eu-west-1"
    assert "iam-token" not in postgres_common.resolve_postgres_url()


def test_iam_pool_resolves_fresh_token_for_each_connection(monkeypatch):
    """Pool replacement connections must not reuse an expired RDS IAM token."""
    postgres_common.reset_pool()
    tokens = iter(["token-1", "token-2"])
    captured: dict[str, object] = {}

    class FakeConnection:
        calls: list[tuple[str, dict[str, object]]] = []

        @classmethod
        def connect(cls, conninfo="", **kwargs):
            cls.calls.append((conninfo, kwargs))
            return object()

    class FakePool:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def connection(self):
            return _RoleConnection()

    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom_app@db.example:5432/agent_bom")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_AUTH_MODE", "iam")
    monkeypatch.setattr(postgres_common, "resolve_postgres_secret", lambda: next(tokens))
    monkeypatch.setitem(sys.modules, "psycopg", types.SimpleNamespace(Connection=FakeConnection))
    monkeypatch.setitem(sys.modules, "psycopg_pool", types.SimpleNamespace(ConnectionPool=FakePool))

    try:
        postgres_common._get_pool()
        connection_class = captured["connection_class"]
        connection_class.connect("postgresql://agent_bom_app@db.example:5432/agent_bom")
        connection_class.connect("postgresql://agent_bom_app@db.example:5432/agent_bom")
    finally:
        postgres_common.reset_pool()

    assert [call[1]["password"] for call in FakeConnection.calls] == ["token-1", "token-2"]
    assert "password" not in captured["kwargs"]


def test_password_mode_is_default(monkeypatch):
    """With AUTH_MODE unset the existing file/password path is used unchanged."""
    from agent_bom.api.postgres_auth import AUTH_MODE_PASSWORD, postgres_auth_mode

    monkeypatch.delenv("AGENT_BOM_POSTGRES_AUTH_MODE", raising=False)
    assert postgres_auth_mode() == AUTH_MODE_PASSWORD
