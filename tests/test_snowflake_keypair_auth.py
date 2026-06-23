"""Snowflake key-pair auth must load the private key, including with snowflake_jwt."""

from __future__ import annotations

from agent_bom.cloud.snowflake import _apply_key_pair, _resolve_snowflake_auth


def test_explicit_snowflake_jwt_loads_private_key(monkeypatch) -> None:
    """SNOWFLAKE_AUTHENTICATOR=snowflake_jwt must still load the key-pair.

    Regression: previously the authenticator was set and the function returned
    without loading the key, so the connector got snowflake_jwt with no key.
    """
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", "/keys/rsa.p8")
    conn: dict = {}
    _resolve_snowflake_auth(conn, "snowflake_jwt")
    assert conn["authenticator"] == "snowflake_jwt"
    assert conn["private_key_file"] == "/keys/rsa.p8"


def test_implicit_keypair_still_works(monkeypatch) -> None:
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", "/keys/rsa.p8")
    conn: dict = {}
    _resolve_snowflake_auth(conn, None)
    assert conn["private_key_file"] == "/keys/rsa.p8"
    assert "authenticator" not in conn  # connector infers JWT from the key file


def test_apply_key_pair_with_passphrase(monkeypatch) -> None:
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", "/keys/rsa.p8")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "secret")
    conn: dict = {}
    assert _apply_key_pair(conn) is True
    assert conn["private_key_file_pwd"] == "secret"


def test_apply_key_pair_no_path_returns_false(monkeypatch) -> None:
    monkeypatch.delenv("SNOWFLAKE_PRIVATE_KEY_PATH", raising=False)
    conn: dict = {}
    assert _apply_key_pair(conn) is False
    assert conn == {}


def test_non_jwt_authenticator_does_not_load_key(monkeypatch) -> None:
    """externalbrowser / oauth should not pull in a key file."""
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", "/keys/rsa.p8")
    conn: dict = {}
    _resolve_snowflake_auth(conn, "externalbrowser")
    assert conn == {"authenticator": "externalbrowser"}
