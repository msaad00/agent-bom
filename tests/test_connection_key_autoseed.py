"""Self-host first-run: auto-seed the at-rest connection encryption key.

Pins the #3935 "self-host defaults just work" contract: a local/no-auth stack
seeds a Fernet key on first boot so creating a cloud connection does not 503 on
``AGENT_BOM_CONNECTIONS_KEY unset`` — while staying fail-closed everywhere that
is not clearly a local, unauthenticated bring-up.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from agent_bom.api import connection_crypto
from agent_bom.api.connection_crypto import (
    LOCAL_KEY_FILENAME,
    decrypt_secret,
    encrypt_secret,
    seed_local_connection_key,
)
from agent_bom.cli._server import _maybe_seed_local_connection_key

_KEY_ENV = "AGENT_BOM_CONNECTIONS_KEY"
_KEY_FILE_ENV = "AGENT_BOM_CONNECTIONS_KEY_FILE"
_PROVIDER_ENV = "AGENT_BOM_CONNECTIONS_KEY_PROVIDER"
_OPT_OUT_ENV = "AGENT_BOM_NO_AUTO_CONNECTIONS_KEY"
_REF_ENV = "AGENT_BOM_CONNECTIONS_KEY_REF"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    for name in (_KEY_ENV, _KEY_FILE_ENV, _PROVIDER_ENV, _OPT_OUT_ENV, _REF_ENV):
        monkeypatch.delenv(name, raising=False)
    # Path.home() -> tmp so seeds land in an isolated state dir.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    connection_crypto.reset_key_cache()
    yield
    connection_crypto.reset_key_cache()


def test_seed_writes_valid_fernet_key_with_locked_down_perms(tmp_path: Path):
    path = seed_local_connection_key(tmp_path / "state")
    assert path.name == LOCAL_KEY_FILENAME
    assert path.is_file()
    # 0600 — owner read/write only.
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, oct(mode)
    from cryptography.fernet import Fernet

    Fernet(path.read_bytes())  # constructs iff the material is a valid key


def test_seed_is_idempotent_and_never_overwrites(tmp_path: Path):
    directory = tmp_path / "state"
    first = seed_local_connection_key(directory)
    original = first.read_bytes()
    second = seed_local_connection_key(directory)
    assert second == first
    # A second call must preserve the existing key so prior ciphertext still
    # decrypts across restarts.
    assert second.read_bytes() == original


def test_loopback_seed_enables_encrypt_decrypt_roundtrip(monkeypatch: pytest.MonkeyPatch):
    assert not connection_crypto.connections_key_configured()
    seeded = _maybe_seed_local_connection_key(host="127.0.0.1", allow_insecure_no_auth=False)
    assert seeded is not None
    assert os.environ[_KEY_FILE_ENV] == seeded
    assert connection_crypto.connections_key_configured()
    token = encrypt_secret("external-id-abc")
    assert decrypt_secret(token) == "external-id-abc"


def test_insecure_no_auth_nonloopback_seeds(monkeypatch: pytest.MonkeyPatch):
    # The pilot compose binds 0.0.0.0 inside the container with
    # --allow-insecure-no-auth; that local bring-up should still seed.
    seeded = _maybe_seed_local_connection_key(host="0.0.0.0", allow_insecure_no_auth=True)
    assert seeded is not None
    assert connection_crypto.connections_key_configured()


def test_nonloopback_without_override_does_not_seed(monkeypatch: pytest.MonkeyPatch):
    seeded = _maybe_seed_local_connection_key(host="0.0.0.0", allow_insecure_no_auth=False)
    assert seeded is None
    assert _KEY_FILE_ENV not in os.environ
    assert not connection_crypto.connections_key_configured()


def test_opt_out_disables_seeding(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(_OPT_OUT_ENV, "1")
    assert _maybe_seed_local_connection_key(host="127.0.0.1", allow_insecure_no_auth=True) is None
    assert not connection_crypto.connections_key_configured()


def test_managed_provider_is_never_shadowed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(_PROVIDER_ENV, "aws-secrets")
    assert _maybe_seed_local_connection_key(host="127.0.0.1", allow_insecure_no_auth=True) is None
    assert _KEY_FILE_ENV not in os.environ


def test_already_configured_key_is_left_untouched(monkeypatch: pytest.MonkeyPatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv(_KEY_ENV, Fernet.generate_key().decode("ascii"))
    connection_crypto.reset_key_cache()
    assert _maybe_seed_local_connection_key(host="127.0.0.1", allow_insecure_no_auth=True) is None
    assert _KEY_FILE_ENV not in os.environ
