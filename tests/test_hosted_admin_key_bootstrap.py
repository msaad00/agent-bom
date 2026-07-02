from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from agent_bom.api.auth import KeyStore, get_key_store, set_key_store
from scripts.deploy.mint_hosted_admin_key import main, mint_admin_key, write_raw_key_file


@pytest.fixture(autouse=True)
def isolated_key_store(monkeypatch: pytest.MonkeyPatch):
    original = get_key_store()
    store = KeyStore()
    set_key_store(store)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    try:
        yield store
    finally:
        set_key_store(original)


def test_mint_hosted_admin_key_persists_admin_record(isolated_key_store: KeyStore) -> None:
    payload = mint_admin_key(
        tenant_id="customer-0",
        name="customer-0-admin",
        allow_inmemory=True,
    )

    verified = isolated_key_store.verify(payload.raw_key)
    assert verified is not None
    assert verified.role.value == "admin"
    assert verified.tenant_id == "customer-0"
    assert verified.scopes == ["*"]
    assert payload.raw_key != payload.metadata["key_prefix"]


def test_mint_hosted_admin_key_requires_persistent_store_without_test_escape() -> None:
    with pytest.raises(RuntimeError, match="AGENT_BOM_POSTGRES_URL"):
        mint_admin_key(tenant_id="customer-0", name="customer-0-admin")


def test_cli_writes_one_time_raw_key_to_private_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    raw_key_file = tmp_path / "customer0-admin.key"

    assert (
        main(
            [
                "--tenant-id",
                "tenant-a",
                "--name",
                "admin",
                "--allow-inmemory",
                "--raw-key-file",
                str(raw_key_file),
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["tenant_id"] == "tenant-a"
    assert payload["role"] == "admin"
    assert "raw_key" not in payload
    assert payload["raw_key_file"] == str(raw_key_file)
    raw_key = raw_key_file.read_text(encoding="utf-8").strip()
    assert raw_key.startswith("abom_")
    assert stat.S_IMODE(raw_key_file.stat().st_mode) == 0o600
    assert os.environ.get("AGENT_BOM_POSTGRES_URL") is None


def test_cli_refuses_to_overwrite_raw_key_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    raw_key_file = tmp_path / "customer0-admin.key"
    raw_key_file.write_text("existing\n", encoding="utf-8")

    assert (
        main(
            [
                "--tenant-id",
                "tenant-a",
                "--name",
                "admin",
                "--allow-inmemory",
                "--raw-key-file",
                str(raw_key_file),
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "raw key file already exists" in captured.err
    assert raw_key_file.read_text(encoding="utf-8") == "existing\n"


def test_write_raw_key_file_force_overwrites_private_file(tmp_path: Path) -> None:
    raw_key_file = tmp_path / "customer0-admin.key"
    raw_key_file.write_text("existing\n", encoding="utf-8")

    write_raw_key_file(raw_key_file, "abom_new-key", force=True)

    assert raw_key_file.read_text(encoding="utf-8") == "abom_new-key\n"
    assert stat.S_IMODE(raw_key_file.stat().st_mode) == 0o600
