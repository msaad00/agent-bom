"""Credential references remain tenant-owned at the persistence boundary."""

from __future__ import annotations

import pytest

from agent_bom.api.credential_store import InMemoryCredentialRefStore, SQLiteCredentialRefStore
from agent_bom.api.models import CredentialRefRecord


def _credential(credential_ref_id: str, tenant_id: str, display_name: str = "Credential") -> CredentialRefRecord:
    return CredentialRefRecord(
        credential_ref_id=credential_ref_id,
        tenant_id=tenant_id,
        display_name=display_name,
        provider="aws",
        mode="role_arn",
        external_ref="arn:aws:iam::123456789012:role/read-only",
        created_at="2026-09-28T00:00:00+00:00",
        updated_at="2026-09-28T00:00:00+00:00",
    )


@pytest.mark.parametrize("store_factory", [InMemoryCredentialRefStore, SQLiteCredentialRefStore])
def test_credential_store_rejects_foreign_tenant_id_takeover(store_factory, tmp_path) -> None:
    store = store_factory() if store_factory is InMemoryCredentialRefStore else store_factory(str(tmp_path / "credentials.db"))
    store.put(_credential("shared-id", "tenant-a"), tenant_id="tenant-a")

    with pytest.raises(ValueError, match="different tenant"):
        store.put(_credential("shared-id", "tenant-b"), tenant_id="tenant-b")

    stored = store.get("shared-id", tenant_id="tenant-a")
    assert stored is not None and stored.tenant_id == "tenant-a"
    assert store.get("shared-id", tenant_id="tenant-b") is None


@pytest.mark.parametrize("store_factory", [InMemoryCredentialRefStore, SQLiteCredentialRefStore])
def test_credential_store_requires_explicit_tenant_for_writes_and_lists(store_factory, tmp_path) -> None:
    store = store_factory() if store_factory is InMemoryCredentialRefStore else store_factory(str(tmp_path / "credentials.db"))

    with pytest.raises(TypeError):
        store.put(_credential("cred-a", "tenant-a"))
    with pytest.raises(TypeError):
        store.list_all()


def test_in_memory_credential_store_copies_records_at_the_boundary() -> None:
    store = InMemoryCredentialRefStore()
    credential = _credential("cred-a", "tenant-a")
    store.put(credential, tenant_id="tenant-a")
    credential.display_name = "mutated outside store"

    loaded = store.get("cred-a", tenant_id="tenant-a")
    assert loaded is not None and loaded.display_name == "Credential"
    loaded.display_name = "mutated after read"
    assert store.get("cred-a", tenant_id="tenant-a").display_name == "Credential"


@pytest.mark.parametrize("store_factory", [InMemoryCredentialRefStore, SQLiteCredentialRefStore])
def test_credential_store_rejects_record_tenant_mismatch(store_factory, tmp_path) -> None:
    store = store_factory() if store_factory is InMemoryCredentialRefStore else store_factory(str(tmp_path / "credentials.db"))

    with pytest.raises(ValueError, match="does not match"):
        store.put(_credential("cred-a", "tenant-a"), tenant_id="tenant-b")
