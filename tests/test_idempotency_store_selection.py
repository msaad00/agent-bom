"""Backend selection for the idempotency store (stores._get_idempotency_store).

Multi-replica prod runs Postgres (AGENT_BOM_POSTGRES_URL set, no local
AGENT_BOM_DB). Before this wiring the selector fell through to a per-process
InMemoryIdempotencyStore, so a retried write with the same Idempotency-Key on
another replica was not recognized and the same-key-different-body 409 guarantee
was lost. These tests pin the selection precedence without needing a live DB.
"""

from __future__ import annotations

import pytest

from agent_bom.api import idempotency_store as idem_mod
from agent_bom.api import stores
from agent_bom.api.idempotency_store import InMemoryIdempotencyStore, SQLiteIdempotencyStore


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    stores.set_idempotency_store(None)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    yield
    stores.set_idempotency_store(None)


def test_default_selects_in_memory():
    assert isinstance(stores._get_idempotency_store(), InMemoryIdempotencyStore)


def test_sqlite_selected_when_only_db_set(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "jobs.db"))
    assert isinstance(stores._get_idempotency_store(), SQLiteIdempotencyStore)


def test_postgres_url_selects_postgres_backend(monkeypatch):
    """AGENT_BOM_POSTGRES_URL must select the shared Postgres backend, not memory."""
    constructed: list[bool] = []

    class _StubPostgresIdempotencyStore:
        def __init__(self, *args, **kwargs):  # noqa: D401 - no real pool touched
            constructed.append(True)

    # Stub the class so no live pool/connection is required for the selection check.
    monkeypatch.setattr(idem_mod, "PostgresIdempotencyStore", _StubPostgresIdempotencyStore)
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://stub")

    store = stores._get_idempotency_store()

    assert constructed == [True]
    assert isinstance(store, _StubPostgresIdempotencyStore)
    assert not isinstance(store, InMemoryIdempotencyStore)


def test_postgres_url_takes_precedence_over_sqlite(monkeypatch, tmp_path):
    class _StubPostgresIdempotencyStore:
        def __init__(self, *args, **kwargs):
            pass

    monkeypatch.setattr(idem_mod, "PostgresIdempotencyStore", _StubPostgresIdempotencyStore)
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://stub")
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "jobs.db"))

    store = stores._get_idempotency_store()
    assert isinstance(store, _StubPostgresIdempotencyStore)
