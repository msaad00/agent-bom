"""API and standalone MCP readers select the same configured job evidence."""

import sqlite3

import pytest

from agent_bom.api import stores
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore


@pytest.fixture(autouse=True)
def isolated_selection(monkeypatch):
    monkeypatch.setattr(stores, "_store", None)
    for name in ("SNOWFLAKE_ACCOUNT", "AGENT_BOM_POSTGRES_URL", "AGENT_BOM_DB", "AGENT_BOM_GRAPH_BACKEND"):
        monkeypatch.delenv(name, raising=False)


def test_unconfigured_job_store_remains_in_memory():
    assert isinstance(stores._get_store(), InMemoryJobStore)


def test_sqlite_job_store_is_selected_before_api_lifespan(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "jobs.db"))
    assert isinstance(stores._get_store(), SQLiteJobStore)
    assert stores._get_store() is stores._get_store()


def test_explicit_store_override_is_preserved(tmp_path, monkeypatch):
    injected = InMemoryJobStore()
    monkeypatch.setattr(stores, "_store", injected)
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "jobs.db"))
    assert stores._get_store() is injected


def test_postgres_takes_priority_over_sqlite(monkeypatch):
    from agent_bom.api import postgres_store

    expected = object()
    monkeypatch.setattr(postgres_store, "PostgresJobStore", lambda: expected)
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://fixture")
    monkeypatch.setenv("AGENT_BOM_DB", "unused.db")
    assert stores._get_store() is expected


def test_snowflake_takes_priority_over_other_backends(monkeypatch):
    from agent_bom.api import snowflake_store

    expected = object()
    monkeypatch.setattr(snowflake_store, "build_connection_params", lambda: {"account": "fixture"})
    monkeypatch.setattr(snowflake_store, "SnowflakeJobStore", lambda params: expected)
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "fixture")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://unused")
    monkeypatch.setenv("AGENT_BOM_DB", "unused.db")
    assert stores._get_store() is expected


def test_experimental_neptune_keeps_existing_job_store_policy(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_GRAPH_BACKEND", "neptune")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://unused")
    assert isinstance(stores._get_store(), InMemoryJobStore)


def test_configured_backend_failure_does_not_fall_back_to_empty_memory(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path))  # directory, not a database
    with pytest.raises(sqlite3.OperationalError):
        stores._get_store()
    assert stores._store is None
