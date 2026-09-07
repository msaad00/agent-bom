"""Startup storage labels follow job-store selection without opening a database."""

from __future__ import annotations

import pytest

from agent_bom.api import stores
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore
from agent_bom.cli._server import _storage_summary


@pytest.fixture(autouse=True)
def isolated_storage_configuration(monkeypatch):
    for name in ("AGENT_BOM_POSTGRES_URL", "AGENT_BOM_DB", "SNOWFLAKE_ACCOUNT", "AGENT_BOM_GRAPH_BACKEND"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(stores, "_store", None)


@pytest.mark.parametrize(
    ("configuration", "expected"),
    [
        ({}, "In-memory (ephemeral)"),
        ({"AGENT_BOM_GRAPH_BACKEND": "neptune", "AGENT_BOM_DB": "/configured/jobs.db"}, "In-memory (ephemeral)"),
        ({"AGENT_BOM_GRAPH_BACKEND": "neptune", "AGENT_BOM_POSTGRES_URL": "postgresql://localhost/db"}, "In-memory (ephemeral)"),
        ({"AGENT_BOM_DB": "/configured/jobs.db"}, "SQLite"),
        ({"AGENT_BOM_POSTGRES_URL": "postgresql://synthetic:do-not-print@localhost/db"}, "PostgreSQL"),
        ({"SNOWFLAKE_ACCOUNT": "synthetic-account"}, "Snowflake"),
        ({"AGENT_BOM_DB": "/configured/jobs.db", "AGENT_BOM_POSTGRES_URL": "postgresql://localhost/db"}, "PostgreSQL"),
        ({"SNOWFLAKE_ACCOUNT": "synthetic-account", "AGENT_BOM_POSTGRES_URL": "postgresql://localhost/db"}, "Snowflake"),
    ],
)
def test_pending_store_summary_matches_lifespan_configuration(monkeypatch, configuration, expected):
    for name, value in configuration.items():
        monkeypatch.setenv(name, value)
    assert _storage_summary(persist=None) == expected
    assert stores._store is None  # Diagnostics must not select or open a store.


def test_explicit_persist_summary_takes_precedence_over_environment(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://localhost/db")
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "synthetic-account")
    monkeypatch.setenv("AGENT_BOM_DB", "/other/jobs.db")
    assert _storage_summary(persist="/explicit/jobs.db") == "SQLite (/explicit/jobs.db)"


def test_injected_memory_store_summary_overrides_environment(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_DB", "/configured/jobs.db")
    monkeypatch.setattr(stores, "_store", InMemoryJobStore())
    assert _storage_summary(persist=None) == "In-memory (ephemeral)"


def test_injected_sqlite_store_summary_overrides_environment(monkeypatch, tmp_path):
    store = SQLiteJobStore(str(tmp_path / "injected.db"))
    monkeypatch.setattr(stores, "_store", store)
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "synthetic-account")
    assert _storage_summary(persist=None) == "SQLite"
    assert stores._store is store


def test_api_preselected_postgres_is_not_relabelled_as_snowflake(monkeypatch):
    from agent_bom.api.postgres_store import PostgresJobStore

    # Avoid a live connection: only the type of the already selected store matters.
    store = object.__new__(PostgresJobStore)
    monkeypatch.setattr(stores, "_store", store)
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "synthetic-account")
    assert _storage_summary(persist=None) == "PostgreSQL"


@pytest.mark.parametrize("command_name", ["serve", "api"])
def test_cli_startup_reports_environment_sqlite(monkeypatch, tmp_path, command_name):
    from click.testing import CliRunner

    from agent_bom.cli._server import api_cmd, serve_cmd

    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "configured.db"))
    summaries = []
    monkeypatch.setattr("agent_bom.cli._server._emit_runtime_summary", lambda title, rows: summaries.append(dict(rows)))
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: None)
    result = CliRunner().invoke(serve_cmd if command_name == "serve" else api_cmd, ["--api-key", "synthetic-test-only-key"])
    assert result.exit_code == 0, result.output
    assert summaries[0]["Storage"] == "SQLite"
