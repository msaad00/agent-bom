"""Shared job-store startup for API lifespan and standalone evidence readers."""

from __future__ import annotations

from typing import Any

from agent_bom.core.settings import env_raw


def configured_job_store() -> Any:
    """Match API backend precedence without hiding configured storage failures."""
    from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore

    if env_raw("SNOWFLAKE_ACCOUNT"):
        from agent_bom.api.snowflake_store import SnowflakeJobStore, build_connection_params

        return SnowflakeJobStore(build_connection_params())
    if env_raw("AGENT_BOM_GRAPH_BACKEND", "").strip().lower() == "neptune":
        return InMemoryJobStore()
    if env_raw("AGENT_BOM_POSTGRES_URL"):
        from agent_bom.api.postgres_store import PostgresJobStore

        return PostgresJobStore()
    if path := env_raw("AGENT_BOM_DB"):
        return SQLiteJobStore(path)
    return InMemoryJobStore()
