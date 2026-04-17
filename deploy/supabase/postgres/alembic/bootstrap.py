from __future__ import annotations

from pathlib import Path

INIT_SQL = Path(__file__).resolve().parents[1] / "init.sql"


def rewrite_bootstrap_sql(sql: str, database_name: str) -> str:
    sql = sql.replace(
        "GRANT CONNECT ON DATABASE agent_bom TO agent_bom_app;",
        f"GRANT CONNECT ON DATABASE {database_name} TO agent_bom_app;",
    )
    sql = sql.replace(
        "GRANT CONNECT ON DATABASE agent_bom TO agent_bom_readonly;",
        f"GRANT CONNECT ON DATABASE {database_name} TO agent_bom_readonly;",
    )
    return sql


def load_bootstrap_sql(database_name: str) -> str:
    return rewrite_bootstrap_sql(INIT_SQL.read_text(), database_name)
