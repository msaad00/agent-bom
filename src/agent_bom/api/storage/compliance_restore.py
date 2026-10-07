"""Explicit snapshot restoration using canonical finding SQL owners.

Normal ingest evolves lifecycle state. Recovery restores validated historical
state into an empty tenant hub and refuses to overwrite existing evidence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from agent_bom.api.finding_lifecycle import normalize_observed_at
from agent_bom.api.hub_payload_codec import encode_hub_payload
from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore
from agent_bom.api.storage.canonical_import import PinnedImportPool
from agent_bom.api.storage.compliance_snapshot import (
    COLUMNS,
    CURRENT,
    LEDGER,
    OBSERVATIONS,
    REFERENCE_KEYS,
    REVISION,
    STATE,
    ComplianceSnapshot,
    comparable_tables,
)
from agent_bom.api.storage.finding_current import CURRENT_COLUMNS, LEDGER_ORDINAL_SENTINEL
from agent_bom.api.storage.finding_current_writes import current_upsert
from agent_bom.api.storage.finding_ledger_writes import FIELDS, ledger_upsert
from agent_bom.api.storage.finding_write_session import finding_write_session
from agent_bom.api.storage.sql import load_json
from agent_bom.api.storage_schema import postgres_deployment_configured
from agent_bom.api.tenant_worker import tenant_bound_context


def read_target_snapshot(conn: Any, tenant_id: str) -> dict[str, list[dict[str, Any]]]:
    tables = {}
    for table, columns in COLUMNS.items():
        found = conn.execute(f"SELECT {', '.join(columns)} FROM {table} WHERE tenant_id=%s", (tenant_id,)).fetchall()
        rows = [
            dict(zip(columns, (normalize_observed_at(value) if isinstance(value, datetime) else value for value in row))) for row in found
        ]
        for row in rows:
            if "payload" in row:
                row["payload"] = load_json(row["payload"])
        tables[table] = rows
    return tables


def lock_snapshot_tenants(conn: Any, records: list[tuple[str, Any, dict[str, Any]]]) -> None:
    # Match the canonical writer order: tenant advisory lock before table locks.
    for tenant in sorted({record.tenant_id for table, record, _ in records if table == "compliance_hub"}):
        finding_write_session(conn, "postgres", tenant)


def restore_snapshot(conn: Any, snapshot: ComplianceSnapshot) -> dict[str, int]:
    if not postgres_deployment_configured():
        raise ValueError("Configure the Postgres deployment before restoring compliance evidence")
    tenant_id = snapshot.tenant_id
    conn.execute("SELECT set_config('app.tenant_id',%s,true)", (tenant_id,))
    conn.execute("SELECT set_config('app.bypass_rls','0',true)")
    with tenant_bound_context(tenant_id):
        # Verify migrated schema through the owning store, without bootstrap DDL.
        PostgresComplianceHubStore(pool=cast(Any, PinnedImportPool(conn)))
        tx = finding_write_session(conn, "postgres", tenant_id)
        current = read_target_snapshot(conn, tenant_id)
        if any(current.values()):
            if comparable_tables(current) == comparable_tables(snapshot.tables):
                return {"inserted": 0, "unchanged": snapshot.row_count, "conflicts": 0}
            return {"inserted": 0, "unchanged": 0, "conflicts": 1}
        _restore_rows(tx, snapshot)
        if comparable_tables(read_target_snapshot(conn, tenant_id)) != comparable_tables(snapshot.tables):
            raise ValueError("Compliance recovery did not preserve the validated source snapshot")
    return {"inserted": snapshot.row_count, "unchanged": 0, "conflicts": 0}


def _restore_rows(tx: Any, snapshot: ComplianceSnapshot) -> None:
    tables = snapshot.tables
    for table in REFERENCE_KEYS:
        _insert_rows(tx, table, tables[table])
    ordinals = {}
    for row in sorted(tables[LEDGER], key=lambda row: row["ordinal"]):
        values = tuple(encode_hub_payload(row[key]) if key == "payload" else row[key] for key in FIELDS)
        saved = tx.execute(ledger_upsert("postgres") + " RETURNING ordinal", values).fetchone()
        ordinals[row["finding_id"]] = saved[0]
    # Lifecycle fields and historical observation timestamps are preserved.
    # Internal ledger sequence values are mapped to the new Postgres rows.
    fields = ("tenant_id", *CURRENT_COLUMNS, "origin", "scan_id", "ledger_finding_id", "ledger_ordinal")
    for original in tables[CURRENT]:
        row = dict(original)
        row["ledger_ordinal"] = ordinals.get(row["ledger_finding_id"], LEDGER_ORDINAL_SENTINEL)
        values = tuple(encode_hub_payload(row[key]) if key == "payload" else row[key] for key in fields)
        tx.execute(current_upsert("postgres", True), values)
    _insert_rows(tx, OBSERVATIONS, tables[OBSERVATIONS])
    _insert_rows(tx, STATE, tables[STATE])
    _insert_rows(tx, REVISION, tables[REVISION])


def _insert_rows(tx: Any, table: str, rows: list[dict[str, Any]]) -> None:
    columns = COLUMNS[table]
    values = ["CAST(? AS JSONB)" if column == "payload" else "?" for column in columns]
    sql = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join(values)})"
    for row in rows:
        tx.execute(sql, tuple(encode_hub_payload(row[key]) if key == "payload" else row[key] for key in columns))
