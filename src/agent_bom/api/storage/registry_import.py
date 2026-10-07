"""Explicit, read-only-source SQLite registry import: ``python -m ...registry_import``."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from psycopg.types.json import Jsonb

from agent_bom.api import postgres_common
from agent_bom.api.storage.canonical_import import CONTROL_TABLES, import_canonical_row, payload_of, validate_groups, validate_target_groups
from agent_bom.api.storage.compliance_restore import lock_snapshot_tenants, restore_snapshot
from agent_bom.api.storage.compliance_snapshot import COLUMNS as COMPLIANCE_COLUMNS
from agent_bom.api.storage.compliance_snapshot import read_compliance_snapshots
from agent_bom.api.storage.observation_registries import (
    PostgresIssueMappingStore,
    PostgresKspmPostureStore,
    PostgresMCPObservationStore,
    PostgresSkillsScanStore,
)
from agent_bom.api.storage.registry_stores import (
    PostgresDatasetVersionStore,
    PostgresDriftIncidentStore,
    PostgresEvaluationRunStore,
    PostgresWebhookSubscriptionStore,
)
from agent_bom.api.storage.runtime_import import RUNTIME_TABLES, import_runtime_groups, validate_runtime_groups
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.security import sanitize_error

ADAPTERS = {
    cls.table: cls
    for cls in (
        PostgresKspmPostureStore,
        PostgresDatasetVersionStore,
        PostgresDriftIncidentStore,
        PostgresEvaluationRunStore,
        PostgresWebhookSubscriptionStore,
        PostgresIssueMappingStore,
        PostgresMCPObservationStore,
        PostgresSkillsScanStore,
    )
}


def read_source(path: Path, tenant_map: dict[str, str], tables: list[str]) -> list[tuple[str, Any, dict[str, Any]]]:
    """Read a consistent SQLite snapshot without schema initialization or mutation."""
    adapters = {**ADAPTERS, **CONTROL_TABLES}
    if not tables or any(table not in {*adapters, "compliance_hub"} for table in tables):
        raise ValueError("Select one or more supported registry tables explicitly")
    records = []
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        for table in sorted(set(tables), key=lambda t: (t == "access_review_items", t)):
            if table == "compliance_hub":
                records.extend(read_compliance_snapshots(conn, tenant_map))
                continue
            for row in conn.execute(f"SELECT * FROM {table} ORDER BY tenant_id, " + ", ".join(adapters[table].keys)):
                raw = dict(row)
                source_tenant = require_explicit_tenant_id(raw["tenant_id"])
                if source_tenant not in tenant_map:
                    raise ValueError("Every source tenant requires an explicit mapping")
                target = require_explicit_tenant_id(tenant_map[source_tenant])
                if table == "issue_mappings":
                    payload = raw
                elif table in {"skills_scan_run", "kspm_cluster_posture"}:
                    payload = {key: raw[key] for key in ("tenant_id", "run_id", "created_at")}
                    payload["payload"] = json.loads(raw["payload_json"])
                    if table == "kspm_cluster_posture":
                        payload["cluster_ref"] = raw["cluster_ref"]
                else:
                    payload = json.loads(raw["data"])
                if payload.get("tenant_id") != source_tenant:
                    raise ValueError("Source row and payload tenant disagree")
                payload["tenant_id"] = target
                adapter = adapters[table]
                if table in CONTROL_TABLES:
                    control = CONTROL_TABLES[table]
                    record = control.decode(payload)
                    for column in control.scalar_fields:
                        if raw[column] != getattr(record, column):
                            raise ValueError("Source row and payload state disagree")
                    payload = payload_of(record)
                else:
                    record = ADAPTERS[table].record_type(**payload)
                # Check scalar keys against JSON before importing; never silently rewrite identity.
                for key in adapter.keys:
                    if raw[key] != getattr(record, key):
                        raise ValueError("Source row and payload identity disagree")
                records.append((table, record, payload))
        conn.rollback()
    validate_groups(records, tables)
    validate_runtime_groups(records, tables)
    _validate_mapping_collisions(records)
    return records


def _validate_mapping_collisions(records: list[tuple[str, Any, dict[str, Any]]]) -> None:
    seen: dict[tuple[Any, ...], dict[str, Any]] = {}
    for table, record, payload in records:
        if table == "compliance_hub":
            continue
        keys = {**ADAPTERS, **CONTROL_TABLES}[table].keys
        if table == "issue_mappings":
            keys = ("target_kind", "target_id", "provider")
        identity = (table, record.tenant_id, *(getattr(record, key) for key in keys))
        if identity in seen and seen[identity] != payload:
            raise ValueError("Source tenant mapping collision requires reconciliation")
        seen[identity] = payload


def import_registries(
    path: Path, tenant_map: dict[str, str], tables: list[str], *, apply: bool = False, pool: Any = None
) -> dict[str, Any]:
    """One target transaction, conflict rejection, and digest receipts; source remains untouched."""
    records = read_source(path, tenant_map, tables)
    digest = hashlib.sha256(json.dumps([(t, p) for t, _, p in records], sort_keys=True).encode()).hexdigest()
    pool = pool or postgres_common._get_pool()
    counts = {"inserted": 0, "unchanged": 0, "conflicts": 0}
    # Use the restricted app role. Each scope is explicit and transaction-local;
    # no maintenance bypass is needed to import operator-selected tenant mappings.
    with pool.connection() as conn:
        lock_snapshot_tenants(conn, records)
        if any(table in {*CONTROL_TABLES, "compliance_hub"} for table in tables):
            # Static allowlisted identifiers only; one operator-selected import
            # transaction excludes live writes while canonical upserts run.
            locked = {CONTROL_TABLES[t].target_table or t if t in CONTROL_TABLES else t for t in tables}
            if "compliance_hub" in locked:
                locked.remove("compliance_hub")
                locked.update(COMPLIANCE_COLUMNS)
            if "sources" in tables:
                locked.add("credential_refs")
            conn.execute("LOCK TABLE " + ", ".join(sorted(locked)) + " IN SHARE ROW EXCLUSIVE MODE")

        runtime_counts = import_runtime_groups(conn, records)
        for key, count in runtime_counts.items():
            counts[key] += count
        for table, record, payload in records:
            if table == "compliance_hub":
                for key, count in restore_snapshot(conn, record).items():
                    counts[key] += count
                continue
            if table in RUNTIME_TABLES:
                continue
            conn.execute("SELECT set_config('app.tenant_id',%s,true)", (record.tenant_id,))
            conn.execute("SELECT set_config('app.bypass_rls','0',true)")
            if table in CONTROL_TABLES:
                counts[import_canonical_row(conn, table, record, payload)] += 1
                continue
            adapter = ADAPTERS[table]
            keys = ("tenant_id", *adapter.keys)
            values = tuple(getattr(record, key) for key in keys)
            where = " AND ".join(f"{key}=%s" for key in keys)
            if table == "issue_mappings":
                where = "tenant_id=%s AND (mapping_id=%s OR (target_kind=%s AND target_id=%s AND provider=%s))"
                values = (*values, record.target_kind, record.target_id, record.provider)
            inserted = False
            if apply:
                columns = ("tenant_id", *adapter.columns, "data")
                inserted = (
                    conn.execute(
                        f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(columns))}) "
                        "ON CONFLICT DO NOTHING RETURNING 1",
                        (record.tenant_id, *(getattr(record, column) for column in adapter.columns), Jsonb(payload)),
                    ).fetchone()
                    is not None
                )
            rows = conn.execute(f"SELECT data FROM {table} WHERE {where} FOR UPDATE", values).fetchall()
            if not rows and not apply:
                counts["inserted"] += 1
            elif len(rows) == 1 and rows[0][0] == payload:
                counts["inserted" if inserted else "unchanged"] += 1
            else:
                counts["conflicts"] += 1
        counts["conflicts"] += validate_target_groups(conn, records)
        if counts["conflicts"] or not apply:
            conn.rollback()
        else:
            conn.commit()
    return {
        "mode": "apply" if apply else "dry-run",
        "committed": apply and not counts["conflicts"],
        "source_snapshot_sha256": digest,
        "selected_tables": tables,
        "row_count": sum(r.row_count if t == "compliance_hub" else 1 for t, r, _ in records),
        **counts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument(
        "--tenant-map", required=True, type=Path, help="JSON object mapping every source tenant to an approved target tenant"
    )
    parser.add_argument("--table", action="append", choices=sorted({*ADAPTERS, *CONTROL_TABLES, "compliance_hub"}), required=True)
    parser.add_argument("--apply", action="store_true", help="Commit only when every selected row is new or identical")
    args = parser.parse_args()
    try:
        receipt = import_registries(args.source, json.loads(args.tenant_map.read_text()), args.table, apply=args.apply)
    except Exception as exc:
        sys.stderr.write(sanitize_error(exc, generic=True) + "\n")
        raise SystemExit(1) from None
    sys.stdout.write(json.dumps(receipt, sort_keys=True) + "\n")
    if receipt["conflicts"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
