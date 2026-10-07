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
    if not tables or any(table not in ADAPTERS for table in tables):
        raise ValueError("Select one or more supported registry tables explicitly")
    records = []
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        for table in tables:
            for row in conn.execute(f"SELECT * FROM {table} ORDER BY tenant_id, " + ", ".join(ADAPTERS[table].keys)):
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
                record = ADAPTERS[table].record_type(**payload)
                # Check scalar keys against JSON before importing; never silently rewrite identity.
                for key in ADAPTERS[table].keys:
                    if raw[key] != getattr(record, key):
                        raise ValueError("Source row and payload identity disagree")
                records.append((table, record, payload))
        conn.rollback()
    _validate_mapping_collisions(records)
    return records


def _validate_mapping_collisions(records: list[tuple[str, Any, dict[str, Any]]]) -> None:
    seen: dict[tuple[Any, ...], dict[str, Any]] = {}
    for table, record, payload in records:
        keys = ADAPTERS[table].keys
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
        for table, record, payload in records:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)", (record.tenant_id,))
            conn.execute("SELECT set_config('app.bypass_rls','0',true)")
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
        if counts["conflicts"] or not apply:
            conn.rollback()
        else:
            conn.commit()
    return {
        "mode": "apply" if apply else "dry-run",
        "committed": apply and not counts["conflicts"],
        "source_snapshot_sha256": digest,
        "selected_tables": tables,
        "row_count": len(records),
        **counts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument(
        "--tenant-map", required=True, type=Path, help="JSON object mapping every source tenant to an approved target tenant"
    )
    parser.add_argument("--table", action="append", choices=sorted(ADAPTERS), required=True)
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
