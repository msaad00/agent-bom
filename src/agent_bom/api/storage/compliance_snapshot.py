"""Validated, tenant-mapped snapshots for explicit compliance recovery."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from agent_bom.api.hub_payload_codec import decode_hub_payload
from agent_bom.api.storage.finding_current import CURRENT_COLUMNS
from agent_bom.api.storage.finding_ledger_writes import FIELDS
from agent_bom.api.storage.finding_payloads import hydrate_ledger_rows
from agent_bom.api.storage.sql import connection_session
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.security import sanitize_sensitive_payload

LEDGER = "compliance_hub_findings"
CURRENT = "hub_findings_current"
OBSERVATIONS = "hub_findings_current_observations"
STATE = "hub_ledger_ingest_state"
REVISION = "hub_overview_revisions"
REFERENCE_KEYS = {"hub_cve_intel": "cve_id", "hub_framework_refs": "framework_ref"}
COLUMNS = {
    LEDGER: (*FIELDS, "ordinal"),
    CURRENT: ("tenant_id", *CURRENT_COLUMNS, "origin", "scan_id", "ledger_finding_id", "ledger_ordinal"),
    OBSERVATIONS: ("tenant_id", "canonical_id", "scan_id", "observed_at"),
    **{table: ("tenant_id", key, "payload", "updated_at") for table, key in REFERENCE_KEYS.items()},
    STATE: ("tenant_id", "finding_count", "next_ordinal"),
    REVISION: ("tenant_id", "revision"),
}


@dataclass(frozen=True)
class ComplianceSnapshot:
    tenant_id: str
    tables: dict[str, list[dict[str, Any]]]
    snapshot_id: str = "compliance_hub"

    @property
    def row_count(self) -> int:
        return sum(len(rows) for rows in self.tables.values())


def read_compliance_snapshots(conn: Any, tenant_map: dict[str, str]) -> list[tuple[str, ComplianceSnapshot, dict[str, Any]]]:
    tables: dict[str, list[dict[str, Any]]] = {}
    for table, columns in COLUMNS.items():
        actual = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if actual != set(columns):
            raise ValueError("Compliance source schema is unsupported; preserve it for explicit compatibility recovery")
        tables[table] = [dict(row) for row in conn.execute(f"SELECT * FROM {table}")]
        for row in tables[table]:
            if "payload" in row:
                row["payload"] = decode_hub_payload(row["payload"])
    tenants = sorted({require_explicit_tenant_id(row["tenant_id"]) for rows in tables.values() for row in rows})
    targets: set[str] = set()
    result = []
    for source in tenants:
        if source not in tenant_map:
            raise ValueError("Every source tenant requires an explicit mapping")
        target = require_explicit_tenant_id(tenant_map[source])
        if target in targets:
            raise ValueError("Compliance recovery cannot merge multiple source tenants")
        targets.add(target)
        selected = {table: [dict(row) for row in rows if row["tenant_id"] == source] for table, rows in tables.items()}
        validate_snapshot(selected)
        # Read hydration proves every compact ledger reference can resolve in the
        # same read-only source snapshot; no store constructor migrates that file.
        tx = connection_session(conn, "sqlite")
        hydrated = hydrate_ledger_rows(tx, source, [row["payload"] for row in selected[LEDGER]])
        _validate_payloads(selected, hydrated)
        for rows in selected.values():
            for row in rows:
                row["tenant_id"] = target
        snapshot = ComplianceSnapshot(target, selected)
        result.append(("compliance_hub", snapshot, {"tenant_id": target, "tables": selected}))
    return result


def _validate_payloads(tables: dict[str, list[dict[str, Any]]], hydrated: list[dict[str, Any]]) -> None:
    from agent_bom.api.compliance_hub_store import _redact_finding
    from agent_bom.api.hub_reference_payload import batch_reference_keys

    for row in tables[LEDGER]:
        payload = row["payload"]
        if payload.get("id") not in (None, row["finding_id"]):
            raise ValueError("Compliance ledger identity disagrees with its payload")
    cves, frameworks = batch_reference_keys([row["payload"] for row in tables[LEDGER]])
    if not cves.issubset({row["cve_id"] for row in tables["hub_cve_intel"]}) or not frameworks.issubset(
        {row["framework_ref"] for row in tables["hub_framework_refs"]}
    ):
        raise ValueError("Compliance source contains missing reference evidence")
    # The finding whitelist applies to compact stored rows. Hydrated reference
    # fields have their own owner contract and are deliberately absent from it.
    payloads = [row["payload"] for table in (LEDGER, CURRENT) for row in tables[table]]
    if any(_redact_finding(payload) != payload for payload in payloads):
        raise ValueError("Compliance source requires explicit redaction before recovery")
    references = [row["payload"] for table in REFERENCE_KEYS for row in tables[table]]
    if any(sanitize_sensitive_payload(payload) != payload for payload in hydrated + references):
        raise ValueError("Compliance reference evidence requires explicit redaction before recovery")


def validate_snapshot(tables: dict[str, list[dict[str, Any]]]) -> None:
    ledger = {row["finding_id"]: row for row in tables[LEDGER]}
    ordinals = {row["ordinal"] for row in tables[LEDGER]}
    if len(ledger) != len(tables[LEDGER]) or len(ordinals) != len(ledger):
        raise ValueError("Compliance ledger has duplicate identities or ordering")
    states = tables[STATE]
    if len(states) > 1 or (ledger and not states):
        raise ValueError("Compliance source lacks unique ingestion counters")
    if states and (states[0]["finding_count"] != len(ledger) or states[0]["next_ordinal"] <= max(ordinals, default=0)):
        raise ValueError("Compliance ingestion counters disagree with the ledger")
    if len(tables[REVISION]) > 1 or any(row["revision"] < 0 for row in tables[REVISION]):
        raise ValueError("Compliance evidence revision is invalid")
    current = {row["canonical_id"]: row for row in tables[CURRENT]}
    observations: dict[str, list[dict[str, Any]]] = {key: [] for key in current}
    for row in tables[OBSERVATIONS]:
        if row["canonical_id"] not in current:
            raise ValueError("Compliance observation has no current lifecycle record")
        observations[row["canonical_id"]].append(row)
    for key, row in current.items():
        _validate_current(row, observations[key], ledger)


def _validate_current(row: dict[str, Any], observations: list[dict[str, Any]], ledger: dict[str, dict[str, Any]]) -> None:
    pointer = row["ledger_finding_id"]
    if pointer and (pointer not in ledger or row["ledger_ordinal"] != ledger[pointer]["ordinal"]):
        raise ValueError("Compliance current finding has an invalid ledger reference")
    if row["status"] not in {"open", "resolved", "reopened", "suppressed", "accepted_risk"}:
        raise ValueError("Compliance lifecycle status is unsupported")
    if row["status"] == "resolved" and not row["resolved_at"]:
        raise ValueError("Resolved compliance finding lacks its evidence timestamp")
    seen = [r["observed_at"] for r in observations]
    if not seen or row["scan_count"] != len(seen) or row["first_seen"] != min(seen) or row["last_seen"] != max(seen):
        raise ValueError("Compliance lifecycle history is incomplete or inconsistent")


def comparable_tables(tables: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    """Physical Postgres ordinals may differ; stable ordering and links may not."""
    result = {}
    for table, rows in tables.items():
        ordered = sorted(rows, key=lambda row: row["ordinal"]) if table == LEDGER else rows
        normalized = [{k: v for k, v in row.items() if k not in {"ordinal", "ledger_ordinal"}} for row in ordered]
        result[table] = normalized if table == LEDGER else sorted(normalized, key=lambda row: json.dumps(row, sort_keys=True))
    return result
