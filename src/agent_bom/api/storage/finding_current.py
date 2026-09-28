"""Portable current-finding row decoding and tenant-scoped hydration."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from agent_bom.api.hub_current_payload import hydrate_current_payload
from agent_bom.api.hub_payload_codec import decode_hub_payload
from agent_bom.api.storage.finding_payloads import hydrate_ledger_rows
from agent_bom.api.storage.sql import SqlSession

CURRENT_COLUMNS = (
    "canonical_id",
    "first_seen",
    "last_seen",
    "status",
    "severity",
    "severity_rank",
    "cvss_score",
    "effective_reach_score",
    "scan_count",
    "resolved_at",
    "reopened_at",
    "updated_at",
    "payload",
)
LEDGER_COLUMNS = ("ledger_finding_id", "ledger_ordinal")
LEDGER_ORDINAL_SENTINEL = 2**63 - 1


def columns(has_ledger: bool) -> str:
    return ", ".join((*CURRENT_COLUMNS, *LEDGER_COLUMNS) if has_ledger else CURRENT_COLUMNS)


def parse_row(row: Sequence[Any], *, has_ledger_col: bool) -> dict[str, Any]:
    result = dict(zip(CURRENT_COLUMNS, row))
    result["payload"] = decode_hub_payload(row[12])
    if has_ledger_col:
        result["ledger_finding_id"] = row[13]
        if len(row) > 14:
            result["ledger_ordinal"] = int(row[14])
    return result


def keyed_rows(tx: SqlSession, tenant: str, ids: Sequence[str], *, ledger: bool, has_ledger: bool = True) -> list[Any]:
    table, key, selected = (
        ("compliance_hub_findings", "finding_id", "finding_id, payload, ordinal")
        if ledger
        else ("hub_findings_current", "canonical_id", columns(has_ledger))
    )
    rows: list[Any] = []
    keys = list(dict.fromkeys(key for key in ids if key))
    for start in range(0, len(keys), 500):
        batch = keys[start : start + 500]
        placeholders = ",".join("?" for _ in batch)
        rows.extend(
            tx.execute(f"SELECT {selected} FROM {table} WHERE tenant_id = ? AND {key} IN ({placeholders})", (tenant, *batch)).fetchall()  # nosec B608
        )  # nosec B608
    return rows


def hydrate_rows(tx: SqlSession, tenant: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ledger = keyed_rows(tx, tenant, [str(row.get("ledger_finding_id") or "") for row in rows], ledger=True)
    payloads = hydrate_ledger_rows(tx, tenant, [decode_hub_payload(row[1]) for row in ledger])
    ledger_map = {str(row[0]): payload for row, payload in zip(ledger, payloads)}
    return [{**row, "payload": hydrate_current_payload(row, ledger_payloads=ledger_map)} for row in rows]
