"""Hydrate finding references with bounded portable SQL in the caller's snapshot."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from agent_bom.api.hub_payload_codec import decode_hub_payload
from agent_bom.api.hub_reference_payload import batch_reference_keys, hydrate_reference_payload
from agent_bom.api.storage.sql import SqlSession


def _reference_rows(tx: SqlSession, tenant_id: str, keys: Sequence[str], *, frameworks: bool) -> dict[str, dict[str, Any]]:
    table, column = ("hub_framework_refs", "framework_ref") if frameworks else ("hub_cve_intel", "cve_id")
    found: dict[str, dict[str, Any]] = {}
    for start in range(0, len(keys), 500):
        batch = keys[start : start + 500]
        placeholders = ",".join("?" for _ in batch)
        rows = tx.execute(
            f"SELECT {column}, payload FROM {table} WHERE tenant_id = ? AND {column} IN ({placeholders})",  # nosec B608
            (tenant_id, *batch),
        ).fetchall()
        found.update((str(row[0]), decode_hub_payload(row[1])) for row in rows)
    return found


def hydrate_ledger_rows(tx: SqlSession, tenant_id: str, payloads: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    cve_ids, framework_refs = batch_reference_keys(payloads)
    cve_map = _reference_rows(tx, tenant_id, sorted(cve_ids), frameworks=False)
    fw_map = _reference_rows(tx, tenant_id, sorted(framework_refs), frameworks=True)
    return [hydrate_reference_payload(item, cve_intel=cve_map, framework_refs=fw_map) for item in payloads]
