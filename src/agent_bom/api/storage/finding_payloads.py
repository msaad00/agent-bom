"""Hydrate finding references with bounded portable SQL in the caller's snapshot."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from agent_bom.api.hub_payload_codec import decode_hub_payload, encode_hub_payload
from agent_bom.api.hub_reference_payload import batch_reference_keys, extract_reference_blobs, hydrate_reference_payload, resolve_cve_id
from agent_bom.api.storage.sql import Dialect, SqlSession, utc_timestamp


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


def persist_references(tx: SqlSession, dialect: Dialect, tenant: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    from agent_bom.api.hub_reference_store import HUB_REFERENCE_NORMALIZE

    if not HUB_REFERENCE_NORMALIZE:
        return dict(payload)
    slim, intel, framework = extract_reference_blobs(payload)
    value = "CAST(? AS JSONB)" if dialect == "postgres" else "?"
    for table, key, identity, blob in [
        ("hub_cve_intel", "cve_id", resolve_cve_id(payload), intel),
        ("hub_framework_refs", "framework_ref", str(slim.get("framework_ref") or ""), framework),
    ]:
        if blob and identity:
            tx.execute(
                f"INSERT INTO {table} (tenant_id, {key}, payload, updated_at) VALUES (?, ?, {value}, ?) "  # nosec B608
                f"ON CONFLICT (tenant_id, {key}) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at",
                (
                    tenant,
                    identity,
                    json.dumps(blob, sort_keys=True) if dialect == "postgres" else encode_hub_payload(blob),
                    utc_timestamp(),
                ),
            )  # nosec B608
    return slim
