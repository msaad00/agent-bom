"""Persistence helpers for hub reference tables (#3513)."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from agent_bom.api.hub_payload_codec import decode_hub_payload, encode_hub_payload
from agent_bom.api.hub_reference_payload import (
    batch_reference_keys,
    extract_reference_blobs,
    hydrate_reference_payload,
    resolve_cve_id,
)
from agent_bom.config import HUB_REFERENCE_NORMALIZE

_HUB_CVE_INTEL_DDL = """
CREATE TABLE IF NOT EXISTS hub_cve_intel (
    tenant_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, cve_id)
)
"""

_HUB_FRAMEWORK_REFS_DDL = """
CREATE TABLE IF NOT EXISTS hub_framework_refs (
    tenant_id TEXT NOT NULL,
    framework_ref TEXT NOT NULL,
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, framework_ref)
)
"""

_MEMORY_CVE_INTEL: dict[tuple[str, str], dict[str, Any]] = {}
_MEMORY_FRAMEWORK_REFS: dict[tuple[str, str], dict[str, Any]] = {}
_MEMORY_LOCK = threading.Lock()


def reset_in_memory_hub_references() -> None:
    with _MEMORY_LOCK:
        _MEMORY_CVE_INTEL.clear()
        _MEMORY_FRAMEWORK_REFS.clear()


def ensure_sqlite_reference_tables(conn: sqlite3.Connection) -> None:
    conn.execute(_HUB_CVE_INTEL_DDL)
    conn.execute(_HUB_FRAMEWORK_REFS_DDL)


def ensure_postgres_reference_tables(conn: Any) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hub_cve_intel (
            tenant_id TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            payload JSONB NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, cve_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hub_framework_refs (
            tenant_id TEXT NOT NULL,
            framework_ref TEXT NOT NULL,
            payload JSONB NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, framework_ref)
        )
        """
    )


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_finding_payload_for_store(tenant_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Extract shared reference blobs and return the slim ledger payload."""
    if not HUB_REFERENCE_NORMALIZE:
        return dict(payload)
    slim, intel_blob, framework_blob = extract_reference_blobs(payload)
    if intel_blob:
        cve_id = resolve_cve_id(payload)
        if cve_id:
            _upsert_cve_intel_memory(tenant_id, cve_id, intel_blob)
    if framework_blob:
        fw_ref = str(slim.get("framework_ref") or "")
        if fw_ref:
            _upsert_framework_ref_memory(tenant_id, fw_ref, framework_blob)
    return slim


def persist_finding_references_sqlite(conn: sqlite3.Connection, tenant_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if not HUB_REFERENCE_NORMALIZE:
        return dict(payload)
    ensure_sqlite_reference_tables(conn)
    slim, intel_blob, framework_blob = extract_reference_blobs(payload)
    now = _now_iso()
    if intel_blob:
        cve_id = resolve_cve_id(payload)
        if cve_id:
            conn.execute(
                """
                INSERT INTO hub_cve_intel (tenant_id, cve_id, payload, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(tenant_id, cve_id) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (tenant_id, cve_id, encode_hub_payload(intel_blob), now),
            )
    if framework_blob:
        fw_ref = str(slim.get("framework_ref") or "")
        if fw_ref:
            conn.execute(
                """
                INSERT INTO hub_framework_refs (tenant_id, framework_ref, payload, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(tenant_id, framework_ref) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (tenant_id, fw_ref, encode_hub_payload(framework_blob), now),
            )
    return slim


def persist_finding_references_postgres(conn: Any, tenant_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if not HUB_REFERENCE_NORMALIZE:
        return dict(payload)
    ensure_postgres_reference_tables(conn)
    slim, intel_blob, framework_blob = extract_reference_blobs(payload)
    now = _now_iso()
    if intel_blob:
        cve_id = resolve_cve_id(payload)
        if cve_id:
            conn.execute(
                """
                INSERT INTO hub_cve_intel (tenant_id, cve_id, payload, updated_at)
                VALUES (%s, %s, %s::jsonb, %s)
                ON CONFLICT (tenant_id, cve_id) DO UPDATE SET
                    payload = EXCLUDED.payload,
                    updated_at = EXCLUDED.updated_at
                """,
                (tenant_id, cve_id, json.dumps(intel_blob, sort_keys=True), now),
            )
    if framework_blob:
        fw_ref = str(slim.get("framework_ref") or "")
        if fw_ref:
            conn.execute(
                """
                INSERT INTO hub_framework_refs (tenant_id, framework_ref, payload, updated_at)
                VALUES (%s, %s, %s::jsonb, %s)
                ON CONFLICT (tenant_id, framework_ref) DO UPDATE SET
                    payload = EXCLUDED.payload,
                    updated_at = EXCLUDED.updated_at
                """,
                (tenant_id, fw_ref, json.dumps(framework_blob, sort_keys=True), now),
            )
    return slim


def _upsert_cve_intel_memory(tenant_id: str, cve_id: str, blob: dict[str, Any]) -> None:
    with _MEMORY_LOCK:
        _MEMORY_CVE_INTEL[(tenant_id, cve_id)] = dict(blob)


def _upsert_framework_ref_memory(tenant_id: str, framework_ref: str, blob: dict[str, Any]) -> None:
    with _MEMORY_LOCK:
        _MEMORY_FRAMEWORK_REFS[(tenant_id, framework_ref)] = dict(blob)


def _fetch_cve_intel_memory(tenant_id: str, cve_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    with _MEMORY_LOCK:
        for cve_id in cve_ids:
            blob = _MEMORY_CVE_INTEL.get((tenant_id, cve_id))
            if blob:
                out[cve_id] = dict(blob)
    return out


def _fetch_framework_refs_memory(tenant_id: str, refs: Sequence[str]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    with _MEMORY_LOCK:
        for ref in refs:
            blob = _MEMORY_FRAMEWORK_REFS.get((tenant_id, ref))
            if blob:
                out[ref] = dict(blob)
    return out


def _fetch_cve_intel_sqlite(conn: sqlite3.Connection, tenant_id: str, cve_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    if not cve_ids:
        return {}
    placeholders = ",".join("?" * len(cve_ids))
    rows = conn.execute(
        f"SELECT cve_id, payload FROM hub_cve_intel WHERE tenant_id = ? AND cve_id IN ({placeholders})",  # nosec B608
        (tenant_id, *cve_ids),
    ).fetchall()
    return {str(row[0]): decode_hub_payload(row[1]) for row in rows}


def _fetch_framework_refs_sqlite(conn: sqlite3.Connection, tenant_id: str, refs: Sequence[str]) -> dict[str, dict[str, Any]]:
    if not refs:
        return {}
    placeholders = ",".join("?" * len(refs))
    rows = conn.execute(
        f"SELECT framework_ref, payload FROM hub_framework_refs WHERE tenant_id = ? AND framework_ref IN ({placeholders})",  # nosec B608
        (tenant_id, *refs),
    ).fetchall()
    return {str(row[0]): decode_hub_payload(row[1]) for row in rows}


def _fetch_cve_intel_postgres(conn: Any, tenant_id: str, cve_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    if not cve_ids:
        return {}
    rows = conn.execute(
        "SELECT cve_id, payload FROM hub_cve_intel WHERE tenant_id = %s AND cve_id = ANY(%s)",
        (tenant_id, list(cve_ids)),
    ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for cve_id, raw in rows:
        out[str(cve_id)] = decode_hub_payload(raw)
    return out


def _fetch_framework_refs_postgres(conn: Any, tenant_id: str, refs: Sequence[str]) -> dict[str, dict[str, Any]]:
    if not refs:
        return {}
    rows = conn.execute(
        "SELECT framework_ref, payload FROM hub_framework_refs WHERE tenant_id = %s AND framework_ref = ANY(%s)",
        (tenant_id, list(refs)),
    ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for framework_ref, raw in rows:
        out[str(framework_ref)] = decode_hub_payload(raw)
    return out


def hydrate_finding_payload_memory(tenant_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    cve_ids, framework_refs = batch_reference_keys([payload])
    return hydrate_reference_payload(
        payload,
        cve_intel=_fetch_cve_intel_memory(tenant_id, sorted(cve_ids)),
        framework_refs=_fetch_framework_refs_memory(tenant_id, sorted(framework_refs)),
    )


def hydrate_finding_payloads_memory(tenant_id: str, payloads: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    items = list(payloads)
    cve_ids, framework_refs = batch_reference_keys(items)
    cve_map = _fetch_cve_intel_memory(tenant_id, sorted(cve_ids))
    fw_map = _fetch_framework_refs_memory(tenant_id, sorted(framework_refs))
    return [hydrate_reference_payload(item, cve_intel=cve_map, framework_refs=fw_map) for item in items]


def hydrate_finding_payloads_sqlite(
    conn: sqlite3.Connection,
    tenant_id: str,
    payloads: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    items = list(payloads)
    cve_ids, framework_refs = batch_reference_keys(items)
    cve_map = _fetch_cve_intel_sqlite(conn, tenant_id, sorted(cve_ids))
    fw_map = _fetch_framework_refs_sqlite(conn, tenant_id, sorted(framework_refs))
    return [hydrate_reference_payload(item, cve_intel=cve_map, framework_refs=fw_map) for item in items]


def hydrate_finding_payloads_postgres(
    conn: Any,
    tenant_id: str,
    payloads: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    items = list(payloads)
    cve_ids, framework_refs = batch_reference_keys(items)
    cve_map = _fetch_cve_intel_postgres(conn, tenant_id, sorted(cve_ids))
    fw_map = _fetch_framework_refs_postgres(conn, tenant_id, sorted(framework_refs))
    return [hydrate_reference_payload(item, cve_intel=cve_map, framework_refs=fw_map) for item in items]
