"""Portable ledger writes preserving ordinal, redaction, references and SLA carry."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from agent_bom.api.hub_payload_codec import decode_hub_payload, encode_hub_payload
from agent_bom.api.storage.finding_payloads import hydrate_ledger_rows, persist_references
from agent_bom.api.storage.sql import Dialect, SqlSession, utc_timestamp
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.graph.sla import carry_finding_sla

FIELDS = (
    "tenant_id",
    "finding_id",
    "ingested_at",
    "source",
    "applicable_frameworks_csv",
    "payload",
    "effective_reach_score",
    "origin",
    "severity",
    "severity_rank",
    "cvss_score",
    "scan_id",
)
# Preserve the atomic conflict guard for assignments made outside hub ingest.
POSTGRES_SLA_CARRY = """EXCLUDED.payload || CASE
    WHEN compliance_hub_findings.payload->>'sla_due_at' IS NOT NULL
     AND COALESCE(compliance_hub_findings.payload->>'sla_due_at_source', 'unknown') != 'severity-kev/v1'
     AND COALESCE(EXCLUDED.payload->>'sla_due_at_source', 'unknown') != 'explicit'
    THEN jsonb_build_object(
        'sla_due_at', compliance_hub_findings.payload->'sla_due_at',
        'sla_due_at_source', CASE WHEN compliance_hub_findings.payload->>'sla_due_at_source' = 'explicit'
            THEN 'explicit' ELSE 'unknown' END)
    ELSE '{}'::jsonb END"""


def ledger_upsert(dialect: Dialect) -> str:
    fields = (*FIELDS, "ordinal") if dialect == "sqlite" else FIELDS
    placeholders = ["CAST(? AS JSONB)" if field == "payload" and dialect == "postgres" else "?" for field in fields]
    updates = [f"{field} = excluded.{field}" for field in FIELDS if field not in {"tenant_id", "finding_id", "payload"}]
    updates.append("payload = " + (POSTGRES_SLA_CARRY if dialect == "postgres" else "excluded.payload"))
    return (
        f"INSERT INTO compliance_hub_findings ({', '.join(fields)}) VALUES ({', '.join(placeholders)}) "  # nosec B608
        f"ON CONFLICT (tenant_id, finding_id) DO UPDATE SET {', '.join(updates)}"
    )


def prior_payloads(tx: SqlSession, dialect: Dialect, tenant: str, ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    rows: list[Any] = []
    keys = sorted(set(ids))
    for start in range(0, len(keys), 500):
        batch = keys[start : start + 500]
        markers = ",".join("?" for _ in batch)
        lock = " FOR UPDATE" if dialect == "postgres" else ""
        rows.extend(
            tx.execute(
                f"SELECT finding_id, payload FROM compliance_hub_findings WHERE tenant_id = ? "  # nosec B608
                f"AND finding_id IN ({markers}) ORDER BY finding_id{lock}",
                (tenant, *batch),
            ).fetchall()
        )  # nosec B608
    hydrated = hydrate_ledger_rows(tx, tenant, [decode_hub_payload(row[1]) for row in rows])
    return {str(row[0]): payload for row, payload in zip(rows, hydrated)}


def write_ledger_batch(
    tx: SqlSession, dialect: Dialect, tenant_id: str, findings: Sequence[dict[str, Any]], *, next_ordinal: int = 0
) -> tuple[int, int]:
    from agent_bom.api.compliance_hub_store import (
        _cvss_value,
        _frameworks_csv,
        _redact_finding,
        _severity_rank,
        compute_effective_reach_score,
    )

    tenant = require_explicit_tenant_id(tenant_id)
    now = utc_timestamp()
    previous = prior_payloads(tx, dialect, tenant, [str(row["id"]) for row in findings if isinstance(row, dict) and row.get("id")])
    prepared: list[tuple[str, tuple[Any, ...]]] = []
    for offset, original in enumerate(findings):
        if not isinstance(original, dict):
            continue
        payload = _redact_finding(persist_references(tx, dialect, tenant, original))
        fallback = f"hub-{next_ordinal + offset}" if dialect == "sqlite" else f"hub-{now}-{id(original)}"
        finding_id = str(payload.get("id") or fallback)
        payload = carry_finding_sla(payload, previous.get(finding_id, {}))
        previous[finding_id] = payload
        row: tuple[Any, ...] = (
            tenant,
            finding_id,
            now,
            str(payload.get("source") or ""),
            _frameworks_csv(original),
            encode_hub_payload(payload),
            compute_effective_reach_score(payload),
            str(payload.get("origin") or ""),
            str(payload.get("severity") or ""),
            _severity_rank(payload),
            _cvss_value(payload),
            str(payload.get("batch_id") or payload.get("scan_id") or ""),
        )
        if dialect == "sqlite":
            row += (next_ordinal + offset,)
        prepared.append((finding_id, row))
    # Generated fallback ids also participate in idempotent conflict accounting.
    existing: set[str] = set()
    keys = list(dict.fromkeys(key for key, _ in prepared))
    for start in range(0, len(keys), 500):
        batch = keys[start : start + 500]
        markers = ",".join("?" for _ in batch)
        found = tx.execute(
            f"SELECT finding_id FROM compliance_hub_findings WHERE tenant_id = ? AND finding_id IN ({markers})",  # nosec B608
            (tenant, *batch),
        ).fetchall()  # nosec B608
        existing.update(str(row[0]) for row in found)
    tx.executemany(ledger_upsert(dialect), [row for _, row in prepared])
    return len({key for key, _ in prepared} - existing), len(prepared)
