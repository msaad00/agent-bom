"""Regression tests for hub current-state payload dedup (#3487)."""

from __future__ import annotations

import sqlite3
from uuid import uuid4

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, SQLiteComplianceHubStore
from agent_bom.api.hub_current_payload import (
    current_state_overlay,
    hydrate_current_payload,
    is_overlay_only_payload,
    resolve_ledger_finding_id,
)
from agent_bom.api.hub_payload_codec import decode_hub_payload


def test_current_state_overlay_keeps_filter_fields_only() -> None:
    payload = {
        "id": "finding-1",
        "canonical_id": "finding-1",
        "origin": "bulk_ingest",
        "batch_id": "batch-1",
        "source": "agent-runtime",
        "title": "Secret in MCP config",
        "severity": "critical",
        "evidence": {"summary": "large blob"},
    }
    overlay = current_state_overlay(payload)
    assert overlay == {
        "id": "finding-1",
        "canonical_id": "finding-1",
        "origin": "bulk_ingest",
        "batch_id": "batch-1",
        "source": "agent-runtime",
    }
    assert is_overlay_only_payload(overlay)


def test_hydrate_current_payload_merges_ledger_body() -> None:
    ledger = {
        "id": "finding-1",
        "title": "Secret in MCP config",
        "severity": "critical",
        "evidence": {"summary": "large blob"},
    }
    overlay = current_state_overlay({**ledger, "origin": "bulk_ingest", "batch_id": "batch-1", "source": "scan"})
    merged = hydrate_current_payload(
        {"payload": overlay, "ledger_finding_id": "finding-1"},
        ledger_payloads={"finding-1": ledger},
    )
    assert merged["title"] == "Secret in MCP config"
    assert merged["evidence"] == {"summary": "large blob"}
    assert merged["origin"] == "bulk_ingest"


def test_in_memory_store_persists_overlay_and_hydrates_on_read() -> None:
    store = InMemoryComplianceHubStore()
    tenant_id = f"overlay-{uuid4().hex}"
    finding = {
        "id": "finding-a",
        "canonical_id": "finding-a",
        "title": "Reachable production credential",
        "severity": "high",
        "effective_reach_score": 9.5,
        "evidence": {"path": "/etc/secrets"},
    }
    store.add(tenant_id, [finding])
    store.upsert_current_batch(
        tenant_id,
        [finding],
        observed_at="2026-07-04T12:00:00Z",
        batch_id="batch-1",
        source="agent-runtime",
    )

    raw = store._current[tenant_id]["finding-a"]
    assert raw["ledger_finding_id"] == resolve_ledger_finding_id(finding)
    assert is_overlay_only_payload(raw["payload"])

    page, _total, _cursor = store.list_current_page(tenant_id, limit=10)
    assert len(page) == 1
    assert page[0]["title"] == "Reachable production credential"
    assert page[0]["severity"] == "high"


def test_sqlite_current_row_stores_overlay_bytes_only(tmp_path) -> None:
    db_path = tmp_path / "hub-overlay.db"
    store = SQLiteComplianceHubStore(str(db_path))
    tenant_id = f"sqlite-{uuid4().hex}"
    finding = {
        "id": "finding-b",
        "title": "Stale dependency with exploit path",
        "severity": "medium",
        "cvss_score": 7.1,
        "frameworks": ["soc2"],
    }
    store.add(tenant_id, [finding])
    store.upsert_current_batch(
        tenant_id,
        [finding],
        observed_at="2026-07-04T12:00:00Z",
        batch_id="batch-2",
        source="compliance",
    )

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT payload, ledger_finding_id
            FROM hub_findings_current
            WHERE tenant_id = ? AND canonical_id = ?
            """,
            (tenant_id, "finding-b"),
        ).fetchone()
    assert row is not None
    stored_payload = decode_hub_payload(row[0])
    assert is_overlay_only_payload(stored_payload)
    assert row[1] == "finding-b"
    assert "title" not in stored_payload

    page, total, _cursor = store.list_current_page(tenant_id, limit=10)
    assert total == 1
    assert page[0]["title"] == "Stale dependency with exploit path"
    assert page[0]["cvss_score"] == 7.1
