"""P0 regression: finding ingest must be idempotent (#3242).

Resending an identical batch of findings — same stable ids, or the same
content without client ids, or the same body under one ``Idempotency-Key`` —
must not inflate a tenant's total. Before the fix, the compliance-hub PK was
``(tenant_id, finding_id, ordinal)`` with ``ordinal = MAX(ordinal)+1`` and the
bulk route minted a fresh ``batch_id``/``id`` per attempt, so three identical
sends yielded 100 -> 200 -> 300.
"""

from __future__ import annotations

import json
import sqlite3
from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    SQLiteComplianceHubStore,
    reset_compliance_hub_store,
)
from agent_bom.api.server import app
from agent_bom.api.stores import set_idempotency_store
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def setup_function() -> None:
    from agent_bom.api.server import set_job_store
    from agent_bom.api.store import InMemoryJobStore

    reset_compliance_hub_store()
    set_idempotency_store(None)
    set_job_store(InMemoryJobStore())


def teardown_function() -> None:
    from agent_bom.api.server import set_job_store
    from agent_bom.api.store import InMemoryJobStore

    reset_compliance_hub_store()
    set_idempotency_store(None)
    set_job_store(InMemoryJobStore())


def _client(tenant: str, role: str = "analyst") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role=role, tenant=tenant))
    return client


def _batch(count: int = 100, *, with_id: bool = True) -> list[dict]:
    rows: list[dict] = []
    for i in range(count):
        row = {
            "title": f"finding {i}",
            "severity": "high",
            "vulnerability_id": f"CVE-2026-{i:04d}",
            "package": f"pkg-{i}",
            "location": f"/app/{i}.py",
        }
        if with_id:
            row["id"] = f"stable-{i:03d}"
        rows.append(row)
    return rows


# ─── Bulk ingest ─────────────────────────────────────────────────────────────


def test_bulk_ingest_idempotent_with_stable_ids() -> None:
    tenant = f"idem-bulk-{uuid4().hex}"
    client = _client(tenant)
    findings = _batch(100, with_id=True)
    totals = []
    for _ in range(3):
        resp = client.post("/v1/findings/bulk", json={"source": "agent", "findings": findings})
        assert resp.status_code == 201, resp.text
        totals.append(resp.json()["tenant_total"])
    assert totals == [100, 100, 100]


def test_bulk_ingest_idempotent_without_client_ids() -> None:
    """No client id -> content-derived deterministic id -> resend collapses."""
    tenant = f"idem-bulk-noid-{uuid4().hex}"
    client = _client(tenant)
    findings = _batch(100, with_id=False)
    totals = []
    for _ in range(3):
        resp = client.post("/v1/findings/bulk", json={"source": "agent", "findings": findings})
        assert resp.status_code == 201, resp.text
        totals.append(resp.json()["tenant_total"])
    assert totals == [100, 100, 100]


def test_bulk_ingest_new_findings_still_append() -> None:
    tenant = f"idem-bulk-append-{uuid4().hex}"
    client = _client(tenant)
    first = client.post("/v1/findings/bulk", json={"source": "agent", "findings": _batch(100)})
    assert first.json()["tenant_total"] == 100
    extra = [{"id": f"extra-{i}", "severity": "low", "title": f"e{i}"} for i in range(10)]
    second = client.post("/v1/findings/bulk", json={"source": "agent", "findings": extra})
    assert second.json()["tenant_total"] == 110


def test_bulk_ingest_idempotency_key_replays_cached_response() -> None:
    tenant = f"idem-bulk-key-{uuid4().hex}"
    client = _client(tenant)
    findings = _batch(100)
    headers = {"Idempotency-Key": "batch-key-1"}
    first = client.post("/v1/findings/bulk", json={"source": "agent", "findings": findings}, headers=headers)
    second = client.post("/v1/findings/bulk", json={"source": "agent", "findings": findings}, headers=headers)
    assert first.status_code == 201 and second.status_code == 201
    assert first.json()["batch_id"] == second.json()["batch_id"]
    assert second.json()["idempotent_replay"] is True
    assert second.json()["tenant_total"] == 100


def test_bulk_ingest_idempotency_key_conflict_on_different_body() -> None:
    tenant = f"idem-bulk-conflict-{uuid4().hex}"
    client = _client(tenant)
    headers = {"Idempotency-Key": "batch-key-2"}
    first = client.post("/v1/findings/bulk", json={"source": "agent", "findings": _batch(100)}, headers=headers)
    assert first.status_code == 201
    conflicting = client.post(
        "/v1/findings/bulk",
        json={"source": "agent", "findings": [{"id": "different", "severity": "low"}]},
        headers=headers,
    )
    assert conflicting.status_code == 409, conflicting.text


# ─── Compliance ingest ───────────────────────────────────────────────────────


def _sarif(count: int = 5) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "external-secrets",
                            "rules": [{"id": f"SECRET-{i}", "properties": {"tags": ["secret", "CWE-798"]}} for i in range(count)],
                        }
                    },
                    "results": [
                        {
                            "ruleId": f"SECRET-{i}",
                            "level": "error",
                            "message": {"text": f"issue {i}"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"app/{i}.py"}}}],
                            "properties": {"security-severity": "9.5"},
                        }
                        for i in range(count)
                    ],
                }
            ],
        }
    )


def test_compliance_ingest_idempotent_on_resend() -> None:
    tenant = f"idem-compliance-{uuid4().hex}"
    client = _client(tenant, role="admin")
    content = _sarif(5)
    totals = []
    for _ in range(3):
        resp = client.post("/v1/compliance/ingest", json={"format": "sarif", "content": content})
        assert resp.status_code == 201, resp.text
        totals.append(resp.json()["tenant_total"])
    assert totals == [5, 5, 5]


# ─── scan_count must not inflate on resend (P1-5) ────────────────────────────


def _max_scan_count(tenant: str) -> int:
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    rows, _total, _cursor = get_compliance_hub_store().list_current_page(tenant, limit=500)
    return max((int(row.get("scan_count", 0) or 0) for row in rows), default=0)


def test_bulk_ingest_resend_does_not_inflate_scan_count() -> None:
    """A resent identical bulk batch must dedup the observation, not re-count it."""
    tenant = f"idem-scancount-bulk-{uuid4().hex}"
    client = _client(tenant)
    findings = _batch(20, with_id=True)
    for _ in range(3):
        resp = client.post("/v1/findings/bulk", json={"source": "agent", "findings": findings})
        assert resp.status_code == 201, resp.text
    # Random per-request batch_ids used to miss the (canonical, batch_id)
    # observation dedup, so scan_count climbed 1 -> 2 -> 3. It must stay 1.
    assert _max_scan_count(tenant) == 1


def test_compliance_ingest_resend_does_not_inflate_scan_count() -> None:
    tenant = f"idem-scancount-compliance-{uuid4().hex}"
    client = _client(tenant, role="admin")
    content = _sarif(5)
    for _ in range(3):
        resp = client.post("/v1/compliance/ingest", json={"format": "sarif", "content": content})
        assert resp.status_code == 201, resp.text
    assert _max_scan_count(tenant) == 1


def test_bulk_ingest_distinct_bodies_do_increment_scan_count() -> None:
    """Guard against over-dedup: genuinely new observations must still count."""
    tenant = f"idem-scancount-distinct-{uuid4().hex}"
    client = _client(tenant)
    findings = _batch(5, with_id=True)
    # Same findings, but a changing companion row shifts the body fingerprint so
    # each POST is a distinct batch -> the shared findings are re-observed.
    for n in range(3):
        body = {"source": "agent", "findings": [*findings, {"id": f"marker-{n}", "severity": "low", "title": f"m{n}"}]}
        resp = client.post("/v1/findings/bulk", json=body)
        assert resp.status_code == 201, resp.text
    assert _max_scan_count(tenant) >= 2


# ─── Scan job replay ─────────────────────────────────────────────────────────


def test_scan_idempotency_key_returns_same_job() -> None:
    tenant = f"idem-scan-{uuid4().hex}"
    client = _client(tenant, role="admin")
    headers = {"Idempotency-Key": "scan-key-1"}
    first = client.post("/v1/scan", json={}, headers=headers)
    second = client.post("/v1/scan", json={}, headers=headers)
    assert first.status_code == 202, first.text
    assert second.status_code == 202, second.text
    assert first.json()["job_id"] == second.json()["job_id"]


def test_scan_idempotency_key_conflict_on_different_body() -> None:
    tenant = f"idem-scan-conflict-{uuid4().hex}"
    client = _client(tenant, role="admin")
    headers = {"Idempotency-Key": "scan-key-2"}
    first = client.post("/v1/scan", json={}, headers=headers)
    assert first.status_code == 202
    conflicting = client.post("/v1/scan", json={"images": ["alpine:latest"]}, headers=headers)
    assert conflicting.status_code == 409, conflicting.text


# ─── Store-level backends ────────────────────────────────────────────────────


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_store_add_is_idempotent_on_finding_id(kind: str, tmp_path) -> None:
    store = InMemoryComplianceHubStore() if kind == "memory" else SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "tenant-store"
    findings = [{"id": f"f-{i}", "severity": "high", "origin": "bulk_ingest"} for i in range(100)]
    assert store.add(tenant, findings) == 100
    assert store.add(tenant, findings) == 100
    assert store.add(tenant, findings) == 100
    # Resend refreshes payload in place; ordinal (ingest order) is preserved.
    rows, total = store.list_page(tenant, limit=5, offset=0, sort="ordinal")
    assert total == 100
    assert [r["id"] for r in rows] == [f"f-{i}" for i in range(5)]


def test_sqlite_migrates_ordinal_primary_key_and_dedups(tmp_path) -> None:
    """A pre-idempotency table (PK includes ordinal, with dup finding rows)
    must rebuild to PK (tenant_id, finding_id), keeping the lowest ordinal."""
    db_path = tmp_path / "hub.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE compliance_hub_findings (
                tenant_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                source TEXT NOT NULL,
                applicable_frameworks_csv TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                effective_reach_score REAL NOT NULL DEFAULT 0,
                origin TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (tenant_id, finding_id, ordinal)
            )
            """
        )
        # Same finding_id ingested twice (ordinals 1 and 2) — a legacy duplicate.
        conn.executemany(
            "INSERT INTO compliance_hub_findings (tenant_id, finding_id, ingested_at, source, payload, ordinal) VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("t", "dup", "2026-01-01T00:00:00Z", "s", json.dumps({"id": "dup", "v": 1}), 1),
                ("t", "dup", "2026-01-02T00:00:00Z", "s", json.dumps({"id": "dup", "v": 2}), 2),
                ("t", "solo", "2026-01-03T00:00:00Z", "s", json.dumps({"id": "solo"}), 3),
            ],
        )
        conn.commit()

    store = SQLiteComplianceHubStore(str(db_path))
    assert store.count("t") == 2  # dup collapsed to one row

    pk_cols = [row[1] for row in store._conn.execute("PRAGMA table_info(compliance_hub_findings)").fetchall() if row[5]]  # noqa: SLF001
    assert pk_cols == ["tenant_id", "finding_id"]

    # Lowest ordinal (the original) is retained for the deduped finding.
    kept = store._conn.execute("SELECT ordinal FROM compliance_hub_findings WHERE finding_id = 'dup'").fetchone()  # noqa: SLF001
    assert kept[0] == 1

    # Re-opening the migrated DB is a no-op (idempotent migration).
    SQLiteComplianceHubStore(str(db_path))
    assert store.count("t") == 2
