"""Keyset cursor pagination for hub current-state findings (#3511)."""

from __future__ import annotations

from uuid import uuid4

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore, set_compliance_hub_store
from agent_bom.api.finding_cursor import decode_finding_cursor, encode_finding_cursor
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def test_finding_cursor_round_trip() -> None:
    token = encode_finding_cursor(
        sort="effective_reach",
        primary=88.5,
        last_seen="2026-07-04T00:00:00Z",
        canonical_id="finding-abc",
    )
    primary, last_seen, canonical_id = decode_finding_cursor(token, expected_sort="effective_reach")
    assert primary == 88.5
    assert last_seen == "2026-07-04T00:00:00Z"
    assert canonical_id == "finding-abc"


def test_sqlite_list_current_page_keyset_walk() -> None:
    import tempfile

    tenant = f"keyset-{uuid4().hex}"
    with tempfile.TemporaryDirectory() as tmp:
        store = SQLiteComplianceHubStore(f"{tmp}/keyset.db")
        findings = []
        for idx in range(1, 8):
            findings.append(
                {
                    "id": f"finding-{idx}",
                    "title": f"Finding {idx}",
                    "severity": "high" if idx % 2 else "medium",
                    "effective_reach_score": float(idx),
                    "origin": "bulk_ingest",
                    "source": "test",
                    "batch_id": "batch-keyset",
                }
            )
        store.add(tenant, findings)
        store.upsert_current_batch(
            tenant,
            findings,
            observed_at="2026-07-04T00:00:00Z",
            batch_id="batch-keyset",
            source="test",
        )

        page1, total, next_cursor = store.list_current_page(tenant, limit=3, origin="bulk_ingest")
        assert total == 7
        assert len(page1) == 3
        assert next_cursor
        assert page1[0]["effective_reach_score"] >= page1[1]["effective_reach_score"]

        page2, _, next_cursor2 = store.list_current_page(
            tenant,
            limit=3,
            origin="bulk_ingest",
            cursor=next_cursor,
            include_total=False,
        )
        assert len(page2) == 3
        assert {row["id"] for row in page1}.isdisjoint({row["id"] for row in page2})

        page3, _, next_cursor3 = store.list_current_page(
            tenant,
            limit=3,
            origin="bulk_ingest",
            cursor=next_cursor2,
            include_total=False,
        )
        assert len(page3) == 1
        assert next_cursor3 is None


def test_findings_api_keyset_pagination() -> None:
    from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore

    tenant = f"api-keyset-{uuid4().hex}"
    store = InMemoryComplianceHubStore()
    set_compliance_hub_store(store)
    findings = [
        {
            "id": f"bulk-{idx}",
            "title": f"Bulk {idx}",
            "severity": "high",
            "effective_reach_score": float(idx),
            "origin": "bulk_ingest",
            "source": "test",
            "batch_id": "batch-api",
        }
        for idx in range(1, 6)
    ]
    store.add(tenant, findings)
    store.upsert_current_batch(
        tenant,
        findings,
        observed_at="2026-07-04T00:00:00Z",
        batch_id="batch-api",
        source="test",
    )

    client = TestClient(app)
    headers = proxy_headers(tenant=tenant)
    first = client.get("/v1/findings?limit=2", headers=headers)
    assert first.status_code == 200
    body = first.json()
    assert body["count"] == 2
    assert body["has_more"] is True
    assert body["next_cursor"]

    second = client.get(
        f"/v1/findings?limit=2&cursor={body['next_cursor']}",
        headers=headers,
    )
    assert second.status_code == 200
    body2 = second.json()
    assert body2["count"] == 2
    assert {row["id"] for row in body["findings"]}.isdisjoint({row["id"] for row in body2["findings"]})


def test_findings_api_rejects_cursor_with_offset() -> None:
    client = TestClient(app)
    headers = proxy_headers(tenant="default")
    resp = client.get("/v1/findings?limit=2&offset=1&cursor=abc", headers=headers)
    assert resp.status_code == 400
