"""Regression guard for findings list latency at modest scale."""

from __future__ import annotations

import time
import uuid

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_FINDINGS_COUNT = 2000
_PAGE_LIMIT = 50
_MAX_ELAPSED_MS = 500.0


def _synthetic_findings(count: int, *, batch_id: str) -> list[dict]:
    rows: list[dict] = []
    for ordinal in range(1, count + 1):
        rows.append(
            {
                "id": f"scale:{batch_id}:{ordinal}",
                "title": f"Scale finding {ordinal}",
                "severity": ("critical", "high", "medium", "low")[ordinal % 4],
                "cvss_score": float(ordinal % 10),
                "epss_score": float((ordinal % 100) / 100),
                "cisa_kev": ordinal % 23 == 0,
                "origin": "bulk_ingest",
                "source": "test_findings_read_scale",
                "batch_id": batch_id,
                "bulk_ordinal": ordinal,
            }
        )
    return rows


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def setup_function() -> None:
    from agent_bom.api.findings_count_cache import reset_findings_count_cache

    set_compliance_hub_store(InMemoryComplianceHubStore())
    reset_findings_count_cache()


def test_findings_list_page_under_500ms_at_2k_rows() -> None:
    tenant_id = f"findings-scale-{uuid.uuid4().hex}"
    batch_id = f"batch-{uuid.uuid4().hex}"
    store = InMemoryComplianceHubStore()
    set_compliance_hub_store(store)
    findings = _synthetic_findings(_FINDINGS_COUNT, batch_id=batch_id)
    store.add(tenant_id, findings)
    store.upsert_current_batch(
        tenant_id,
        findings,
        observed_at="2026-07-03T12:00:00Z",
        batch_id=batch_id,
        source="test_findings_read_scale",
    )

    client = TestClient(app)
    headers = proxy_headers(role="viewer", tenant=tenant_id)

    # Warm the route once so the timed sample reflects steady-state list cost.
    warmup = client.get("/v1/findings", params={"limit": _PAGE_LIMIT, "offset": 0}, headers=headers)
    assert warmup.status_code == 200, warmup.text

    started = time.perf_counter()
    response = client.get("/v1/findings", params={"limit": _PAGE_LIMIT, "offset": 0}, headers=headers)
    elapsed_ms = (time.perf_counter() - started) * 1000

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == _FINDINGS_COUNT
    assert body["count"] == _PAGE_LIMIT
    assert len(body["findings"]) == _PAGE_LIMIT
    assert elapsed_ms < _MAX_ELAPSED_MS, f"GET /v1/findings took {elapsed_ms:.1f}ms (limit {_MAX_ELAPSED_MS}ms)"


def test_findings_approximate_total_skips_count_on_deep_page() -> None:
    tenant_id = f"findings-approx-{uuid.uuid4().hex}"
    batch_id = f"batch-{uuid.uuid4().hex}"
    store = InMemoryComplianceHubStore()
    set_compliance_hub_store(store)
    findings = _synthetic_findings(_FINDINGS_COUNT, batch_id=batch_id)
    store.add(tenant_id, findings)
    store.upsert_current_batch(
        tenant_id,
        findings,
        observed_at="2026-07-03T12:00:00Z",
        batch_id=batch_id,
        source="test_findings_read_scale",
    )

    client = TestClient(app)
    headers = proxy_headers(role="viewer", tenant=tenant_id)

    first = client.get(
        "/v1/findings",
        params={"limit": _PAGE_LIMIT, "offset": 0, "approximate_total": "true"},
        headers=headers,
    )
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["total"] == _FINDINGS_COUNT
    assert first_body.get("total_approximate") is not True

    deep = client.get(
        "/v1/findings",
        params={"limit": _PAGE_LIMIT, "offset": _PAGE_LIMIT, "approximate_total": "true"},
        headers=headers,
    )
    assert deep.status_code == 200, deep.text
    deep_body = deep.json()
    assert deep_body["total"] == _FINDINGS_COUNT
    assert deep_body.get("total_approximate") is True
    assert len(deep_body["findings"]) == _PAGE_LIMIT
