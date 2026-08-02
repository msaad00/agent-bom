"""Regression guard for findings list latency at modest scale."""

from __future__ import annotations

import uuid

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    get_compliance_hub_store,
    set_compliance_hub_store,
)
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_FINDINGS_COUNT = 2000
_PAGE_LIMIT = 50

# The property worth guarding is that the route pages the store rather than
# fetching a tenant's whole table and slicing it in Python.
#
# Two earlier attempts measured time and both were wrong. A wall-clock ceiling
# recorded how busy the runner was (622ms contended, ~30ms idle, same code). A
# growth *ratio* was better but still wrong here, because the in-memory store
# backing these tests is a dict, not an indexed table — it examines rows on
# every read by construction, so its cost grows with size no matter how correct
# the route is. Asserting flatness against it tests the wrong thing.
#
# Assert the contract instead: one bounded store call per request, with the
# page limit pushed down, returning no more rows than a page. That is exactly
# what "fetch everything and slice" violates, it is identical on every backend,
# and it cannot flake.
_SCALE_TIERS = (2_000, 8_000, 32_000)


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


def _seed_tenant(count: int) -> str:
    """Seed one tenant with ``count`` findings and return its id."""
    tenant_id = f"findings-scale-{uuid.uuid4().hex}"
    batch_id = f"batch-{uuid.uuid4().hex}"
    findings = _synthetic_findings(count, batch_id=batch_id)
    store = get_compliance_hub_store()
    store.add(tenant_id, findings)
    store.upsert_current_batch(
        tenant_id,
        findings,
        observed_at="2026-07-03T12:00:00Z",
        batch_id=batch_id,
        source="test_findings_read_scale",
    )
    return tenant_id


def _first_page_store_calls(
    client: TestClient, tenant_id: str, expected_total: int
) -> list[tuple[int | None, int]]:
    """Return ``(limit_pushed_down, rows_returned)`` for each store call one page makes."""
    headers = proxy_headers(role="viewer", tenant=tenant_id)
    params = {"limit": _PAGE_LIMIT, "offset": 0}
    calls: list[tuple[int | None, int]] = []
    original = InMemoryComplianceHubStore.list_current_page

    def _spy(self, tenant: str, **kwargs):  # type: ignore[no-untyped-def]
        rows, total, cursor = original(self, tenant, **kwargs)
        calls.append((kwargs.get("limit"), len(rows)))
        return rows, total, cursor

    InMemoryComplianceHubStore.list_current_page = _spy  # type: ignore[method-assign]
    try:
        response = client.get("/v1/findings", params=params, headers=headers)
    finally:
        InMemoryComplianceHubStore.list_current_page = original  # type: ignore[method-assign]

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == expected_total, f"total {body['total']} != seeded {expected_total}"
    assert body["count"] == _PAGE_LIMIT, (
        f"page reported count={body['count']} for a {_PAGE_LIMIT}-row request at "
        f"{expected_total} rows; the page limit was not honoured"
    )
    assert len(body["findings"]) == _PAGE_LIMIT, (
        f"page returned {len(body['findings'])} findings for a {_PAGE_LIMIT}-row request"
    )
    return calls


def test_findings_first_page_is_paged_not_scanned() -> None:
    """One bounded store call per page, whatever the tenant's table size."""
    set_compliance_hub_store(InMemoryComplianceHubStore())
    client = TestClient(app)

    for total in _SCALE_TIERS:
        calls = _first_page_store_calls(client, _seed_tenant(total), total)

        assert len(calls) == 1, (
            f"one first page issued {len(calls)} store reads at {total} rows; "
            "the route is fetching in a loop rather than paging"
        )
        limit, rows = calls[0]
        assert limit == _PAGE_LIMIT, (
            f"route asked the store for limit={limit} at {total} rows, expected {_PAGE_LIMIT}; "
            "the page limit is no longer pushed down"
        )
        assert rows <= _PAGE_LIMIT, (
            f"store returned {rows} rows for a {_PAGE_LIMIT}-row page at {total} rows; "
            "the read path is scanning rather than paging"
        )


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
