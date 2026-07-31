"""Regression guard for findings list latency at modest scale."""

from __future__ import annotations

import time
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

# The property worth guarding is that first-page cost does not scale with the
# size of the tenant's table — i.e. nobody reintroduced a full scan on the read
# path. A wall-clock ceiling cannot measure that on shared CI hardware: the same
# unchanged code measured 622ms on a contended runner and ~30ms on an idle one,
# so the threshold only ever recorded how busy the machine was.
#
# Compare the small table against a 4x larger one in the same process instead.
# Indexed/keyset reads stay roughly flat; a full scan grows with the row count.
# The allowance is deliberately loose because both samples share whatever noise
# the runner has — it still catches the 4x-and-worse growth of a real scan.
_SCALE_FACTOR = 4
_MAX_GROWTH_RATIO = 2.5

# Retained only as a catastrophic-regression backstop, far above any plausible
# scheduling noise. It is not the assertion that does the work.
_ABSURD_ELAPSED_MS = 10_000.0


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


def _time_first_page(client: TestClient, tenant_id: str, expected_total: int) -> float:
    """Return the steady-state milliseconds for one first-page read."""
    headers = proxy_headers(role="viewer", tenant=tenant_id)
    params = {"limit": _PAGE_LIMIT, "offset": 0}

    # Warm the route so the timed samples reflect steady-state list cost.
    warmup = client.get("/v1/findings", params=params, headers=headers)
    assert warmup.status_code == 200, warmup.text

    # Take the best of three: a scheduling stall inflates a sample but can never
    # make a genuinely slow read look fast, so the minimum is the honest figure.
    samples = []
    for _ in range(3):
        started = time.perf_counter()
        response = client.get("/v1/findings", params=params, headers=headers)
        samples.append((time.perf_counter() - started) * 1000)
        assert response.status_code == 200, response.text

    body = response.json()
    assert body["total"] == expected_total
    assert body["count"] == _PAGE_LIMIT
    assert len(body["findings"]) == _PAGE_LIMIT
    return min(samples)


def test_findings_first_page_cost_does_not_scale_with_table_size() -> None:
    """A first-page read must stay flat as the tenant's table grows."""
    set_compliance_hub_store(InMemoryComplianceHubStore())
    client = TestClient(app)

    small = _time_first_page(client, _seed_tenant(_FINDINGS_COUNT), _FINDINGS_COUNT)
    large_count = _FINDINGS_COUNT * _SCALE_FACTOR
    large = _time_first_page(client, _seed_tenant(large_count), large_count)

    ratio = large / small if small > 0 else 0.0
    assert ratio < _MAX_GROWTH_RATIO, (
        f"first-page cost grew {ratio:.1f}x for a {_SCALE_FACTOR}x larger table "
        f"({small:.1f}ms at {_FINDINGS_COUNT} rows -> {large:.1f}ms at {large_count}); "
        "the read path is scanning rather than paging"
    )
    assert large < _ABSURD_ELAPSED_MS, f"GET /v1/findings took {large:.1f}ms at {large_count} rows"


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
