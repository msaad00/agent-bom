"""Contract: every finding-list surface returns the one canonical envelope (#3666).

The audit found three divergent finding-list endpoints:

    ``GET /v1/findings``                 rich canonical envelope (the target)
    ``GET /v1/compliance/hub/findings``  ``{findings, count, total, limit, offset}``
    ``GET /v1/governance/findings``      ``{findings, count, warnings}`` (no paging)

This locks all three onto :func:`finding_list_envelope` so consumers learn one
shape, and pins that the migration stayed backward compatible (legacy fields
still present) and that the hub keyset cursor walks rows 0-dup / 0-drop.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import reset_compliance_hub_store
from agent_bom.api.finding_list_envelope import FINDING_LIST_ENVELOPE_KEYS
from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


@pytest.fixture(autouse=True)
def _reset_store():
    reset_compliance_hub_store()
    set_job_store(InMemoryJobStore())
    yield
    reset_compliance_hub_store()
    set_job_store(InMemoryJobStore())


def _client(tenant: str = "tenant-alpha", role: str = "admin") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role=role, tenant=tenant))
    return client


def _assert_canonical_envelope(body: dict) -> None:
    # ``total_approximate`` is the only optional key; everything else is fixed.
    keys = set(body) - {"total_approximate"}
    assert keys == set(FINDING_LIST_ENVELOPE_KEYS), sorted(keys ^ set(FINDING_LIST_ENVELOPE_KEYS))
    assert isinstance(body["findings"], list)
    assert body["count"] == len(body["findings"])
    assert body["has_more"] == bool(body["next_cursor"])
    assert isinstance(body["warnings"], list)
    assert body["schema_version"] == "v1"


def _ingest_csv(client: TestClient, rows: int) -> None:
    csv_rows = "Title,Severity\n" + "\n".join(f"row-{i},low" for i in range(rows))
    resp = client.post("/v1/compliance/ingest", json={"format": "csv", "content": csv_rows})
    assert resp.status_code in (200, 201), resp.text


def _ingest_bulk(client: TestClient, count: int) -> None:
    resp = client.post(
        "/v1/findings/bulk",
        json={
            "source": "external_scan",
            "findings": [
                {
                    "id": f"f-{i}",
                    "vulnerability_id": f"CVE-2026-{i:04d}",
                    "severity": "high",
                    "package": "pkg",
                    "title": f"row-{i}",
                }
                for i in range(count)
            ],
        },
    )
    assert resp.status_code in (200, 201), resp.text


# ─── Canonical envelope across every surface ─────────────────────────────────


def test_v1_findings_returns_canonical_envelope():
    client = _client(role="analyst")
    client.post(
        "/v1/findings/bulk",
        json={
            "source": "external_scan",
            "findings": [{"id": "f-1", "vulnerability_id": "CVE-2026-0001", "severity": "high", "title": "x"}],
        },
    )
    body = client.get("/v1/findings").json()
    _assert_canonical_envelope(body)


def test_hub_findings_returns_canonical_envelope():
    client = _client()
    _ingest_csv(client, 3)
    body = client.get("/v1/compliance/hub/findings").json()
    _assert_canonical_envelope(body)
    # Legacy consumers depend on these — must survive the migration.
    assert body["total"] == 3
    assert body["count"] == 3
    assert body["offset"] == 0
    assert body["sort"] == "ordinal"


def test_governance_findings_returns_canonical_envelope(monkeypatch):
    class _Finding:
        def __init__(self, sev: str, cat: str) -> None:
            self._d = {"id": f"gov-{sev}-{cat}", "severity": sev, "category": cat, "title": "gov"}

        def to_dict(self) -> dict:
            return dict(self._d)

    class _Report:
        findings = [_Finding("high", "access"), _Finding("low", "tagging")]
        warnings = ["snowflake sample"]

    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct-test")
    import agent_bom.cloud as cloud_mod

    monkeypatch.setattr(cloud_mod, "discover_governance", lambda **_: _Report())

    body = _client().get("/v1/governance/findings").json()
    _assert_canonical_envelope(body)
    assert body["total"] == 2
    assert body["warnings"] == ["snowflake sample"]
    # Filter still applies within the canonical envelope.
    filtered = _client().get("/v1/governance/findings?severity=high").json()
    assert filtered["count"] == 1
    assert filtered["findings"][0]["severity"] == "high"


# ─── Canonical /v1/findings keyset cursor: 0-dup / 0-drop ────────────────────


def test_v1_findings_keyset_cursor_no_dup_no_drop():
    client = _client(role="analyst")
    _ingest_bulk(client, 50)

    # Ground truth: the full set of ingested findings (single deep page).
    baseline = client.get("/v1/findings?limit=1000").json()
    _assert_canonical_envelope(baseline)
    expected = {f["vulnerability_id"] for f in baseline["findings"]}
    assert len(expected) == 50

    # Walk the same rows with keyset pagination (never OFFSET).
    seen: list[str] = []
    cursor = ""
    pages = 0
    while True:
        qs = f"/v1/findings?limit=10{f'&cursor={cursor}' if cursor else ''}"
        body = client.get(qs).json()
        _assert_canonical_envelope(body)
        seen.extend(f["vulnerability_id"] for f in body["findings"])
        pages += 1
        cursor = body["next_cursor"]
        if not cursor:
            break
        assert pages < 20, "cursor walk did not terminate"

    assert len(seen) == len(set(seen)), "cursor walk produced duplicates"
    assert set(seen) == expected, "cursor walk dropped or added rows"


def test_hub_findings_offset_pagination_stays_backward_compatible():
    client = _client()
    _ingest_csv(client, 50)
    body = client.get("/v1/compliance/hub/findings?limit=10&offset=20").json()
    _assert_canonical_envelope(body)
    assert body["count"] == 10
    assert body["total"] == 50
    assert body["offset"] == 20
