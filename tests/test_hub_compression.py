"""Tests for hub payload compression and HTTP gzip responses."""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.hub_payload_codec import decode_hub_payload, encode_hub_payload
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def test_hub_payload_codec_round_trip_small_plain_json() -> None:
    payload = {"id": "f-1", "severity": "low", "title": "short"}
    stored = encode_hub_payload(payload)
    assert '"__abom_zstd"' not in stored
    assert decode_hub_payload(stored) == payload


def test_hub_payload_codec_round_trip_large_zstd() -> None:
    pytest.importorskip("zstandard")
    payload = {
        "id": "f-large",
        "severity": "critical",
        "description": "x" * 900,
        "evidence": {"blob": "y" * 400},
    }
    stored = encode_hub_payload(payload)
    assert "__abom_zstd" in stored
    assert decode_hub_payload(stored) == payload
    raw = json.dumps(payload, sort_keys=True).encode()
    assert len(stored) < len(raw)


def test_findings_list_returns_gzip_when_accepted() -> None:
    store = InMemoryComplianceHubStore()
    set_compliance_hub_store(store)
    tenant = "gzip-tenant"
    findings = [
        {
            "id": f"bulk-{idx}",
            "severity": "high",
            "title": f"Finding {idx}",
            "description": "z" * 120,
            "origin": "bulk_ingest",
            "batch_id": "batch-gzip",
        }
        for idx in range(40)
    ]
    store.add(tenant, findings)
    store.upsert_current_batch(
        tenant,
        findings,
        observed_at="2026-07-04T00:00:00Z",
        batch_id="batch-gzip",
        source="bulk_ingest",
    )

    client = TestClient(app)
    headers = {**proxy_headers(tenant=tenant), "Accept-Encoding": "gzip"}
    resp = client.get("/v1/findings?limit=50", headers=headers)
    assert resp.status_code == 200
    assert resp.headers.get("content-encoding") == "gzip"
    body = json.loads(resp.content)
    assert body["total"] == 40
    assert len(body["findings"]) == 40
