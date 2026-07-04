"""Reference-table normalization for hub finding payloads (#3513)."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, SQLiteComplianceHubStore
from agent_bom.api.hub_payload_codec import encode_hub_payload
from agent_bom.api.hub_reference_payload import extract_reference_blobs, hydrate_reference_payload
from agent_bom.api.hub_reference_store import reset_in_memory_hub_references


@pytest.fixture(autouse=True)
def _reset_memory_refs():
    reset_in_memory_hub_references()
    yield
    reset_in_memory_hub_references()


def _shared_intel_finding(finding_id: str, *, cve_id: str = "CVE-2026-3513") -> dict:
    return {
        "id": finding_id,
        "title": f"Finding {finding_id}",
        "severity": "high",
        "cvss_score": 8.8,
        "epss_score": 0.42,
        "cve_id": cve_id,
        "vulnerability_id": cve_id,
        "summary": "Shared CVE enrichment blob " + ("x" * 400),
        "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        "advisory_sources": ["osv", "ghsa", "nvd"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_tags": ["LLM01", "LLM02"],
        "nist_csf_tags": ["ID.AM-1"],
        "compliance_tags": ["LLM01"],
        "origin": "bulk_ingest",
        "source": "test",
        "batch_id": "batch-ref",
    }


def test_extract_and_hydrate_reference_blobs_roundtrip() -> None:
    finding = _shared_intel_finding("f-1")
    slim, intel_blob, framework_blob = extract_reference_blobs(finding)
    assert slim["intel_ref"] == "CVE-2026-3513"
    assert slim["framework_ref"]
    assert "summary" not in slim
    assert "owasp_tags" not in slim
    assert intel_blob is not None
    assert framework_blob is not None

    restored = hydrate_reference_payload(
        slim,
        cve_intel={"CVE-2026-3513": intel_blob},
        framework_refs={slim["framework_ref"]: framework_blob},
    )
    assert restored["summary"] == finding["summary"]
    assert restored["owasp_tags"] == finding["owasp_tags"]
    assert restored["cvss_score"] == finding["cvss_score"]


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"])
def test_hub_list_returns_hydrated_user_visible_fields(store_factory: str, tmp_path) -> None:
    if store_factory == "memory":
        store = InMemoryComplianceHubStore()
    else:
        store = SQLiteComplianceHubStore(str(tmp_path / "refs.db"))

    tenant = f"ref-{uuid4().hex}"
    findings = [_shared_intel_finding(f"f-{idx}") for idx in range(5)]
    store.add(tenant, findings)

    listed = store.list(tenant)
    assert len(listed) == 5
    for item, original in zip(listed, findings):
        assert item["summary"] == original["summary"]
        assert item["owasp_tags"] == original["owasp_tags"]
        assert item["cvss_score"] == original["cvss_score"]

    if store_factory == "sqlite":
        row = store._conn.execute(
            "SELECT payload FROM compliance_hub_findings WHERE tenant_id = ? LIMIT 1",
            (tenant,),
        ).fetchone()
        assert row is not None
        stored = json.loads(row[0])
        assert stored.get("intel_ref") == "CVE-2026-3513"
        assert "summary" not in stored


def test_reference_normalization_reduces_ledger_bytes_at_scale(tmp_path) -> None:
    store = SQLiteComplianceHubStore(str(tmp_path / "scale.db"))
    tenant = f"scale-{uuid4().hex}"
    count = 1000
    findings = [_shared_intel_finding(f"scale-{idx}") for idx in range(count)]
    store.add(tenant, findings)

    inline_bytes = sum(len(encode_hub_payload(f)) for f in findings)
    rows = store._conn.execute(
        "SELECT payload FROM compliance_hub_findings WHERE tenant_id = ?",
        (tenant,),
    ).fetchall()
    stored_bytes = sum(len(row[0]) for row in rows)
    intel_rows = store._conn.execute(
        "SELECT payload FROM hub_cve_intel WHERE tenant_id = ?",
        (tenant,),
    ).fetchall()
    ref_bytes = sum(len(row[0]) for row in intel_rows)

    assert stored_bytes < inline_bytes * 0.65
    assert ref_bytes < inline_bytes * 0.02
    assert stored_bytes + ref_bytes < inline_bytes * 0.7
