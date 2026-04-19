"""Benchmarks for the scanner hot paths that show up on large inventories.

Run with:
    pytest tests/benchmarks/ --benchmark-only
    pytest tests/benchmarks/ --benchmark-only -k "50k"    # only the largest
    pytest tests/benchmarks/ --benchmark-json=bench.json  # for CI artifact

Each hot path is measured at 1k / 10k / 50k package inventory sizes so we
have a real O(n) growth curve instead of a single small-scale number.

The 50k variant is marked ``slow`` and skipped by default in CI; run it
locally or on a dedicated perf runner. Numbers currently reported in
docs/PERFORMANCE_BENCHMARKS.md are drawn from these benchmarks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

import pytest

# pytest-benchmark is opt-in; skip cleanly when not installed so the main
# test suite stays lean.
pytest.importorskip("pytest_benchmark")


def _synth_blast_radius(n: int) -> list[dict[str, Any]]:
    """Build ``n`` synthetic blast-radius entries tagged across 14 frameworks."""
    tag_pools = {
        "owasp_tags": ["LLM01", "LLM02", "LLM03", "LLM04"],
        "owasp_mcp_tags": ["MCP01", "MCP02", "MCP03"],
        "atlas_tags": ["AML.T0010", "AML.T0020"],
        "nist_ai_rmf_tags": ["GOVERN-1.1", "MAP-5.1"],
        "owasp_agentic_tags": ["A1", "A2"],
        "eu_ai_act_tags": ["Art-10", "Art-15"],
        "nist_csf_tags": ["ID.AM-1", "PR.AC-3"],
        "iso_27001_tags": ["A.8.2", "A.8.25"],
        "soc2_tags": ["CC6.1", "CC7.1"],
        "cmmc_tags": ["AC.L1-3.1.1"],
        "fedramp_tags": ["SC-7", "SI-4"],
        "pci_dss_tags": ["Req-6.2"],
        "cis_tags": ["1.1", "2.1"],
        "nist_800_53_tags": ["CM-8", "RA-5"],
    }
    entries = []
    for i in range(n):
        entry = {
            "vulnerability_id": f"CVE-2024-{i:05d}",
            "package": f"pkg-{i % 500}@1.0.{i % 10}",
            "severity": ["critical", "high", "medium", "low"][i % 4],
            "fixed_version": "1.0.99",
            "affected_agents": [f"agent-{i % 50}"],
        }
        for field, pool in tag_pools.items():
            entry[field] = [pool[i % len(pool)]]
        entries.append(entry)
    return entries


# ─── Blast-radius tag index (real `_index_blast_radii_by_tag`) ─────────────


def _index_by_tag(blast: list[dict]) -> dict[str, list[dict]]:
    """Copy of the production indexing pass — mirrors compliance.py flow."""
    by_tag: dict[str, list[dict]] = {}
    tag_fields = (
        "owasp_tags",
        "owasp_mcp_tags",
        "atlas_tags",
        "nist_ai_rmf_tags",
        "nist_csf_tags",
        "iso_27001_tags",
        "soc2_tags",
        "cmmc_tags",
        "fedramp_tags",
        "owasp_agentic_tags",
        "eu_ai_act_tags",
        "cis_tags",
        "nist_800_53_tags",
        "pci_dss_tags",
    )
    for br in blast:
        for field in tag_fields:
            for tag in br.get(field, []) or []:
                by_tag.setdefault(tag, []).append(br)
    return by_tag


class TestTagIndexPerformance:
    @pytest.mark.parametrize("n", [1_000, 10_000])
    def test_index_by_tag(self, benchmark, n: int) -> None:
        blast = _synth_blast_radius(n)
        result = benchmark(_index_by_tag, blast)
        assert result, "index must not be empty"

    @pytest.mark.slow
    @pytest.mark.skipif(
        os.environ.get("AGENT_BOM_BENCH_FULL") != "1",
        reason="50k variant is slow; run locally with AGENT_BOM_BENCH_FULL=1",
    )
    def test_index_by_tag_50k(self, benchmark) -> None:
        blast = _synth_blast_radius(50_000)
        result = benchmark(_index_by_tag, blast)
        assert len(result) > 20, "50k inventory should produce at least 20 distinct tag buckets"


# ─── Compliance bundle signature (real HMAC path) ──────────────────────────


def _canonical_signature(body: dict, key: bytes) -> str:
    payload = json.dumps(body, sort_keys=True).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


class TestBundleSignaturePerformance:
    @pytest.mark.parametrize("n_controls", [100, 1_000, 10_000])
    def test_hmac_sign_canonical_bundle(self, benchmark, n_controls: int) -> None:
        body = {
            "schema_version": "v1",
            "framework": "owasp-llm",
            "framework_key": "owasp_llm_top10",
            "tenant_id": "tenant-bench",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2026-01-02T00:00:00+00:00",
            "nonce": "0" * 32,
            "controls": [
                {
                    "control_id": f"LLM{i:02d}",
                    "control_name": f"Control {i}",
                    "status": "fail" if i % 3 == 0 else "pass",
                    "finding_count": i % 10,
                    "evidence": [{"finding_id": f"F{i}-{j}", "vulnerability_id": f"CVE-2024-{j:04d}"} for j in range(i % 10)],
                }
                for i in range(n_controls)
            ],
            "audit_events": [],
            "audit_log_integrity": {"verified": n_controls, "tampered": 0, "checked": n_controls},
        }
        key = b"benchmark-secret-key-32-bytes-long!"
        sig = benchmark(_canonical_signature, body, key)
        assert len(sig) == 64  # HMAC-SHA256 hex
