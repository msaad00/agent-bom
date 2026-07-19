"""Regression guard for #4253: enrichment circuit state must not leak across tests.

The OSV/NVD/EPSS circuit-breaker state in ``agent_bom.enrichment_posture`` is
process-global. A test that records enough consecutive OSV failures opens the
OSV circuit for minutes; once open, ``query_osv_batch_impl`` skips every remote
query, so a later test on the same xdist worker builds ZERO OSV queries and sees
empty ecosystem/vuln results (the original #4253 symptom:
``Maven not in queried ecosystems: set()``).

The autouse ``reset_global_test_state`` fixture in ``conftest.py`` must clear the
enrichment posture between tests. These two ordered tests prove it: the first
opens the OSV circuit and intentionally leaves it dirty; the second asserts the
circuit is closed on entry. Before the fix, running them in order left the
second failing.
"""

from __future__ import annotations

from agent_bom.enrichment_posture import (
    enrichment_source_available,
    record_enrichment_source,
)


def test_open_osv_circuit_leaves_it_dirty() -> None:
    """Open the OSV circuit and do NOT reset it — the fixture must clean up."""
    for _ in range(3):  # default consecutive-failure threshold
        record_enrichment_source("osv", "failure", error="timeout")
    assert enrichment_source_available("osv") is False


def test_osv_circuit_is_clean_on_entry() -> None:
    """A prior test opened the OSV circuit; this test must still start clean.

    This is the assertion that would have caught #4253 — without the autouse
    enrichment-posture reset, the circuit stayed open and OSV queries came back
    empty.
    """
    assert enrichment_source_available("osv") is True
