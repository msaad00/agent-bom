"""Order-independence guard for the proxy audit-event dedupe table.

``/v1/proxy/audit`` dedupes alerts by ``(tenant_id, event_id)`` in the process-
global ``_audit_dedupe`` table with a 24h window. That table is NOT reset by the
in-memory store fixtures, so a ``(tenant, event_id)`` key claimed by one test
suppresses the SAME event in a later test — a genuine order-dependent flake once
randomized ordering is on repo-wide.

These two tests deliberately ingest the SAME ``event_id`` and, crucially, the
second does NOT manually clear the dedupe table. It relies solely on the autouse
``reset_global_test_state`` fixture having cleared ``_audit_dedupe`` on the prior
test's teardown. If that reset regresses, ``test_two_...`` fails with
``accepted_alert_count == 0`` (the event is wrongly treated as a replay).
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import app

_SHARED_EVENT_ID = "evt-dedupe-isolation-shared"


def _payload() -> dict:
    return {
        "source_id": "proxy-isolation",
        "session_id": "session-iso",
        "alerts": [
            {
                "event_id": _SHARED_EVENT_ID,
                "severity": "critical",
                "detector": "credential_leak",
                "message": "secret detected",
            }
        ],
        "summary": None,
    }


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def test_one_ingests_shared_event_id(client):
    # First test to claim the shared (default, event_id) key. No manual dedupe
    # reset here — we intentionally leave the key behind to prove the autouse
    # teardown clears it before the next test runs.
    resp = client.post("/v1/proxy/audit", json=_payload())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["accepted_alert_count"] == 1
    assert body["duplicate_alert_count"] == 0


def test_two_same_event_id_not_deduped_across_test_boundary(client):
    # This test does NOT call _reset_audit_dedupe_for_tests(). If the conftest
    # reset covers _audit_dedupe (the fix), the key left by test_one is gone and
    # this identical event is accepted as new. Without the fix, it would be
    # deduped: accepted_alert_count == 0, duplicate_alert_count == 1.
    resp = client.post("/v1/proxy/audit", json=_payload())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["accepted_alert_count"] == 1, (
        "shared event_id was deduped across the test boundary — the proxy "
        "_audit_dedupe table leaked from the previous test (conftest reset regressed)"
    )
    assert body["duplicate_alert_count"] == 0
    assert _SHARED_EVENT_ID not in body["duplicate_event_ids"]
