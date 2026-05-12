"""Regression tests for the v0.86.7 API/data P1 batch (P1-16/17/18/19/20/22/24).

These tests pin down the seven defects landed in the v0.86.5 audit follow-up:

* P1-16: ``schema_version`` on terminal list responses
* P1-17: pagination ceiling enforced ``limit≤1000`` across list endpoints
* P1-18: structured error envelope with ``code`` + ``correlation_id``
* P1-19: ``/v1/proxy/audit`` counts runtime_alert entries + dedupes by ``event_id``
* P1-20: gateway bearer token now gates ``/v1/firewall/check`` + ``/metrics``
* P1-22: ``iac`` + ``check`` JSON outputs carry the schema envelope
* P1-24: CLI compliance-narrative accepts the full framework slug set,
  including the ``mitre-attack`` alias to ``attack``.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from starlette.testclient import TestClient

from agent_bom.api import stores as _stores
from agent_bom.api.routes import proxy as proxy_routes
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store


@pytest.fixture
def fresh_client():
    """Return a TestClient with a clean in-memory job store + sources store."""
    from agent_bom.api.exception_store import InMemoryExceptionStore
    from agent_bom.api.source_store import InMemorySourceStore
    from agent_bom.api.stores import set_exception_store, set_source_store

    store = InMemoryJobStore()
    set_job_store(store)
    set_source_store(InMemorySourceStore())
    set_exception_store(InMemoryExceptionStore())
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client
    _stores._store = None
    _stores._source_store = None
    _stores._exception_store = None


@pytest.fixture(autouse=True)
def reset_proxy_runtime_state():
    """Keep proxy audit regressions from leaking process-global alert state."""
    proxy_routes._reset_audit_dedupe_for_tests()
    proxy_routes._proxy_alerts.clear()
    proxy_routes._proxy_metrics = None
    proxy_routes._proxy_metrics_by_tenant.clear()
    yield
    proxy_routes._reset_audit_dedupe_for_tests()
    proxy_routes._proxy_alerts.clear()
    proxy_routes._proxy_metrics = None
    proxy_routes._proxy_metrics_by_tenant.clear()


# ── P1-16: schema_version on terminal list responses ───────────────────────────


@pytest.mark.parametrize(
    "path,key",
    [
        ("/v1/findings", "schema_version"),
        ("/v1/jobs", "schema_version"),
        ("/v1/sources", "schema_version"),
        ("/v1/audit", "schema_version"),
        ("/v1/auth/keys", "schema_version"),
    ],
)
def test_p1_16_schema_version_on_list_responses(fresh_client, path, key):
    resp = fresh_client.get(path)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body.get(key) == "v1", f"{path} response missing schema_version=v1: {body}"


# ── P1-17: pagination cap ≤1000 ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        "/v1/findings",
        "/v1/jobs",
        "/v1/sources",
        "/v1/exceptions",
        "/v1/inventory",
    ],
)
def test_p1_17_pagination_rejects_oversize_limit(fresh_client, path):
    """`?limit=10000` is now a 422, not silently honored."""
    resp = fresh_client.get(f"{path}?limit=10000")
    assert resp.status_code == 422, f"{path} did not reject limit=10000 (got {resp.status_code})"


def test_p1_17_pagination_accepts_max_cap(fresh_client):
    resp = fresh_client.get("/v1/findings?limit=1000")
    assert resp.status_code == 200
    assert resp.json()["limit"] == 1000


# ── P1-18: structured error envelope ───────────────────────────────────────────


def test_p1_18_error_envelope_for_not_found(fresh_client):
    resp = fresh_client.get("/v1/jobs/nonexistent-job-id")
    assert resp.status_code in (404, 405), resp.status_code
    body = resp.json()
    assert "error" in body, body
    err = body["error"]
    assert err["code"] in {"NOT_FOUND", "METHOD_NOT_ALLOWED"}
    assert err["correlation_id"]
    assert resp.headers.get("X-Request-ID") == err["correlation_id"]
    # Backward-compat: the original FastAPI ``detail`` is still surfaced.
    assert "detail" in body


def test_p1_18_error_envelope_for_validation(fresh_client):
    # limit=0 violates ge=1; FastAPI now returns the structured envelope.
    resp = fresh_client.get("/v1/findings?limit=0")
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["correlation_id"]


def test_p1_18_correlation_id_round_trips(fresh_client):
    requested = "test-corr-id-1234"
    resp = fresh_client.get("/v1/jobs/missing-job", headers={"x-request-id": requested})
    assert resp.status_code == 404
    body = resp.json()
    assert body["error"]["correlation_id"] == requested


# ── P1-19: proxy audit counts + dedupe ─────────────────────────────────────────


def test_p1_19_proxy_audit_dedupes_by_event_id(fresh_client):
    proxy_routes._reset_audit_dedupe_for_tests()
    payload = {
        "source_id": "proxy-a",
        "session_id": "session-1",
        "alerts": [
            {
                "event_id": "evt-001",
                "severity": "critical",
                "detector": "credential_leak",
                "message": "secret detected",
            }
        ],
        "summary": None,
    }
    first = fresh_client.post("/v1/proxy/audit", json=payload)
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["alert_count"] == 1
    assert first_body["accepted_alert_count"] == 1
    assert first_body["duplicate_alert_count"] == 0

    second = fresh_client.post("/v1/proxy/audit", json=payload)
    assert second.status_code == 200
    second_body = second.json()
    # Replayed alert is rejected; downstream tallies must not double-count.
    assert second_body["accepted_alert_count"] == 0
    assert second_body["duplicate_alert_count"] == 1
    assert "evt-001" in second_body["duplicate_event_ids"]


def test_p1_19_proxy_audit_counts_summary_runtime_alerts(fresh_client):
    proxy_routes._reset_audit_dedupe_for_tests()
    payload = {
        "source_id": "proxy-b",
        "session_id": "session-2",
        "alerts": [],
        "summary": {
            "runtime_alerts": 3,
            "runtime_alerts_by_detector": {"credential_leak": 3},
        },
    }
    resp = fresh_client.post("/v1/proxy/audit", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["alert_count"] == 3, body
    assert body["has_summary"] is True


# ── P1-22: schema envelope on iac + check JSON ─────────────────────────────────


def test_p1_22_check_json_has_schema_envelope(tmp_path):
    from agent_bom.cli._check import _check_result_payload

    payload = _check_result_payload(
        name="left-pad",
        version="1.3.0",
        ecosystems=["npm"],
        verdict="clean",
        message="no known vulns",
        exit_code=0,
        vulnerabilities=[],
        warnings=[],
    )
    assert payload["schema_version"] == "1.0"
    assert payload["document_type"] == "PACKAGE-CHECK"
    assert payload["spec_version"] == "1.0"


def test_p1_22_iac_json_has_schema_envelope(tmp_path, monkeypatch):
    """`agent-bom iac` JSON output carries the envelope so consumers can pin shape."""
    from agent_bom.cli._focused_commands import iac_cmd

    # Drop a single dockerfile finding-worthy file. The exact rule firing isn't
    # important — we just need a JSON body to inspect.
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:latest\nUSER root\n", encoding="utf-8")
    out = tmp_path / "iac.json"

    runner = CliRunner()
    result = runner.invoke(iac_cmd, [str(tmp_path), "-f", "json", "-o", str(out)])
    # `iac` exits 1 when high-severity findings are present — that's still a
    # successful run for the envelope check. Anything other than 0/1 is fatal.
    assert result.exit_code in (0, 1), result.output

    data = json.loads(out.read_text())
    assert data["schema_version"] == "1.0"
    assert data["document_type"] == "IAC-FINDINGS"
    assert data["spec_version"] == "1.0"
    assert "findings" in data
    assert "total" in data


# ── P1-24: compliance-narrative framework alias ────────────────────────────────


def test_p1_24_normalize_alias_maps_mitre_attack_to_attack():
    from agent_bom.output.compliance_narrative import (
        ALL_FRAMEWORK_SLUGS,
        normalize_framework_slug,
    )

    assert "attack" in ALL_FRAMEWORK_SLUGS
    assert normalize_framework_slug("mitre-attack") == "attack"
    assert normalize_framework_slug("MITRE-ATTACK") == "attack"
    assert normalize_framework_slug("attack") == "attack"


def test_p1_24_cli_compliance_narrative_accepts_mitre_attack(tmp_path):
    from agent_bom.cli._history import compliance_narrative_cmd

    scan_file = tmp_path / "scan.json"
    scan_file.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "agents": [],
                "blast_radii": [],
                "scan_metadata": {"scan_id": "x", "version": "v1"},
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        compliance_narrative_cmd,
        [str(scan_file), "--framework", "mitre-attack", "-f", "json"],
    )
    # The framework alias must be accepted; the narrative generator may still
    # emit an empty payload when no findings exist, but it must not 2-out from
    # click.Choice rejecting the alias.
    assert result.exit_code == 0, result.output
