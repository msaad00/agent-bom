from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.server import app
from agent_bom.runtime_blueprints import (
    classify_runtime_tool,
    evaluate_runtime_blueprint_drift,
    runtime_role_blueprint,
    runtime_role_blueprints,
)


def test_runtime_role_blueprints_are_canonical_profiles() -> None:
    blueprints = runtime_role_blueprints()
    ids = {blueprint["blueprint_id"] for blueprint in blueprints}
    assert ids == {"developer", "security_analyst", "mlops", "finance", "admin"}
    for blueprint in blueprints:
        assert blueprint["allowed_tool_categories"]
        assert blueprint["restricted_tool_categories"]
        assert blueprint["approval_required_for"]
        assert blueprint["default_decision"] in {"allow", "warn", "block"}
        assert blueprint["retention_mode"] in {"metadata_only", "redacted"}
        assert "decision" in blueprint["evidence_required"]


def test_runtime_role_blueprint_lookup_normalizes_ids() -> None:
    assert runtime_role_blueprint("security-analyst")["blueprint_id"] == "security_analyst"  # type: ignore[index]
    assert runtime_role_blueprint("missing") is None


def test_runtime_blueprints_api_lists_and_gets_profiles() -> None:
    client = TestClient(app)

    listing = client.get("/v1/runtime/blueprints").json()
    assert listing["schema_version"] == "runtime.blueprints.v1"
    assert listing["tenant_id"] == "default"
    assert [blueprint["blueprint_id"] for blueprint in listing["blueprints"]] == [
        "developer",
        "security_analyst",
        "mlops",
        "finance",
        "admin",
    ]

    finance = client.get("/v1/runtime/blueprints/finance").json()
    assert finance["blueprint"]["default_decision"] == "block"
    assert "payment_write" in finance["blueprint"]["approval_required_for"]

    missing = client.get("/v1/runtime/blueprints/not-real")
    assert missing.status_code == 404


def test_runtime_blueprint_drift_evaluates_live_index(monkeypatch) -> None:
    import agent_bom.api.routes.proxy as proxy_mod
    from agent_bom.api.server import push_proxy_metrics

    proxy_mod._proxy_alerts.clear()
    proxy_mod._proxy_metrics = None
    proxy_mod._proxy_metrics_by_tenant.clear()
    monkeypatch.delenv("AGENT_BOM_LOG", raising=False)

    push_proxy_metrics(
        {
            "type": "proxy_summary",
            "tenant_id": "default",
            "total_tool_calls": 3,
            "total_blocked": 0,
            "calls_by_tool": {
                "repo.read_file": 2,
                "prod.deploy_service": 1,
            },
        }
    )

    data = TestClient(app).get("/v1/runtime/blueprints/developer/drift").json()
    assert data["schema_version"] == "runtime.blueprint_drift.v1"
    assert data["status"] == "drift_detected"
    assert data["observed"]["categories"]["repo_read"] == 2
    assert data["observed"]["categories"]["production_write"] == 1
    assert data["violations"][0]["category"] == "production_write"
    assert data["retention"] == "metadata_only"

    proxy_mod._proxy_alerts.clear()
    proxy_mod._proxy_metrics = None
    proxy_mod._proxy_metrics_by_tenant.clear()


def test_runtime_blueprint_drift_empty_runtime_is_no_activity() -> None:
    payload = evaluate_runtime_blueprint_drift(
        "security_analyst",
        {"schema_version": "runtime.production_index.v1", "status": "no_runtime_activity", "traffic": {"calls_by_tool": {}}},
    )
    assert payload["status"] == "no_runtime_activity"
    assert payload["drift_score"] == 0.0
    assert classify_runtime_tool("intel_lookup") == "threat_intel"
