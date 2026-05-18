from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.server import app
from agent_bom.runtime_blueprints import runtime_role_blueprint, runtime_role_blueprints


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
