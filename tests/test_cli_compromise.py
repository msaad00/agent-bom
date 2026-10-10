"""Headless assessment surfaces require explicit assumptions and preserve receipts."""

import json

from click.testing import CliRunner

from agent_bom.cli import main
from tests.test_cli_graph_paths import FakeGraphClient, _install


def test_cli_compromise_requires_explicit_control_assumption():
    result = CliRunner().invoke(main, ["graph-paths", "compromise", "--scan-id", "scan-one", "--node", "principal:one"])
    assert result.exit_code != 0
    assert "--assume-control" in result.output


def test_cli_compromise_json_preserves_snapshot_receipt(monkeypatch):
    fake = _install(monkeypatch)

    def assess(self, **kwargs):
        fake.calls.append(("compromise", kwargs))
        return {"scan_id": "scan-one", "snapshot_generation": "revision-one", "actions": [], "collection_coverage": "unknown"}

    monkeypatch.setattr(FakeGraphClient, "compromise_assessment", assess, raising=False)
    result = CliRunner().invoke(
        main, ["graph-paths", "compromise", "--scan-id", "scan-one", "--node", "principal:one", "--assume-control", "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["snapshot_generation"] == "revision-one"
    assert fake.calls[0][1]["assume_control"] is True
    assert fake.calls[0][1]["root_node_id"] == "principal:one"


def test_cli_compromise_never_labels_empty_results_safe(monkeypatch):
    _install(monkeypatch)
    monkeypatch.setattr(
        FakeGraphClient,
        "compromise_assessment",
        lambda self, **kwargs: {"scan_id": "s", "snapshot_generation": "r", "actions": [], "relationships_examined": 0, "truncated": False},
        raising=False,
    )
    result = CliRunner().invoke(main, ["graph-paths", "compromise", "--scan-id", "s", "--node", "principal:one", "--assume-control"])
    assert result.exit_code == 0, result.output
    assert "coverage unknown" in result.output.lower()
    assert "execution not established" in result.output.lower()


def test_python_client_sends_the_strict_assessment_body_with_auth_headers():
    import httpx

    from agent_bom.api.graph_compromise import GraphCompromiseRequest
    from agent_bom.client import AgentBomClient

    def handler(request):
        assert request.method == "POST"
        assert request.url.path == "/v1/graph/compromise"
        assert request.headers["authorization"] == "Bearer fixture-token"
        body = GraphCompromiseRequest.model_validate(json.loads(request.content))
        assert body.root_node_id == "principal:with spaces/+&?"
        assert body.snapshot_generation == "revision-one"
        assert body.assume_control is True
        return httpx.Response(200, json={"snapshot_generation": body.snapshot_generation, "actions": []})

    with AgentBomClient(
        base_url="https://example.test", bearer_token="fixture-token", tenant_id="tenant-a", transport=httpx.MockTransport(handler)
    ) as client:
        result = client.compromise_assessment(
            root_node_id="principal:with spaces/+&?", scan_id="scan-one", snapshot_generation="revision-one", assume_control=True
        )
    assert result["snapshot_generation"] == "revision-one"
