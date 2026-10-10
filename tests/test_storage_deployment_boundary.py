"""Storage deployment policy must not depend on HTTP middleware."""

from pathlib import Path

import pytest

from scripts.check_import_graph import build_graph


def test_storage_posture_does_not_import_http_middleware():
    edges = build_graph(Path(__file__).resolve().parents[1])
    for module in ("agent_bom.api.shared_auth_state", "agent_bom.api.report_artifact_store"):
        assert "agent_bom.api.middleware" not in edges[module]


@pytest.mark.parametrize(
    "replicas,required,expected", [("", "", False), ("1", "0", False), ("2", "", True), ("invalid", "", False), ("1", "true", True)]
)
def test_cluster_requirement_preserves_configuration(replicas, required, expected, monkeypatch):
    from agent_bom.api.storage.deployment import clustered_control_plane_required

    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", replicas)
    monkeypatch.setenv("AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT", required)
    assert clustered_control_plane_required() is expected
