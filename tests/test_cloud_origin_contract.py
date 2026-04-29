"""Contract tests for normalized cloud-origin provider metadata."""

from __future__ import annotations

from agent_bom.cloud import _PROVIDERS
from agent_bom.cloud.normalization import build_cloud_origin
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType
from agent_bom.models import Agent, AgentType, AIBOMReport
from agent_bom.output.json_fmt import to_json

LOCAL_ONLY_PROVIDERS = {
    "ollama": "Discovers a local Ollama daemon; no external cloud/SaaS resource identity exists.",
}

MOCKED_CLOUD_ORIGIN_PROVIDERS = {
    "aws",
    "azure",
    "coreweave",
    "databricks",
    "gcp",
    "huggingface",
    "mlflow",
    "nebius",
    "openai",
    "snowflake",
    "wandb",
}


def test_registered_provider_cloud_origin_contract_is_documented() -> None:
    """Every registered provider has a representative cloud_origin test or is local-only."""
    assert MOCKED_CLOUD_ORIGIN_PROVIDERS | set(LOCAL_ONLY_PROVIDERS) == set(_PROVIDERS)
    assert not (MOCKED_CLOUD_ORIGIN_PROVIDERS & set(LOCAL_ONLY_PROVIDERS))
    assert all(reason for reason in LOCAL_ONLY_PROVIDERS.values())


def test_cloud_origin_raw_identity_sanitizes_secret_shaped_values() -> None:
    origin = build_cloud_origin(
        provider="openai",
        service="assistants",
        resource_type="assistant",
        resource_id="asst_123",
        resource_name="assistant",
        raw_identity={
            "id": "asst_123",
            "api_key": "sk-secret-value",
            "endpoint_url": "https://token:secret@example.test/path?apikey=secret",
            "empty": "",
            "nested": {"not": "included"},
        },
    )

    assert origin["raw_identity"]["id"] == "asst_123"
    assert origin["raw_identity"]["api_key"] == "***REDACTED***"
    assert origin["raw_identity"]["endpoint_url"] == "https://example.test/path"
    assert "empty" not in origin["raw_identity"]
    assert "nested" not in origin["raw_identity"]


def test_cloud_origin_survives_json_and_graph_workflow() -> None:
    """Cloud context stays available beyond provider discovery."""
    agent = Agent(
        name="aws-bedrock:agent-123",
        agent_type=AgentType.CUSTOM,
        config_path="arn:aws:bedrock:us-east-1:123456789012:agent/agent-123",
        source="aws-bedrock",
        metadata={
            "cloud_origin": build_cloud_origin(
                provider="aws",
                service="bedrock",
                resource_type="agent",
                resource_id="arn:aws:bedrock:us-east-1:123456789012:agent/agent-123",
                resource_name="support-agent",
                location="us-east-1",
                account_id="123456789012",
                raw_identity={"agent_id": "agent-123", "agent_name": "support-agent"},
            )
        },
    )
    report_json = to_json(AIBOMReport(agents=[agent]))

    json_origin = report_json["agents"][0]["metadata"]["cloud_origin"]
    assert json_origin["provider"] == "aws"
    assert json_origin["service"] == "bedrock"
    assert json_origin["resource_type"] == "agent"
    assert json_origin["scope"]["account_id"] == "123456789012"

    graph = build_unified_graph_from_report(report_json)
    resource_nodes = [node for node in graph.nodes_by_type(EntityType.CLOUD_RESOURCE) if node.attributes.get("cloud_origin") == json_origin]
    assert len(resource_nodes) == 1
    assert resource_nodes[0].dimensions.cloud_provider == "aws"
    assert resource_nodes[0].dimensions.surface == "bedrock"
    assert resource_nodes[0].attributes["cloud_service"] == "bedrock"
