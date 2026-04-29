from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from agent_bom.cli._common import _build_agents_from_inventory
from agent_bom.inventory import load_inventory
from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

ADAPTER_PATH = Path(__file__).resolve().parents[1] / "examples" / "operator_pull" / "aws_inventory_adapter.py"


def _load_adapter():
    spec = importlib.util.spec_from_file_location("aws_inventory_adapter", ADAPTER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_aws_operator_pull_adapter_emits_valid_sanitized_inventory(tmp_path: Path) -> None:
    adapter = _load_adapter()
    agent = Agent(
        name="bedrock-agent",
        agent_type=AgentType.CUSTOM,
        config_path="arn:aws:bedrock:us-east-1:123456789012:agent/AGENT123",
        source="aws-bedrock",
        metadata={
            "cloud_origin": {
                "provider": "aws",
                "service": "bedrock",
                "resource_type": "agent",
                "resource_id": "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT123",
                "scope": {"account_id": "123456789012", "api_token": "should-not-survive"},
            },
            "cloud_principal": {"principal_arn": "arn:aws:sts::123456789012:assumed-role/ReadOnly/session"},
        },
        mcp_servers=[
            MCPServer(
                name="bedrock-runtime",
                command="npx",
                args=["-y", "@modelcontextprotocol/server-fetch@1.0.0", "--api-key", "secret-value"],
                env={"AWS_SESSION_TOKEN": "raw-token"},
                transport=TransportType.STDIO,
                packages=[
                    Package(
                        name="@modelcontextprotocol/server-fetch",
                        version="1.0.0",
                        ecosystem="npm",
                        purl="pkg:npm/%40modelcontextprotocol/server-fetch@1.0.0",
                    )
                ],
            )
        ],
    )

    payload = adapter.build_inventory(
        [agent],
        generated_at="2026-04-29T12:00:00+00:00",
        permissions_used=["sts:GetCallerIdentity", "bedrock:ListAgents"],
        source="aws-skill-invoked",
        discovery_method="skill_invoked_pull",
    )
    output_path = tmp_path / "aws-inventory.json"
    output_path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = load_inventory(str(output_path))
    rebuilt_agents = _build_agents_from_inventory(loaded, str(output_path))

    assert loaded["schema_version"] == "1"
    assert loaded["source"] == "aws-skill-invoked"
    assert loaded["discovery_provenance"]["source_type"] == "skill_invoked_pull"
    assert loaded["discovery_provenance"]["observed_via"] == ["skill_invoked_pull", "aws_sdk"]
    assert loaded["agents"][0]["metadata"]["cloud_origin"]["scope"]["api_token"] == "***REDACTED***"
    assert loaded["agents"][0]["discovery_provenance"]["source_type"] == "skill_invoked_pull"
    assert loaded["agents"][0]["discovery_provenance"]["service"] == "bedrock"
    assert loaded["agents"][0]["metadata"]["permissions_used"] == ["bedrock:ListAgents", "sts:GetCallerIdentity"]
    assert loaded["agents"][0]["mcp_servers"][0]["env"]["AWS_SESSION_TOKEN"] == "***REDACTED***"
    assert loaded["agents"][0]["mcp_servers"][0]["packages"][0]["discovery_provenance"]["source_type"] == "skill_invoked_pull"
    assert "secret-value" not in json.dumps(loaded)
    assert rebuilt_agents[0].metadata["cloud_origin"]["provider"] == "aws"
    assert rebuilt_agents[0].metadata["permissions_used"] == ["bedrock:ListAgents", "sts:GetCallerIdentity"]


def test_aws_operator_pull_adapter_cli_writes_inventory(monkeypatch, tmp_path: Path) -> None:
    adapter = _load_adapter()
    monkeypatch.setattr(
        adapter,
        "discover",
        lambda **_kwargs: (
            [Agent(name="aws-empty", agent_type=AgentType.CUSTOM, config_path="aws://empty", source="aws", mcp_servers=[])],
            ["Access denied for token=secret"],
        ),
    )
    output_path = tmp_path / "inventory.json"

    assert adapter.main(["--region", "us-east-1", "--no-include-ecs", "--output", str(output_path)]) == 0

    loaded = load_inventory(str(output_path))
    assert loaded["agents"][0]["name"] == "aws-empty"
    assert loaded["discovery_provenance"]["source_type"] == "operator_pushed_inventory"


def test_aws_operator_pull_adapter_cli_marks_skill_invoked_inventory(monkeypatch, tmp_path: Path) -> None:
    adapter = _load_adapter()
    monkeypatch.setattr(
        adapter,
        "discover",
        lambda **_kwargs: (
            [Agent(name="aws-skill", agent_type=AgentType.CUSTOM, config_path="aws://skill", source="aws", mcp_servers=[])],
            [],
        ),
    )
    output_path = tmp_path / "inventory.json"

    assert (
        adapter.main(
            [
                "--region",
                "us-east-1",
                "--no-include-ecs",
                "--source",
                "aws-skill-invoked",
                "--discovery-method",
                "skill_invoked_pull",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    loaded = load_inventory(str(output_path))
    assert loaded["source"] == "aws-skill-invoked"
    assert loaded["agents"][0]["discovery_provenance"]["source_type"] == "skill_invoked_pull"


def test_aws_operator_pull_adapter_keeps_container_purl_schema_valid() -> None:
    adapter = _load_adapter()
    package = Package(
        name="123456789012.dkr.ecr.us-east-1.amazonaws.com/model-api",
        version="2026-04",
        ecosystem="container-image",
        purl="pkg:docker/123456789012.dkr.ecr.us-east-1.amazonaws.com/model-api@2026-04",
    )

    payload = adapter._package_to_inventory(package)

    assert payload == {
        "name": "123456789012.dkr.ecr.us-east-1.amazonaws.com/model-api",
        "version": "2026-04",
        "purl": "pkg:docker/123456789012.dkr.ecr.us-east-1.amazonaws.com/model-api@2026-04",
    }


def test_aws_permissions_used_reads_provider_contract_shape() -> None:
    adapter = _load_adapter()

    permissions = adapter._aws_permissions_used()

    assert "sts:GetCallerIdentity" in permissions
    assert "bedrock:ListAgents" in permissions
