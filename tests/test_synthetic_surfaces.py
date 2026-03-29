from __future__ import annotations

from datetime import datetime

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package, ServerSurface, TransportType
from agent_bom.output.json_fmt import to_json
from agent_bom.parsers import extract_packages


def test_extract_packages_skips_registry_fallback_for_container_image_surface(monkeypatch):
    server = MCPServer(
        name="ghcr.io/example/app:1.2.3",
        command="docker",
        args=["run", "ghcr.io/example/app:1.2.3"],
        transport=TransportType.STDIO,
        surface=ServerSurface.CONTAINER_IMAGE,
    )

    monkeypatch.setattr(
        "agent_bom.parsers.lookup_mcp_registry",
        lambda _server: [Package(name="@pierrebrunelle/mcp-server-youtube", version="latest", ecosystem="npm")],
    )

    assert extract_packages(server) == []


def test_image_surface_does_not_claim_mcp_context():
    image_server = MCPServer(
        name="agentbom/agent-bom:latest",
        command="docker",
        args=["run", "agentbom/agent-bom:latest"],
        transport=TransportType.STDIO,
        surface=ServerSurface.CONTAINER_IMAGE,
        packages=[Package(name="openssl", version="3.0.16", ecosystem="deb")],
    )
    report = AIBOMReport(
        agents=[
            Agent(
                name="image:agentbom/agent-bom:latest",
                agent_type=AgentType.CUSTOM,
                config_path="docker://agentbom/agent-bom:latest",
                source="image",
                mcp_servers=[image_server],
            )
        ],
        generated_at=datetime(2026, 3, 25, 12, 0, 0),
    )

    assert report.has_mcp_context is False


def test_other_surface_does_not_claim_mcp_context():
    project_server = MCPServer(
        name="project:repo",
        command="project",
        args=["/workspace"],
        transport=TransportType.STDIO,
        surface=ServerSurface.OTHER,
        packages=[Package(name="requests", version="2.33.0", ecosystem="pypi")],
    )
    report = AIBOMReport(
        agents=[
            Agent(
                name="project:repo",
                agent_type=AgentType.CUSTOM,
                config_path="/workspace",
                source="project",
                mcp_servers=[project_server],
            )
        ],
        generated_at=datetime(2026, 3, 25, 12, 0, 0),
    )

    assert report.has_mcp_context is False


def test_json_inventory_snapshot_preserves_server_surface():
    image_server = MCPServer(
        name="agentbom/agent-bom:latest",
        command="docker",
        args=["run", "agentbom/agent-bom:latest"],
        transport=TransportType.STDIO,
        surface=ServerSurface.CONTAINER_IMAGE,
        packages=[Package(name="openssl", version="3.0.16", ecosystem="deb")],
    )
    report = AIBOMReport(
        agents=[
            Agent(
                name="image:agentbom/agent-bom:latest",
                agent_type=AgentType.CUSTOM,
                config_path="docker://agentbom/agent-bom:latest",
                source="image",
                mcp_servers=[image_server],
            )
        ],
        generated_at=datetime(2026, 3, 25, 12, 0, 0),
    )

    payload = to_json(report)

    assert payload["summary"]["total_agents"] == 1
    assert payload["agents"][0]["mcp_servers"][0]["surface"] == "container-image"
    assert payload["inventory_snapshot"]["servers"][0]["surface"] == "container-image"
