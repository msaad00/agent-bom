from __future__ import annotations

from click.testing import CliRunner
from starlette.testclient import TestClient

from agent_bom.agent_manifest import build_control_plane_agent_manifest, build_local_agent_manifest
from agent_bom.api import stores as api_stores
from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
from agent_bom.api.mcp_observation_store import InMemoryMCPObservationStore, MCPObservation
from agent_bom.api.server import app
from agent_bom.cli import main
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, TransportType


def _agent() -> Agent:
    return Agent(
        name="local-coder",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude.json",
        mcp_servers=[
            MCPServer(
                name="filesystem",
                command="npx",
                args=["-y", "@modelcontextprotocol/server-filesystem", "--token", "sk-hidden"],
                env={"API_KEY": "sk-secret-value", "SAFE_FLAG": "1"},
                transport=TransportType.STDIO,
                tools=[MCPTool(name="read_file", description="Read files")],
            )
        ],
    )


def test_local_agent_manifest_redacts_credential_values() -> None:
    payload = build_local_agent_manifest([_agent()])
    rendered = repr(payload)

    assert payload["schema_version"] == "agent-bom.manifest/v1"
    assert payload["summary"]["agents"] == 1
    assert payload["summary"]["mcp_servers"] == 1
    assert payload["summary"]["tools"] == 1
    assert payload["graph"]["stats"]["nodes"] == 4
    assert payload["graph"]["stats"]["edges"] == 3
    assert payload["visibility"]["unowned_agents"] == 1
    assert payload["blueprint_drift"]["status"] == "aligned"
    assert payload["mcp_servers"][0]["credential_refs"] == [{"name": "API_KEY", "kind": "env"}]
    assert "sk-secret-value" not in rendered
    assert "SAFE_FLAG" not in rendered


def test_manifest_cli_emits_agent_bom_json(monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.cli._agent_manifest.discover_all", lambda project_dir=None: [_agent()])

    result = CliRunner().invoke(main, ["manifest", "--tenant-id", "tenant-a"])

    assert result.exit_code == 0, result.output
    assert '"schema_version": "agent-bom.manifest/v1"' in result.output
    assert '"tenant_id": "tenant-a"' in result.output
    assert "sk-secret-value" not in result.output


def test_agent_bom_manifest_api_is_tenant_scoped_and_redacted() -> None:
    fleet = InMemoryFleetStore()
    observations = InMemoryMCPObservationStore()
    fleet.put(
        FleetAgent(
            tenant_id="default",
            agent_id="agent-1",
            name="prod-agent",
            agent_type="claude-desktop",
            lifecycle_state=FleetLifecycleState.APPROVED,
            owner="platform-team",
            environment="prod",
            server_count=1,
            credential_count=1,
        )
    )
    observations.put(
        MCPObservation(
            tenant_id="default",
            observation_id="obs-1",
            server_stable_id="srv-1",
            server_name="filesystem",
            agent_name="prod-agent",
            transport="stdio",
            command="npx",
            args=["-y", "server", "--token", "sk-hidden"],
            credential_env_vars=["API_KEY"],
            fleet_present=True,
            gateway_registered=True,
            runtime_observed=True,
        )
    )

    previous_fleet = api_stores._fleet_store
    previous_observations = api_stores._mcp_observation_store
    try:
        api_stores.set_fleet_store(fleet)
        api_stores.set_mcp_observation_store(observations)
        response = TestClient(app).get("/v1/agent-bom/manifest")
    finally:
        api_stores.set_fleet_store(previous_fleet)
        api_stores.set_mcp_observation_store(previous_observations)

    assert response.status_code == 200
    payload = response.json()
    assert payload["tenant_id"] == "default"
    assert payload["summary"]["agents"] == 1
    assert payload["summary"]["mcp_servers"] == 1
    assert payload["summary"]["runtime_observed_servers"] == 1
    assert payload["visibility"]["owners"] == 1
    assert payload["visibility"]["risky_credential_refs"] == 1
    assert payload["blueprint_drift"]["status"] == "aligned"
    assert payload["graph"]["stats"]["nodes"] == 5
    assert payload["graph"]["stats"]["edges"] == 4
    assert "owns" in payload["graph"]["stats"]["relationships"]
    assert "part_of" in payload["graph"]["stats"]["relationships"]
    assert {edge["relationship"] for edge in payload["graph"]["edges"]} >= {"owns", "part_of", "uses", "exposes_cred"}
    assert payload["mcp_servers"][0]["credential_refs"] == [{"name": "API_KEY", "kind": "env"}]
    assert "sk-hidden" not in response.text


def test_agent_bom_manifest_reports_observation_only_blueprint_drift() -> None:
    payload = build_control_plane_agent_manifest(
        [],
        [
            MCPObservation(
                tenant_id="default",
                observation_id="obs-shadow",
                server_stable_id="srv-shadow",
                server_name="shadow-server",
                agent_name="unknown-agent",
                transport="stdio",
                credential_env_vars=["ROOT_TOKEN"],
                runtime_observed=True,
                gateway_registered=False,
                fleet_present=False,
            )
        ],
        tenant_id="default",
    )

    assert payload["visibility"]["shadow_runtime_servers"] == 1
    assert payload["visibility"]["untracked_runtime_servers"] == 1
    assert payload["visibility"]["risky_credential_refs"] == 1
    assert payload["blueprint_drift"]["status"] == "needs_review"
    assert {signal["kind"] for signal in payload["blueprint_drift"]["signals"]} == {
        "unregistered_runtime_server",
        "untracked_runtime_server",
    }
