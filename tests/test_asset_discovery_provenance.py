from __future__ import annotations

import json
from datetime import datetime, timezone

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _run_scan_sync
from agent_bom.api.routes.discovery import _serialize_agent
from agent_bom.asset_provenance import sanitize_discovery_provenance
from agent_bom.finding import blast_radius_to_finding
from agent_bom.graph import EntityType
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.inventory import load_inventory
from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output.json_fmt import to_json


def test_discovery_provenance_contract_is_sanitized() -> None:
    provenance = sanitize_discovery_provenance(
        {
            "source_type": "skill_invoked_pull",
            "observed_via": ["skill:api_key=secret", "skill_invoked_pull", "skill_invoked_pull"],
            "source": "https://user:pass@example.test/path",
            "collector": "skill_scanner\nwith-control",
            "ignored": "not exported",
        }
    )

    assert provenance == {
        "source_type": "skill_invoked_pull",
        "observed_via": ["<redacted>", "skill_invoked_pull"],
        "source": "<redacted>",
        "collector": "skill_scanner with-control",
    }


def test_json_surfaces_infer_and_preserve_asset_discovery_provenance() -> None:
    registry_pkg = Package(
        name="mcp-server",
        version="unknown",
        ecosystem="npm",
        resolved_from_registry=True,
        version_source="registry_fallback",
    )
    cloud_agent = Agent(
        name="bedrock-agent",
        agent_type=AgentType.CUSTOM,
        config_path="aws://bedrock/agent-1",
        source="aws-bedrock",
        metadata={
            "cloud_origin": {
                "provider": "aws",
                "service": "bedrock",
                "resource_type": "agent",
                "resource_id": "arn:aws:bedrock:us-east-1:123:agent/agent-1",
                "resource_name": "agent-1",
                "location": "us-east-1",
            }
        },
        mcp_servers=[MCPServer(name="bedrock-runtime", packages=[registry_pkg])],
    )
    inventory_agent = _inventory_agent()
    skill_agent = Agent(
        name="skill-files",
        agent_type=AgentType.CUSTOM,
        config_path="SKILL.md",
        source="skill-files",
        mcp_servers=[
            MCPServer(
                name="skill-packages",
                packages=[
                    Package(
                        name="langchain",
                        version="0.1.0",
                        ecosystem="pypi",
                        discovery_provenance={"source": "skill:token=secret"},
                    )
                ],
            )
        ],
    )
    local_agent = Agent(
        name="claude",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude.json",
        mcp_servers=[MCPServer(name="local-server", packages=[Package(name="express", version="4.18.2", ecosystem="npm")])],
    )
    report = AIBOMReport(
        agents=[cloud_agent, inventory_agent, skill_agent, local_agent],
        generated_at=datetime(2026, 4, 29, tzinfo=timezone.utc),
    )

    payload = to_json(report)
    agents = {agent["name"]: agent for agent in payload["agents"]}
    assert agents["bedrock-agent"]["discovery_provenance"]["source_type"] == "direct_cloud_pull"
    assert agents["bedrock-agent"]["discovery_provenance"]["provider"] == "aws"
    assert agents["inventory-agent"]["discovery_provenance"]["source_type"] == "operator_pushed_inventory"
    assert agents["skill-files"]["discovery_provenance"]["source_type"] == "skill_invoked_pull"
    assert agents["claude"]["discovery_provenance"]["source_type"] == "local_discovery"

    registry_provenance = agents["bedrock-agent"]["mcp_servers"][0]["packages"][0]["discovery_provenance"]
    assert registry_provenance["source_type"] == "registry_fallback"
    assert registry_provenance["resolved_from_registry"] is True
    assert registry_provenance["version_source"] == "registry_fallback"

    skill_provenance = agents["skill-files"]["mcp_servers"][0]["packages"][0]["discovery_provenance"]
    assert skill_provenance["source_type"] == "skill_invoked_pull"
    assert skill_provenance["source"] == "<redacted>"

    snapshot_pkg = next(pkg for pkg in payload["inventory_snapshot"]["packages"] if pkg["name"] == "mcp-server")
    assert snapshot_pkg["discovery_provenance"]["source_type"] == "registry_fallback"


def test_api_graph_and_finding_surfaces_preserve_sanitized_provenance() -> None:
    vuln = Vulnerability(id="CVE-2026-0001", summary="test", severity=Severity.HIGH)
    pkg = Package(
        name="requests",
        version="2.0.0",
        ecosystem="pypi",
        vulnerabilities=[vuln],
        discovery_provenance={
            "source_type": "operator_pushed_inventory",
            "observed_via": ["operator_inventory"],
            "source": "inventory:password=secret",
        },
    )
    server = MCPServer(name="inventory-server", packages=[pkg])
    agent = Agent(
        name="inventory-agent",
        agent_type=AgentType.CUSTOM,
        config_path="/tmp/inventory.json",
        source="inventory",
        mcp_servers=[server],
    )

    api_payload = _serialize_agent(agent)
    api_provenance = api_payload["mcp_servers"][0]["packages"][0]["discovery_provenance"]
    assert api_provenance["source_type"] == "operator_pushed_inventory"
    assert api_provenance["source"] == "<redacted>"

    report_payload = to_json(AIBOMReport(agents=[agent], blast_radii=[_blast_radius(vuln, pkg, server, agent)]))
    graph = build_unified_graph_from_report(report_payload)
    package_node = graph.nodes_by_type(EntityType.PACKAGE)[0]
    assert package_node.attributes["discovery_provenance"]["source"] == "<redacted>"
    depends_edge = graph.edges_to(package_node.id)[0]
    assert depends_edge.evidence["discovery_provenance"]["source_type"] == "operator_pushed_inventory"

    finding = blast_radius_to_finding(_blast_radius(vuln, pkg, server, agent))
    assert finding.evidence["package_discovery_provenance"]["source"] == "<redacted>"


def test_inventory_schema_accepts_discovery_provenance(tmp_path) -> None:
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "source": "customer-cmdb",
                "discovery_provenance": {
                    "source_type": "operator_pushed_inventory",
                    "observed_via": ["operator_inventory"],
                    "collector": "cmdb-export",
                },
                "agents": [
                    {
                        "name": "inventory-agent",
                        "agent_type": "custom",
                        "discovery_provenance": {
                            "source_type": "operator_pushed_inventory",
                            "observed_via": ["operator_inventory"],
                            "provider": "aws",
                        },
                        "mcp_servers": [
                            {
                                "name": "inventory-server",
                                "discovery_provenance": {
                                    "source_type": "operator_pushed_inventory",
                                    "observed_via": ["operator_inventory"],
                                    "service": "bedrock",
                                },
                                "packages": [
                                    {
                                        "name": "fastapi",
                                        "version": "0.104.0",
                                        "ecosystem": "pypi",
                                        "discovery_provenance": {
                                            "source_type": "operator_pushed_inventory",
                                            "observed_via": ["operator_inventory"],
                                            "version_source": "manifest",
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    payload = load_inventory(str(inventory_path))

    assert payload["discovery_provenance"]["collector"] == "cmdb-export"
    pkg = payload["agents"][0]["mcp_servers"][0]["packages"][0]
    assert pkg["discovery_provenance"]["version_source"] == "manifest"


def test_api_pipeline_inventory_preserves_packages_and_provenance(monkeypatch, tmp_path) -> None:
    class _DummyStore:
        def __init__(self) -> None:
            self.jobs: list[ScanJob] = []

        def put(self, job: ScanJob) -> None:
            self.jobs.append(job)

    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "source": "customer-cmdb",
                "agents": [
                    {
                        "name": "inventory-agent",
                        "agent_type": "custom",
                        "mcp_servers": [
                            {
                                "name": "inventory-server",
                                "packages": [
                                    {
                                        "name": "fastapi",
                                        "version": "0.104.0",
                                        "ecosystem": "pypi",
                                        "discovery_provenance": {
                                            "source_type": "operator_pushed_inventory",
                                            "observed_via": ["operator_inventory"],
                                            "source": "cmdb:token=secret",
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    store = _DummyStore()
    job = ScanJob(
        job_id="inventory-provenance",
        created_at="2026-04-29T12:00:00Z",
        request=ScanRequest(inventory=str(inventory_path), enrich=False),
    )

    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: store)
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda _agents, tenant_id="default": None)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *args, **kwargs: [])
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", lambda agents, enable_enrichment=False, **kwargs: [])

    _run_scan_sync(job)

    assert job.status == JobStatus.DONE
    assert job.result is not None
    agent = job.result["agents"][0]
    assert agent["discovery_provenance"]["source_type"] == "operator_pushed_inventory"
    pkg = agent["mcp_servers"][0]["packages"][0]
    assert pkg["name"] == "fastapi"
    assert pkg["discovery_provenance"]["source"] == "<redacted>"


def _inventory_agent() -> Agent:
    from agent_bom.cli._common import _build_agents_from_inventory

    return _build_agents_from_inventory(
        {
            "source": "cmdb-inventory",
            "agents": [
                {
                    "name": "inventory-agent",
                    "agent_type": "custom",
                    "mcp_servers": [
                        {
                            "name": "inventory-server",
                            "packages": [{"name": "fastapi", "version": "0.104.0", "ecosystem": "pypi"}],
                        }
                    ],
                }
            ],
        },
        "/tmp/inventory.json",
    )[0]


def _blast_radius(vuln: Vulnerability, pkg: Package, server: MCPServer, agent: Agent) -> BlastRadius:
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
