"""Per-agent scope, evidence honesty, portability and tamper detection."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from agent_bom.evidence.agent_bom import AgentBomDocument, build_agent_bom
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package


def inventory_agent(source_id="deployment-a"):
    return Agent(
        name="support-agent",
        agent_type=AgentType.CUSTOM,
        config_path="/private/config.json",
        source_id=source_id,
        discovered_at="2026-09-26T10:00:00+00:00",
        metadata={"prompt": "private conversation", "secret": "private credential"},
        mcp_servers=[
            MCPServer(
                name="support-tools",
                command="private-path",
                env={"TOKEN": "private credential"},
                tools=[MCPTool(name="lookup", description="Lookup a record")],
                packages=[Package(name="sdk", version="1.2.3", ecosystem="pypi")],
            )
        ],
    )


def test_profile_contains_only_selected_agent_and_safe_composition():
    agent = inventory_agent()
    doc = build_agent_bom(agent, tenant_id="team-a")
    assert doc.content.subject.agent_id == agent.stable_id
    assert {item.kind for item in doc.content.components} == {"mcp_server", "tool", "package"}
    assert {item.relationship for item in doc.content.relationships} == {"configured_with", "provides_tool", "contains_package"}
    rendered = doc.model_dump_json()
    for private in ("private credential", "private conversation", "private-path", "/private/config.json"):
        assert private not in rendered
    assert AgentBomDocument.model_validate_json(rendered) == doc


def test_snapshot_stable_across_export_time_and_input_order_but_changes_with_evidence():
    agent = inventory_agent()
    agent.mcp_servers[0].packages.append(Package(name="other", version="2", ecosystem="npm"))
    before = build_agent_bom(agent, generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    agent.mcp_servers[0].packages.reverse()
    after = build_agent_bom(agent, generated_at=datetime(2026, 2, 1, tzinfo=timezone.utc))
    assert before.generated_at != after.generated_at
    assert before.snapshot_id == after.snapshot_id
    agent.mcp_servers[0].packages[0].version = "3"
    assert build_agent_bom(agent).snapshot_id != before.snapshot_id


def test_same_name_deployments_and_tenants_are_distinct():
    a, b = inventory_agent("deployment-a"), inventory_agent("deployment-b")
    assert build_agent_bom(a).content.subject.agent_id != build_agent_bom(b).content.subject.agent_id
    assert build_agent_bom(a, tenant_id="a").snapshot_id != build_agent_bom(a, tenant_id="b").snapshot_id


def test_unknown_is_not_clean_or_verified():
    doc = build_agent_bom(inventory_agent())
    assert doc.content.subject.identity_status == "observed"
    coverage = {item.area: item.status for item in doc.content.coverage}
    assert coverage["composition"] == "partial"
    for area in ("identity", "authority", "runtime", "vulnerabilities", "controls", "cost", "models", "data"):
        assert coverage[area] == "not_assessed"
    assert all(edge.basis == "declared" for edge in doc.content.relationships)


def test_tampered_content_rejected():
    payload = build_agent_bom(inventory_agent()).model_dump(mode="json")
    payload["content"]["subject"]["name"] = "other"
    with pytest.raises(ValidationError, match="digest mismatch"):
        AgentBomDocument.model_validate(payload)


@pytest.mark.parametrize("mutation", ["edge", "receipt", "coverage", "duplicate", "extra"])
def test_invalid_profile_relationships_and_scope_rejected(mutation):
    payload = build_agent_bom(inventory_agent()).model_dump(mode="json")
    content = payload["content"]
    if mutation == "edge":
        content["relationships"][0]["target"] = "another-agent"
    elif mutation == "receipt":
        content["components"][0]["evidence_ids"] = ["unknown"]
    elif mutation == "coverage":
        content["coverage"][1]["area"] = content["coverage"][0]["area"]
    elif mutation == "duplicate":
        content["components"].append(content["components"][0])
    else:
        content["subject"]["credential"] = "forbidden field"
    with pytest.raises(ValidationError):
        AgentBomDocument.model_validate(payload)


def test_generated_schema_accepts_export():
    import jsonschema

    doc = build_agent_bom(inventory_agent())
    jsonschema.Draft202012Validator(AgentBomDocument.model_json_schema()).validate(doc.model_dump(mode="json"))
