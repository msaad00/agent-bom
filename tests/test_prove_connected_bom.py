"""Real parser/rescan, retained storage, authenticated REST and MCP wire proof."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def journey(tmp_path):
    output = tmp_path / "proof"
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_")}
    env.update(PYTHONPATH=str(ROOT / "src"), AGENT_BOM_STATE_DIR=str(tmp_path / "state"))
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/prove_connected_bom.py"), "--output-dir", str(output)],
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return output, env


def test_changed_input_rescan_preserves_scope_and_prior_evidence(journey):
    output, env = journey
    proof = json.loads((output / "proof.json").read_text())
    before, after = proof["receipts"]
    assert before["linked_findings"] == ["vuln:CVE-2023-4863"]
    assert after["linked_findings"] == []
    assert before["input_sha256"] != after["input_sha256"]
    assert before["generation"] != after["generation"]
    assert before["relationship_pages"] == 2
    for receipt in (before, after):
        assert receipt["same_name_cloud_resources"] == 3
        assert receipt["tenant_isolation"] and receipt["mcp_service_parity"]
        assert len(receipt["bom_artifacts"]) == 3
        for filename in receipt["bom_artifacts"]:
            document = json.loads((output / filename).read_text())
            assert "agent-bom:cloud-inventory:v1" in json.dumps(document)
            assert "synthetic-example" in json.dumps(document)
            assert "example-project" in json.dumps(document)
    old = (output / "proof.json").read_bytes()
    repeated = subprocess.run(
        [sys.executable, str(ROOT / "scripts/prove_connected_bom.py"), "--output-dir", str(output)],
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert repeated.returncode != 0
    assert (output / "proof.json").read_bytes() == old


def test_authenticated_rest_retains_component_and_control_evidence(journey):
    output, env = journey
    probe = """
import json, secrets, sys
from pathlib import Path
from starlette.testclient import TestClient
from agent_bom.api.auth import Role, create_api_key_record
from agent_bom.api.server import app, configure_api, get_key_store
from agent_bom.api.stores import set_graph_store
from agent_bom.api.graph_store import SQLiteGraphStore
root = Path(sys.argv[1])
set_graph_store(SQLiteGraphStore(root / "graph.db"))
key = secrets.token_urlsafe(32)
get_key_store().add(create_api_key_record(key, "proof-reader", Role.ANALYST, tenant_id="connected-bom-example"))
configure_api(allow_unauthenticated=False, listener_host="127.0.0.1")
client = TestClient(app, base_url="http://127.0.0.1:8422")
path = "/v1/inventory/assets/pkg:pypi:pillow@9.0.0"
assert client.get(path, params={"scan_id":"connected-before"}).status_code == 401
headers = {"Authorization": "Bearer " + key}
response = client.get(path, params={"scan_id":"connected-before", "limit":1}, headers=headers)
assert response.status_code == 200, response.status_code
assert response.json() == json.loads((root / "before-component.json").read_text())[0]
controls = json.loads((root / "before-controls.json").read_text())
response = client.get("/v1/inventory/assets/" + controls["asset"]["id"], params={"scan_id":"connected-before"}, headers=headers)
assert response.status_code == 200
assert response.json() == controls
assert client.get(path, params={"scan_id":"missing"}, headers=headers).status_code == 404
"""
    subprocess.run([sys.executable, "-c", probe, str(output)], env=env, check=True, capture_output=True, text=True, timeout=60)


def test_mcp_wire_reads_retained_evidence_and_rejects_extra_arguments(journey):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    output, env = journey
    env.update(AGENT_BOM_GRAPH_DB=str(output / "graph.db"), AGENT_BOM_MCP_TENANT_ID="connected-bom-example")

    async def probe():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-c", "from agent_bom.cli import cli_main; cli_main()", "mcp", "server", "--profile", "graph"],
            env=env,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                assert "inventory_asset" in {tool.name for tool in (await session.list_tools()).tools}
                arguments = {"asset_id": "pkg:pypi:pillow@9.0.0", "scan_id": "connected-before", "limit": 1}
                response = await session.call_tool("inventory_asset", arguments)
                assert not response.isError
                assert json.loads(response.content[0].text) == json.loads((output / "before-component.json").read_text())[0]
                rejected = await session.call_tool("inventory_asset", {**arguments, "unexpected_argument": True})
                assert rejected.isError

    asyncio.run(asyncio.wait_for(probe(), timeout=30))
