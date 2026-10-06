"""Published contracts validate actual HTTP projections, including redaction."""

import json
from pathlib import Path

import jsonschema
import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output import to_json


@pytest.mark.parametrize("export", ["scan-report", "graph-export"])
def test_http_export_matches_published_contract(monkeypatch, export):
    store = InMemoryJobStore()
    monkeypatch.setattr(stores, "_store", store)
    report = AIBOMReport(
        scan_id="http-contract",
        agents=[
            Agent(
                name="contract-agent",
                agent_type=AgentType.CUSTOM,
                config_path="/private/test/config.json",
                mcp_servers=[MCPServer(name="server", command="npx", packages=[Package(name="example", version="1.0.0", ecosystem="npm")])],
            )
        ],
        prompt_scan_data={
            "files_scanned": 1,
            "findings": [
                {
                    "source_file": "system.prompt",
                    "line_number": 1,
                    "title": "Prompt override",
                    "category": "prompt_injection",
                    "severity": "high",
                    "detail": "Untrusted override",
                    "matched_text": "ignore previous instructions",
                    "recommendation": "Remove override",
                }
            ],
        },
    )
    store.put(
        ScanJob(
            job_id="http-contract",
            status=JobStatus.DONE,
            created_at="2026-10-01T00:00:00Z",
            completed_at="2026-10-01T00:00:01Z",
            request=ScanRequest(),
            result=to_json(report),
        )
    )
    path = "/v1/scan/http-contract"
    if export == "graph-export":
        path += "/graph-export?format=json"
    response = TestClient(app).get(path)
    assert response.status_code == 200
    payload = response.json()["result"] if export == "scan-report" else response.json()
    if export == "scan-report":
        assert payload["findings"]
    else:
        assert payload["nodes"] and payload["edges"]
    schema = json.loads((Path(__file__).resolve().parents[2] / "contracts/v1" / f"{export}.schema.json").read_text())
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(payload))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)
    assert "/private/test" not in json.dumps(payload)
