"""Per-agent scan exports preserve identity, provenance, bounds and tenant scope."""

import copy
import json

import pytest
from click.testing import CliRunner
from fastapi import FastAPI
from starlette.testclient import TestClient

from agent_bom.cli import main
from agent_bom.evidence.agent_bom import validate_agent_bom_json
from agent_bom.evidence.scan_agent_bom import AgentSelectionError, build_scan_agent_bom, read_scan_json


def scan():
    return {
        "scan_id": "scan-one",
        "generated_at": "2026-09-26T12:00:00Z",
        "agents": [
            {
                "name": "same",
                "canonical_id": identity,
                "stable_id": identity,
                "agent_type": "custom",
                "metadata": {"secret": "do-not-copy"},
                "mcp_servers": [
                    {
                        "name": "tools",
                        "surface": "mcp-server",
                        "canonical_id": "server-" + identity,
                        "args": ["do-not-copy"],
                        "env": {"TOKEN": "do-not-copy"},
                        "tools": [{"name": "read", "description": "do-not-copy"}],
                        "packages": [{"name": "example", "version": "1.0", "ecosystem": "pypi"}],
                    }
                ],
            }
            for identity in ("agent-a", "agent-b")
        ],
    }


def test_exact_scan_identity_and_deterministic_redacted_export():
    result = scan()
    before = copy.deepcopy(result)
    a = build_scan_agent_bom(result, agent_id="agent-b", tenant_id="tenant-a")
    b = build_scan_agent_bom(result, agent_id="agent-b", tenant_id="tenant-a")
    assert a == b
    assert result == before
    assert a.content.subject.agent_id == "agent-b"
    assert a.content.subject.identity_status == "observed"
    assert a.content.evidence[0].evidence_id == "scan:scan-one"
    assert a.generated_at == a.content.evidence[0].observed_at
    assert "do-not-copy" not in a.model_dump_json()
    assert len(a.content.components) == 3
    assert all(c.status == ("partial" if c.area == "composition" else "not_assessed") for c in a.content.coverage)
    assert validate_agent_bom_json(a.model_dump_json().encode()) == a


@pytest.mark.parametrize("identity", [None, "same", "missing"])
def test_no_ambiguous_or_name_selection(identity):
    with pytest.raises(AgentSelectionError):
        build_scan_agent_bom(scan(), agent_id=identity, tenant_id="t")


def test_conflicting_and_duplicate_ids_fail_closed():
    result = scan()
    result["agents"][1]["canonical_id"] = "agent-a"
    for identity in ("agent-a", "agent-b"):
        with pytest.raises(AgentSelectionError):
            build_scan_agent_bom(result, agent_id=identity, tenant_id="t")


def test_non_mcp_scan_wrapper_does_not_become_an_mcp_server():
    result = scan()
    result["agents"][0]["mcp_servers"][0]["surface"] = "container-image"
    doc = build_scan_agent_bom(result, agent_id="agent-a", tenant_id="t")
    assert [component.kind for component in doc.content.components] == ["package"]
    assert doc.content.relationships[0].source == "agent-a"


@pytest.mark.parametrize("field,value", [("generated_at", "not-a-date"), ("generated_at", "2026-09-26T12:00:00"), ("scan_id", "")])
def test_missing_or_invalid_provenance_is_not_fabricated(field, value):
    result = scan()
    result[field] = value
    with pytest.raises(ValueError):
        build_scan_agent_bom(result, agent_id="agent-a", tenant_id="t")


@pytest.mark.parametrize("raw", [b'{"agents":[],"agents":[]}', b'{"x":NaN}', b"\xff", b"[" * 2000])
def test_ambiguous_json_is_rejected(raw):
    with pytest.raises(ValueError):
        read_scan_json(raw)


def test_input_and_output_budgets(monkeypatch):
    monkeypatch.setattr("agent_bom.evidence.scan_agent_bom.MAX_SCAN_INPUT_BYTES", 10)
    with pytest.raises(ValueError):
        read_scan_json(b" " * 11)
    monkeypatch.setattr("agent_bom.evidence.scan_agent_bom.MAX_AGENT_BOM_BYTES", 100)
    with pytest.raises(ValueError):
        build_scan_agent_bom(scan(), agent_id="agent-a", tenant_id="t")


def test_cli_reads_scan_without_discovery(monkeypatch, tmp_path):
    monkeypatch.setattr("agent_bom.cli._agent_manifest._discover_manifest_agents", lambda *a: pytest.fail("must not rediscover"))
    source, target = tmp_path / "scan.json", tmp_path / "agent.json"
    source.write_text(json.dumps(scan()))
    result = CliRunner().invoke(main, ["manifest", "--scan-result", str(source), "--agent-id", "agent-b", "-o", str(target)])
    assert result.exit_code == 0, result.output
    assert validate_agent_bom_json(target.read_bytes()).content.subject.agent_id == "agent-b"
    assert CliRunner().invoke(main, ["manifest", "--scan-result", str(source)]).exit_code == 2


@pytest.fixture
def api_client(monkeypatch):
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.routes import scan as routes
    from agent_bom.rbac import Role

    app = FastAPI()

    @app.middleware("http")
    async def trusted_principal(request, call_next):
        # Synthetic authentication fixture; a supplied tenant header has no authority.
        if request.headers.get("authorization") == "Bearer fixture-key":
            request.state.api_key_role = Role.VIEWER.value
            request.state.auth_method = "api_key"
            request.state.tenant_id = "tenant-a"
        return await call_next(request)

    from agent_bom.api.store import InMemoryJobStore

    store = InMemoryJobStore()
    for job_id, tenant, status in (
        ("job-a", "tenant-a", JobStatus.DONE),
        ("job-other", "tenant-b", JobStatus.DONE),
        ("pending", "tenant-a", JobStatus.PENDING),
    ):
        store.put(
            ScanJob(job_id=job_id, tenant_id=tenant, status=status, request=ScanRequest(), created_at="2026-09-26T12:00:00Z", result=scan())
        )
    monkeypatch.setattr(routes, "_get_store", lambda: store)
    monkeypatch.setattr(routes, "_jobs_get", lambda job_id: None)
    monkeypatch.setattr(
        "agent_bom.api.middleware.get_auth_runtime_status", lambda: {"auth_required": True, "unauthenticated_allowed": False}
    )
    app.include_router(routes.router, prefix="/v1")
    return TestClient(app)


def test_api_requires_auth_and_exports_only_selected_scan_agent(api_client):
    url = "/v1/scan/job-a/agent-bom?agent_id=agent-b"
    assert api_client.get(url).status_code in (401, 403)
    response = api_client.get(url, headers={"Authorization": "Bearer fixture-key"})
    assert response.status_code == 200, response.text
    doc = validate_agent_bom_json(response.content)
    assert doc.content.tenant_id == "tenant-a"
    assert doc.content.subject.agent_id == "agent-b"
    assert doc.content.evidence[0].evidence_id == "scan:job-a"
    assert api_client.get("/v1/scan/job-a/agent-bom?agent_id=same", headers={"Authorization": "Bearer fixture-key"}).status_code == 409
    assert (
        api_client.get("/v1/scan/job-other/agent-bom?agent_id=agent-b", headers={"Authorization": "Bearer fixture-key"}).status_code == 404
    )


def test_api_tenant_headers_cannot_override_authenticated_scope(api_client):
    headers = {"Authorization": "Bearer fixture-key", "X-Agent-Bom-Tenant-Id": "tenant-b"}
    assert api_client.get("/v1/scan/job-other/agent-bom?agent_id=agent-b", headers=headers).status_code == 404
    assert api_client.get("/v1/scan/pending/agent-bom?agent_id=agent-a", headers=headers).status_code == 409
    response = api_client.get("/v1/scan/job-a/agent-bom?agent_id=agent-a", headers=headers)
    assert response.json()["content"]["tenant_id"] == "tenant-a"


def test_evidence_refresh_changes_snapshot_without_changing_composition():
    result = scan()
    first = build_scan_agent_bom(result, agent_id="agent-a", tenant_id="t")
    result["generated_at"] = "2026-09-27T12:00:00Z"
    refreshed = build_scan_agent_bom(result, agent_id="agent-a", tenant_id="t")
    assert first.snapshot_id != refreshed.snapshot_id
    assert first.content.subject == refreshed.content.subject
    assert first.content.components == refreshed.content.components


def test_unknown_package_version_is_preserved_as_unknown():
    result = scan()
    result["agents"][0]["mcp_servers"][0]["packages"][0].pop("version")
    doc = build_scan_agent_bom(result, agent_id="agent-a", tenant_id="t")
    assert next(c for c in doc.content.components if c.kind == "package").version is None
