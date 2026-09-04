"""Executable evidence for the machine-readable MCP compatibility contract."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
import os
import secrets
import sys
import tomllib
from importlib.metadata import version
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from jsonschema import Draft202012Validator
from mcp import ClientSession, StdioServerParameters
from mcp.client.session import SUPPORTED_PROTOCOL_VERSIONS
from mcp.client.stdio import stdio_client
from mcp.types import LATEST_PROTOCOL_VERSION
from starlette.testclient import TestClient

from agent_bom.mcp_server import create_mcp_server
from agent_bom.mcp_server_factory import build_mcp_authorization_server

REPO_ROOT = Path(__file__).parents[1]
MANIFEST_PATH = REPO_ROOT / "src" / "agent_bom" / "data" / "mcp_protocol_compatibility.json"
SCHEMA_PATH = REPO_ROOT / "src" / "agent_bom" / "data" / "mcp_protocol_compatibility.schema.json"
OFFICIAL_REVISION = "2026-07-28"
LOCKED_PROTOCOL = "2025-11-25"
EXECUTABLE_EVIDENCE_IDS = {
    "tests/test_mcp_protocol_compatibility.py::test_locked_sdk_stdio_wire_contract",
    "tests/test_mcp_protocol_compatibility.py::test_locked_sdk_streamable_http_wire_contract",
    "tests/test_mcp_protocol_compatibility.py::test_2026_server_discover_is_rejected_by_session_era_server",
    "tests/test_mcp_protocol_compatibility.py::test_oauth_2025_resource_binding_gap_is_recorded_as_nonconformant",
}
EVIDENCE_KIND_BASIS = {
    "executable_test": "executable_contract",
    "official_spec": "official_spec",
    "source": "static_code",
}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _manifest() -> dict:
    return _load(MANIFEST_PATH)


def _features() -> dict[str, dict]:
    return {row["feature_id"]: row for row in _manifest()["features"]}


def _sse_json(response) -> dict:
    for line in response.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line.removeprefix("data: "))
    raise AssertionError(f"no JSON data event in response: {response.text[:200]!r}")


def test_manifest_validates_against_strict_schema() -> None:
    schema = _load(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    errors = sorted(Draft202012Validator(schema).iter_errors(_manifest()), key=lambda error: list(error.path))
    assert errors == [], "\n".join(error.message for error in errors)


def test_schema_rejects_conformance_claim_without_passing_wire_evidence() -> None:
    schema = _load(SCHEMA_PATH)
    manifest = copy.deepcopy(_manifest())
    feature = next(row for row in manifest["features"] if row["feature_id"] == "server.sse.transport")
    feature.update(
        implementation_state="implemented",
        conformance_state="conformant",
        assessment_status="complete",
        evidence_basis=["static_code"],
        evidence_refs=[],
        evidence_outcome="passed",
        reason_codes=[],
    )

    errors = list(Draft202012Validator(schema).iter_errors(manifest))

    assert errors, "the published schema must fail closed on unsupported conformance claims"


def test_schema_rejects_evidence_ref_without_matching_basis() -> None:
    schema = _load(SCHEMA_PATH)
    manifest = copy.deepcopy(_manifest())
    feature = next(row for row in manifest["features"] if row["feature_id"] == "server.2026.no_session_id")
    feature["evidence_basis"] = ["live_wire", "official_spec"]

    errors = list(Draft202012Validator(schema).iter_errors(manifest))

    assert errors, "the published schema must bind evidence reference kinds to their declared evidence basis"


def test_schema_rejects_evidence_basis_without_matching_ref() -> None:
    schema = _load(SCHEMA_PATH)
    manifest = copy.deepcopy(_manifest())
    feature = next(row for row in manifest["features"] if row["feature_id"] == "server.sse.transport")
    feature["evidence_basis"].append("executable_contract")

    errors = list(Draft202012Validator(schema).iter_errors(manifest))

    assert errors, "the published schema must bind declared evidence basis to a matching reference kind"


def test_feature_ids_are_unique_and_claims_bind_to_passing_executable_tests() -> None:
    rows = _manifest()["features"]
    ids = [row["feature_id"] for row in rows]
    assert len(ids) == len(set(ids))

    for row in rows:
        passed_refs = {ref["ref"] for ref in row["evidence_refs"] if ref["kind"] == "executable_test" and ref["outcome"] == "passed"}
        assert passed_refs <= EXECUTABLE_EVIDENCE_IDS, row["feature_id"]
        if row["implementation_state"] == "implemented" or row["conformance_state"] == "conformant":
            assert passed_refs, row["feature_id"]
            assert row["evidence_outcome"] == "passed", row["feature_id"]
            assert row["assessment_status"] == "complete", row["feature_id"]


def test_evidence_reference_kinds_match_declared_basis() -> None:
    for row in _manifest()["features"]:
        ref_kinds = {ref["kind"] for ref in row["evidence_refs"]}
        for ref_kind, basis in EVIDENCE_KIND_BASIS.items():
            assert (ref_kind in ref_kinds) == (basis in row["evidence_basis"]), row["feature_id"]


def test_sdk_policy_separates_locked_capability_from_current_official_revision() -> None:
    manifest = _manifest()
    sdk = manifest["sdk_policy"]
    official = manifest["official_protocol"]
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    dependency = next(item for item in project["dependencies"] if item.startswith("mcp>="))
    locked = next(item["version"] for item in lock["package"] if item["name"] == "mcp")

    assert sdk["dependency_constraint"] == dependency
    assert sdk["locked_version"] == locked == version("mcp")
    assert sdk["latest_protocol_supported_by_locked_sdk"] == LATEST_PROTOCOL_VERSION == LOCKED_PROTOCOL
    assert set(sdk["protocol_versions_supported_by_locked_sdk"]) == set(SUPPORTED_PROTOCOL_VERSIONS)
    assert official == {
        "current_revision": OFFICIAL_REVISION,
        "immutable_revision": OFFICIAL_REVISION,
        "source_url": "https://modelcontextprotocol.io/specification/2026-07-28/changelog",
        "retrieved_at": "2026-09-04",
    }
    assert official["current_revision"] != sdk["latest_protocol_supported_by_locked_sdk"]


def test_2026_protocol_deltas_are_independent_and_not_claimed_conformant() -> None:
    rows = [row for row in _manifest()["features"] if row["protocol_version"] == OFFICIAL_REVISION]
    required = {
        "server.2026.stateless_requests",
        "server.2026.server_discover",
        "server.2026.no_initialize",
        "server.2026.no_session_id",
        "server.2026.per_request_meta",
        "server.2026.method_name_headers",
        "server.2026.subscriptions_listen",
        "server.2026.extensions",
        "server.2026.tasks_extension",
        "server.2026.mrtr",
        "server.2026.result_type",
        "server.2026.cache_hints",
        "server.2026.deterministic_tools_list",
        "server.2026.no_sse_resumability",
        "server.2026.removed_control_methods",
        "server.2026.elicitation_completion_removed",
        "server.2026.error_code_allocation",
        "gateway.2026.trace_context",
        "server.2026.json_schema_2020_12",
        "server.2026.resource_error_code",
        "server.2026.oauth_issuer_identification",
        "server.2026.oauth_application_type",
        "server.2026.oauth_issuer_bound_credentials",
        "server.2026.cimd",
        "server.2026.deprecated_capabilities",
        "server.2026.http_sse_deprecated",
        "server.2026.include_context_deprecated",
        "server.2026.oauth_dcr_deprecated",
    }
    assert {row["feature_id"] for row in rows} == required
    assert all(row["conformance_state"] != "conformant" for row in rows)
    assert all(row["assessment_status"] in {"partial", "unavailable"} for row in rows)
    unassessed = [row for row in rows if "not_assessed" in row["evidence_basis"]]
    assert all(row["implementation_state"] == "unverified" for row in unassessed)


def test_surface_and_role_gaps_are_explicit() -> None:
    features = _features()
    assert features["server.sse.transport"]["lifecycle"] == "deprecated"
    assert features["server.sse.transport"]["conformance_state"] == "unverified"
    assert features["introspection.remote.authenticated"]["implementation_state"] == "not_implemented"
    for feature_id in ("api.compatibility_contract", "ui.compatibility_contract"):
        assert features[feature_id]["implementation_state"] == "not_implemented"
        assert features[feature_id]["assessment_status"] == "unavailable"
    assert _manifest()["official_conformance_suite"]["status"] == "not_run"


def test_locked_sdk_streamable_http_wire_contract(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    server = create_mcp_server()
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LOCKED_PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "agent-bom-contract", "version": "1"},
        },
    }
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        initialized = client.post("/mcp", headers=headers, json=initialize)
        payload = _sse_json(initialized)
        assert initialized.status_code == 200
        assert payload["result"]["protocolVersion"] == LOCKED_PROTOCOL
        session_id = initialized.headers["mcp-session-id"]
        session_headers = {
            **headers,
            "mcp-session-id": session_id,
            "mcp-protocol-version": LOCKED_PROTOCOL,
        }
        ready = client.post("/mcp", headers=session_headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        assert ready.status_code in {200, 202}
        for request_id, method, result_key, expected_count in (
            (2, "tools/list", "tools", 86),
            (3, "resources/list", "resources", 6),
            (4, "prompts/list", "prompts", 8),
        ):
            response = client.post(
                "/mcp",
                headers=session_headers,
                json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": {}},
            )
            result = _sse_json(response)["result"]
            assert response.status_code == 200
            assert len(result[result_key]) == expected_count

        for rejected_version in ("not-a-protocol-version", OFFICIAL_REVISION):
            response = client.post(
                "/mcp",
                headers={**session_headers, "mcp-protocol-version": rejected_version},
                json={"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}},
            )
            assert response.status_code == 400
            assert response.json()["error"]["code"] == -32600

        malformed = client.post("/mcp", headers=session_headers, content=b"{")
        assert malformed.status_code == 400
        assert malformed.json()["error"]["code"] == -32700


def test_locked_sdk_stdio_wire_contract(tmp_path) -> None:
    async def probe() -> None:
        env = os.environ.copy()
        env["AGENT_BOM_STATE_DIR"] = str(tmp_path / "state")
        env["PYTHONPATH"] = str(REPO_ROOT / "src")
        params = StdioServerParameters(
            command=sys.executable,
            args=["-c", "from agent_bom.cli import cli_main; cli_main()", "mcp", "server"],
            env=env,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                assert initialized.protocolVersion == LOCKED_PROTOCOL
                assert len((await session.list_tools()).tools) == 86
                assert len((await session.list_resources()).resources) == 6
                assert len((await session.list_prompts()).prompts) == 8

    asyncio.run(asyncio.wait_for(probe(), timeout=30))


def test_2026_server_discover_is_rejected_by_session_era_server(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    server = create_mcp_server()
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        response = client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "Mcp-Protocol-Version": OFFICIAL_REVISION,
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}},
        )
    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == -32600
    assert "session" in payload["error"]["message"].lower()
    assert "mcp-session-id" in response.headers
    assert _features()["server.2026.server_discover"]["conformance_state"] == "nonconformant"


def test_oauth_2025_resource_binding_gap_is_recorded_as_nonconformant() -> None:
    server = build_mcp_authorization_server("https://agent-bom.example/")
    client = server.register_client({"redirect_uris": ["https://client.example/cb"]})
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    resource = "https://agent-bom.example/mcp"
    location = server.authorize(
        {
            "response_type": "code",
            "client_id": client["client_id"],
            "redirect_uri": "https://client.example/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": resource,
        }
    )
    token = server.token(
        {
            "grant_type": "authorization_code",
            "code": parse_qs(urlparse(location).query)["code"][0],
            "redirect_uri": "https://client.example/cb",
            "client_id": client["client_id"],
            "code_verifier": verifier,
            "resource": resource,
        }
    )["access_token"]
    encoded_payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4)))

    assert claims["aud"] != resource
    oauth = _features()["server.oauth.authorization_server.2025"]
    assert oauth["implementation_state"] == "partial"
    assert oauth["conformance_state"] == "nonconformant"
    assert oauth["assessment_status"] == "partial"


def test_docs_bound_client_compatibility_to_the_verified_handshake_era() -> None:
    roots = (REPO_ROOT / "docs", REPO_ROOT / "site-docs", REPO_ROOT / "integrations")
    paths = [REPO_ROOT / "README.md", *(path for root in roots for path in root.rglob("*.md"))]
    offenders = [str(path.relative_to(REPO_ROOT)) for path in paths if "any mcp-compatible" in path.read_text(encoding="utf-8").lower()]
    assert offenders == []

    server_docs = (REPO_ROOT / "docs" / "MCP_SERVER.md").read_text(encoding="utf-8")
    assert LOCKED_PROTOCOL in server_docs
    assert OFFICIAL_REVISION in server_docs
