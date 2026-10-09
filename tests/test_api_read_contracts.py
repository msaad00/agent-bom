"""Live-body contract for the typed dashboard read endpoints.

Each endpoint is called against a seeded estate and an empty one, and the real
JSON body is validated against its documented response model with undeclared
keys forbidden at every level. A model that drifts from the handler fails here,
not as a silently narrowed or fail-open response in production.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError
from starlette.testclient import TestClient

from agent_bom.api import read_models
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers
from tests.test_demo_estate_bootstrap import demo_estate_client  # noqa: F401

TYPED_READS: dict[str, type[read_models.ReadResponse]] = {
    "/v1/activity": read_models.ActivityTimelineResponse,
    "/v1/agents": read_models.AgentsResponse,
    "/v1/auth/me": read_models.AuthMeResponse,
    "/v1/cloud/connections": read_models.CloudConnectionsResponse,
    "/v1/compliance": read_models.ComplianceResponse,
    "/v1/compliance/hub/posture": read_models.HubPostureResponse,
    "/v1/compliance/narrative": read_models.ComplianceNarrativeResponse,
    "/v1/connectors": read_models.ConnectorsResponse,
    "/v1/discovery/providers": read_models.DiscoveryProvidersResponse,
    "/v1/findings": read_models.FindingsResponse,
    "/v1/fleet": read_models.FleetResponse,
    "/v1/fleet/stats": read_models.FleetStatsResponse,
    "/v1/frameworks/catalogs": read_models.FrameworkCatalogsResponse,
    "/v1/gateway/policies": read_models.GatewayPoliciesResponse,
    "/v1/graph/scenarios": read_models.GraphScenariosResponse,
    "/v1/identities": read_models.IdentitiesResponse,
    "/v1/intel/sources": read_models.IntelSourcesResponse,
    "/v1/jobs": read_models.JobsResponse,
    "/v1/overview": read_models.OverviewResponse,
    "/v1/posture": read_models.PostureResponse,
    "/v1/posture/counts": read_models.PostureCountsResponse,
    "/v1/proxy/alerts": read_models.ProxyAlertsResponse,
    "/v1/proxy/status": read_models.ProxyStatusResponse,
    "/v1/registry": read_models.RegistryResponse,
    "/v1/runtime/drift/incidents": read_models.DriftIncidentsResponse,
    "/v1/siem/connectors": read_models.SiemConnectorsResponse,
    "/v1/siem/formats": read_models.SiemFormatsResponse,
    "/v1/skills/scan": read_models.SkillsScanResponse,
    "/v1/sources": read_models.SourcesResponse,
    "/v1/ticketing/connections": read_models.TicketingConnectionsResponse,
    "/v1/trends": read_models.TrendsResponse,
}

# Seeded demo requests run as the anonymous viewer, which the demo estate grants.
_DEMO_HEADERS: dict[str, str] = {}


# Endpoints whose empty-estate answer is an error rather than an empty body.
def _undeclared_keys(value: Any, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, BaseModel):
        for key in (value.__pydantic_extra__ or {}).keys():
            found.append(f"{path}.{key}")
        for name in type(value).model_fields:
            if name in value.model_fields_set:
                found.extend(_undeclared_keys(getattr(value, name), f"{path}.{name}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_undeclared_keys(item, f"{path}[{index}]"))
    elif isinstance(value, dict):
        for key, item in value.items():
            found.extend(_undeclared_keys(item, f"{path}.{key}"))
    return found


def _contract_violations(path: str, body: Any) -> list[str]:
    model = TYPED_READS[path]
    try:
        instance = model.model_validate(body, context={read_models.STRICT_CONTRACT: True})
    except ValidationError as exc:
        return [f"{path}: {exc}"]
    problems: list[str] = []
    undeclared = _undeclared_keys(instance)
    if undeclared:
        problems.append(f"{path}: keys {model.__name__} does not document: {undeclared[:10]}")
    # Round-trip proves the documented model reproduces the body exactly.
    if instance.model_dump(mode="json", by_alias=True, exclude_unset=True) != body:
        problems.append(f"{path}: model round-trip changes the body")
    return problems


def test_every_typed_read_documents_its_model_in_openapi() -> None:
    from agent_bom.api.server import app

    app.openapi_schema = None
    paths = app.openapi()["paths"]
    documented = {path: paths[path]["get"]["responses"]["200"]["content"]["application/json"]["schema"] for path in TYPED_READS}
    assert documented == {path: {"$ref": f"#/components/schemas/{model.__name__}"} for path, model in TYPED_READS.items()}


def test_seeded_bodies_match_documented_models(demo_estate_client: TestClient) -> None:  # noqa: F811
    problems: list[str] = []
    for path in sorted(TYPED_READS):
        response = demo_estate_client.get(path, headers=_DEMO_HEADERS)
        if response.status_code != 200:
            problems.append(f"{path}: HTTP {response.status_code}")
            continue
        problems.extend(_contract_violations(path, response.json()))
    assert not problems, "\n".join(problems)


@pytest.fixture()
def empty_estate_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Any):
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "empty.db"))
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    from agent_bom.api import stores as api_stores
    from agent_bom.api.routes.overview import _reset_overview_cache
    from agent_bom.api.server import app, set_job_store
    from agent_bom.api.store import InMemoryJobStore

    original_store = api_stores._store
    set_job_store(InMemoryJobStore())
    _reset_overview_cache()
    enable_trusted_proxy_env()
    try:
        with TestClient(app) as client:
            yield client
    finally:
        disable_trusted_proxy_env()
        api_stores._store = original_store
        _reset_overview_cache()


def test_empty_estate_bodies_match_documented_models(empty_estate_client: TestClient) -> None:
    problems: list[str] = []
    headers = proxy_headers(role="admin", tenant="contract-empty")
    for path in sorted(TYPED_READS):
        response = empty_estate_client.get(path, headers=headers)
        if response.status_code != 200:
            problems.append(f"{path}: HTTP {response.status_code} {response.text[:200]}")
            continue
        problems.extend(_contract_violations(path, response.json()))
    assert not problems, "\n".join(problems)


def test_contract_drift_fails_open_with_the_handler_body(caplog: pytest.LogCaptureFixture) -> None:
    drifted = {"connectors": ["a", 7], "unexpected": True}
    with caplog.at_level(logging.WARNING, logger=read_models.__name__):
        instance = read_models.ConnectorsResponse.model_validate(drifted)
    assert any("response contract drift for ConnectorsResponse" in record.getMessage() for record in caplog.records)
    assert "unexpected" not in caplog.text and "'a'" not in caplog.text
    assert instance.model_dump(mode="json", exclude_unset=True, warnings=False) == drifted


def test_integral_numbers_are_not_rerendered_as_floats() -> None:
    body = {"total": 3, "avg_trust_score": 100, "low_trust_count": 0, "by_environment": {}, "by_state": {}}
    instance = read_models.FleetStatsResponse.model_validate(body)
    expected = '{"total":3,"avg_trust_score":100,"low_trust_count":0,"by_environment":{},"by_state":{}}'
    assert instance.model_dump_json(exclude_unset=True) == expected


def test_error_codes_in_the_schema_match_the_runtime_mapping() -> None:
    from typing import get_args

    from agent_bom.api.error_envelope import _ERROR_CODE_BY_STATUS, ErrorCode

    assert set(get_args(ErrorCode)) == set(_ERROR_CODE_BY_STATUS.values())


def test_v1_operations_document_the_real_error_envelope() -> None:
    from agent_bom.api.server import app

    app.openapi_schema = None
    paths = app.openapi()["paths"]
    stale = []
    for path, operations in paths.items():
        if not path.startswith("/v1/"):
            continue
        for method, operation in operations.items():
            responses = operation["responses"]
            for status_range in ("4XX", "5XX"):
                # SSE routes carry the schema under their own media type.
                schemas = [media.get("schema") for media in responses.get(status_range, {}).get("content", {}).values()]
                if schemas != [{"$ref": "#/components/schemas/ErrorEnvelope"}]:
                    stale.append(f"{method.upper()} {path} {status_range}")
            if "HTTPValidationError" in str(responses):
                stale.append(f"{method.upper()} {path} HTTPValidationError")
    assert not stale, stale[:10]


def test_live_error_bodies_validate_against_the_envelope(empty_estate_client: TestClient) -> None:
    from agent_bom.api.error_envelope import ErrorEnvelope

    headers = proxy_headers(role="admin", tenant="contract-empty")
    not_found = empty_estate_client.get("/v1/scan/does-not-exist", headers=headers)
    invalid = empty_estate_client.get("/v1/jobs", params={"limit": "0"}, headers=headers)
    forbidden = empty_estate_client.get("/v1/audit", headers=proxy_headers(role="viewer", tenant="contract-empty"))
    observed = {}
    for response in (not_found, invalid, forbidden):
        envelope = ErrorEnvelope.model_validate(response.json())
        assert envelope.error.correlation_id == response.headers["X-Request-ID"]
        observed[response.status_code] = envelope.error.code
    assert observed == {404: "NOT_FOUND", 422: "VALIDATION_ERROR", 403: "FORBIDDEN"}
