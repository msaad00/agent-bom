"""Write-path contract alignment: one answer per class of bad input.

Three defect classes are pinned here, each reproduced against a live app before
the fix:

1. **4xx vs 5xx.** ``POST /v1/traces`` funnelled every parser failure through a
   blanket ``except Exception`` -> 500, so a malformed *client* body returned
   ``INTERNAL_ERROR`` carrying the raw exception text (``'str' object has no
   attribute 'get'``). Its sibling ``POST /v1/traces/attack-paths`` mapped the
   same parser's ``ValueError`` to 400 — same body, same parser, two answers.

2. **Unknown fields.** 60 of 69 write bodies set ``extra="forbid"``; a handful
   silently swallowed unknown keys, so a typo'd field on a config write
   returned 200 having done nothing.

3. **``tenant_id`` in the body.** Eight write routes accept a client-supplied
   ``tenant_id``. Three rejected a mismatch with 403, three ignored it with a
   response warning, two ignored it silently. No route ever wrote to the body's
   tenant, so this was never a cross-tenant write — but the contract answer for
   "you asked to write into a tenant you are not authenticated for" has to be
   one answer, and the fail-closed one.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.credential_store import InMemoryCredentialRefStore
from agent_bom.api.schedule_store import InMemoryScheduleStore
from agent_bom.api.server import app
from agent_bom.api.source_store import InMemorySourceStore
from agent_bom.api.stores import set_credential_ref_store, set_schedule_store, set_source_store
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


@pytest.fixture(autouse=True)
def _stores() -> None:
    """Wire the in-memory stores the create routes write through.

    Production wires these in the app lifespan; without them a create route
    raises ``RuntimeError`` from the store accessor, which would mask the
    contract behaviour under test.
    """
    set_credential_ref_store(InMemoryCredentialRefStore())
    set_schedule_store(InMemoryScheduleStore())
    set_source_store(InMemorySourceStore())


def _client(role: str = "admin", tenant: str = "write-contract") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role=role, tenant=tenant))
    return client


def _envelope(response: Any) -> dict[str, Any]:
    body = response.json()
    assert "error" in body, body
    return dict(body["error"])


# ── class 1: a malformed body is a client error, on every sibling route ──────


MALFORMED_TRACE_BODIES = [
    pytest.param({}, id="no-spans-key"),
    pytest.param({"spans": "not-a-list"}, id="spans-not-a-list"),
    pytest.param({"spans": ["not-an-object"]}, id="span-not-an-object"),
    pytest.param({"resourceSpans": "not-a-list"}, id="resourcespans-not-a-list"),
    pytest.param({"resourceSpans": ["not-an-object"]}, id="resourcespan-not-an-object"),
    pytest.param({"resourceSpans": [{"scopeSpans": ["not-an-object"]}]}, id="scopespan-not-an-object"),
    pytest.param({"resourceSpans": [{"scopeSpans": [{"spans": ["nope"]}]}]}, id="nested-span-not-an-object"),
]


@pytest.mark.parametrize("body", MALFORMED_TRACE_BODIES)
@pytest.mark.parametrize("path", ["/v1/traces", "/v1/traces/attack-paths"])
def test_malformed_trace_body_is_a_client_error(path: str, body: dict[str, Any]) -> None:
    response = _client().post(path, json=body)
    assert response.status_code == 422, response.text
    assert _envelope(response)["code"] == "VALIDATION_ERROR"


@pytest.mark.parametrize("body", MALFORMED_TRACE_BODIES)
@pytest.mark.parametrize("path", ["/v1/traces", "/v1/traces/attack-paths"])
def test_malformed_trace_body_never_leaks_raw_exception_text(path: str, body: dict[str, Any]) -> None:
    """A parser's internal AttributeError text must not reach the client."""
    response = _client().post(path, json=body)
    assert "object has no attribute" not in response.text
    assert "Traceback" not in response.text


def test_trace_sibling_routes_agree_on_status_for_the_same_bad_body() -> None:
    body = {"spans": ["not-an-object"]}
    client = _client()
    ingest = client.post("/v1/traces", json=body)
    correlate = client.post("/v1/traces/attack-paths", json=body)
    assert ingest.status_code == correlate.status_code, (ingest.text, correlate.text)


def test_valid_flat_trace_still_ingests() -> None:
    """The fix must not turn a well-formed empty payload into an error."""
    response = _client().post("/v1/traces", json={"spans": []})
    assert response.status_code == 200, response.text
    assert response.json()["traces"] == 0


# ── class 2: unknown fields are rejected, and the error names them ───────────


UNKNOWN_FIELD_WRITES = [
    pytest.param(
        "PUT",
        "/v1/overview/score-config",
        {"weights": {}, "weigths": {"a": 1}},
        "weigths",
        id="score-config",
    ),
    pytest.param(
        "POST",
        "/v1/exports/destinations",
        {"kind": "s3", "display_name": "d", "confg": {}},
        "confg",
        id="export-destination",
    ),
    pytest.param(
        "POST",
        "/v1/governance/blueprints",
        {"name": "bp", "owner": "o", "descrption": "x"},
        "descrption",
        id="blueprint-create",
    ),
]


@pytest.mark.parametrize("method,path,body,offender", UNKNOWN_FIELD_WRITES)
def test_unknown_field_on_a_write_is_rejected_and_named(method: str, path: str, body: dict[str, Any], offender: str) -> None:
    response = _client().request(method, path, json=body)
    assert response.status_code == 422, response.text
    assert offender in response.text, response.text


# ── class 3: a body tenant_id that is not the caller's fails closed ──────────


BODY_TENANT_WRITES = [
    pytest.param("POST", "/v1/credentials", {"display_name": "c", "provider": "aws", "external_ref": "env:X"}, id="credentials"),
    pytest.param("POST", "/v1/schedules", {"name": "s", "cron_expression": "0 0 * * *"}, id="schedules"),
    pytest.param(
        "POST",
        "/v1/sources",
        {
            "display_name": "s",
            "kind": "scan.repo",
            "config": {"scan_request": {"repo_url": "https://github.com/example/repo"}},
        },
        id="sources",
    ),
    pytest.param("POST", "/v1/exceptions", {"vuln_id": "CVE-2024-1", "package_name": "p"}, id="exceptions"),
    pytest.param(
        "POST",
        "/v1/findings/bulk",
        {"source": "connector", "findings": [{"id": "f-1", "severity": "high"}]},
        id="findings-bulk",
    ),
    pytest.param(
        "POST",
        "/v1/datasets/ds-contract/versions",
        {"source": "s3", "artifact_uri": "s3://b/k"},
        id="dataset-versions",
    ),
    pytest.param("POST", "/v1/evaluations", {"name": "e"}, id="evaluations"),
]


@pytest.mark.parametrize("method,path,body", BODY_TENANT_WRITES)
def test_body_tenant_id_mismatch_fails_closed(method: str, path: str, body: dict[str, Any]) -> None:
    payload = dict(body) | {"tenant_id": "some-other-tenant"}
    response = _client(tenant="write-contract").request(method, path, json=payload)
    assert response.status_code == 403, response.text
    envelope = _envelope(response)
    assert envelope["code"] == "FORBIDDEN"
    assert "tenant_id" in envelope["message"]


@pytest.mark.parametrize("method,path,body", BODY_TENANT_WRITES)
def test_body_tenant_id_matching_the_caller_is_accepted(method: str, path: str, body: dict[str, Any]) -> None:
    payload = dict(body) | {"tenant_id": "write-contract"}
    response = _client(tenant="write-contract").request(method, path, json=payload)
    assert response.status_code < 400, response.text


# ── class 4: raw-dict write bodies are as strict as their modelled siblings ──


IDENTITY_WRITES = [
    pytest.param("/v1/identities", {"agent_id": "a"}, "role", id="issue-identity"),
    pytest.param("/v1/conditional-access-policies", {"name": "p"}, "description", id="conditional-policy"),
]


@pytest.mark.parametrize("path,body,known_field", IDENTITY_WRITES)
def test_raw_dict_write_rejects_unknown_field_and_names_it(path: str, body: dict[str, Any], known_field: str) -> None:
    typo = f"{known_field}_typo"
    response = _client().post(path, json=dict(body) | {typo: "x"})
    assert response.status_code == 400, response.text
    message = _envelope(response)["message"]
    assert typo in message, message
    assert known_field in message, message


@pytest.mark.parametrize("path,body,known_field", IDENTITY_WRITES)
def test_raw_dict_write_still_accepts_a_conforming_body(path: str, body: dict[str, Any], known_field: str) -> None:
    response = _client().post(path, json=body)
    assert response.status_code == 201, response.text


def test_structured_value_is_not_coerced_into_an_identifier() -> None:
    """``str({"x": 1})`` used to persist an identity literally named "{'x': 1}"."""
    response = _client().post("/v1/identities", json={"agent_id": {"x": 1}})
    assert response.status_code == 400, response.text
    assert "agent_id" in _envelope(response)["message"]


def test_structured_value_is_not_coerced_into_a_delegation_target() -> None:
    issued = _client().post("/v1/identities", json={"agent_id": "delegator"})
    assert issued.status_code == 201, issued.text
    identity_id = issued.json()["identity"]["identity_id"]
    response = _client().post(
        f"/v1/identities/{identity_id}/delegations",
        json={"delegatee": ["a", "b"], "scopes": ["read"]},
    )
    assert response.status_code == 400, response.text
    assert "delegatee" in _envelope(response)["message"]


def test_webhook_create_rejects_a_typoed_security_field() -> None:
    """A dropped ``signing_secret``/``allow_private_networks`` is a security silent-fail.

    The route reads a raw dict, so a misspelled ``signing_secret`` used to be
    dropped and the subscription was created with a server-generated secret the
    caller never asked for — a 201 that silently did the wrong thing.
    """
    response = _client().post(
        "/v1/webhooks",
        json={"url": "https://example.com/hook", "event_types": [], "signing_secrets": "s3cret"},
    )
    assert response.status_code == 400, response.text
    message = _envelope(response)["message"]
    assert "signing_secrets" in message, message
    assert "signing_secret" in message, message


def test_webhook_create_still_accepts_a_conforming_body() -> None:
    response = _client().post(
        "/v1/webhooks",
        json={"url": "https://example.com/hook", "event_types": [], "description": "ok"},
    )
    assert response.status_code == 201, response.text
