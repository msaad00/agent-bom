"""Client-caused malformed requests must be 4xx envelopes, never bare 500s.

Every case here previously escaped as an unhandled exception: the caller got a
bare ``500 Internal Server Error`` with no ``error.code`` and no
``correlation_id``, and 5xx alerting was poisoned by client-caused errors.
"""

from __future__ import annotations

import json

from starlette.testclient import TestClient

from agent_bom.api.server import app


def _envelope(response) -> dict:
    """Assert the v1 error envelope shape and return the ``error`` object."""
    body = response.json()
    assert "error" in body, body
    error = body["error"]
    assert isinstance(error.get("code"), str) and error["code"], body
    assert isinstance(error.get("message"), str) and error["message"], body
    assert isinstance(error.get("correlation_id"), str) and error["correlation_id"], body
    return error


def _deep_payload(depth: int = 400) -> dict:
    root: dict = {}
    cursor = root
    for _ in range(depth):
        cursor["a"] = {}
        cursor = cursor["a"]
    return root


def test_non_json_content_type_returns_validation_envelope_not_500() -> None:
    """A ``text/plain`` body makes Pydantic report raw ``bytes`` as ``input``."""
    client = TestClient(app)
    response = client.post(
        "/v1/findings/bulk",
        headers={"Content-Type": "text/plain"},
        content=b'{"findings":[{"title":"x"}]}',
    )
    assert response.status_code == 422, response.text
    _envelope(response)


def test_form_encoded_body_returns_validation_envelope_not_500() -> None:
    client = TestClient(app)
    response = client.post(
        "/v1/findings/bulk",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        content=b"findings=1",
    )
    assert response.status_code == 422, response.text
    _envelope(response)


def test_missing_content_type_returns_validation_envelope_not_500() -> None:
    client = TestClient(app)
    response = client.request(
        "POST",
        "/v1/findings/bulk",
        headers={"Content-Type": ""},
        content=b'{"findings":[{"title":"x"}]}',
    )
    assert response.status_code == 422, response.text
    _envelope(response)


def test_validation_errors_never_reflect_the_submitted_value() -> None:
    """422 detail must not echo credential-shaped submitted values."""
    client = TestClient(app)
    response = client.post(
        "/v1/exceptions",
        json={"password": "hunter2-do-not-echo", "api_key": "abom_LEAKED_KEY_VALUE"},
    )
    assert response.status_code == 422, response.text
    _envelope(response)
    assert "hunter2-do-not-echo" not in response.text
    assert "abom_LEAKED_KEY_VALUE" not in response.text
    for item in response.json()["error"]["details"]:
        assert "input" not in item, item


def test_deeply_nested_body_returns_422_envelope_not_500() -> None:
    """The idempotency fingerprint recurses; a 400-deep body must not 500."""
    client = TestClient(app)
    response = client.post(
        "/v1/findings/bulk",
        headers={"Content-Type": "application/json"},
        content=json.dumps({"findings": [{"title": "x", "metadata": _deep_payload()}]}),
    )
    assert response.status_code == 422, response.text
    _envelope(response)


def test_nul_byte_in_path_parameter_returns_400_envelope_not_500() -> None:
    """A NUL in a path id reaches psycopg as a text field and raises DataError."""
    client = TestClient(app)
    response = client.put("/v1/fleet/%00%01", json={"owner": "o"})
    assert response.status_code == 400, response.text
    error = _envelope(response)
    assert "NUL" in error["message"] or "null byte" in error["message"].lower()


def test_nul_byte_rejection_does_not_break_ordinary_paths() -> None:
    client = TestClient(app)
    assert client.get("/health").status_code == 200


def test_idempotency_payload_error_detail_is_sanitized() -> None:
    """The 422 body must never echo raw exception text (paths, URLs, secrets)."""
    from fastapi import FastAPI

    from agent_bom.api.idempotency_store import IdempotencyPayloadError
    from agent_bom.api.middleware import install_error_envelope

    leaky = FastAPI()
    install_error_envelope(leaky)

    @leaky.post("/boom")
    async def _boom() -> None:
        raise IdempotencyPayloadError(
            "payload rejected at /srv/agent-bom/secrets/creds.json via https://internal.example/api token=SUPER_SECRET"
        )

    response = TestClient(leaky, raise_server_exceptions=False).post("/boom")
    assert response.status_code == 422, response.text
    error = _envelope(response)
    assert "/srv/agent-bom/secrets/creds.json" not in response.text
    assert "https://internal.example/api" not in response.text
    assert "SUPER_SECRET" not in response.text
    assert "<path>" in error["message"] or "<url>" in error["message"]


# ── Middleware-origin failures share the route-origin envelope ──────────────
#
# Auth rejections are returned by the middleware stack, not by a route handler,
# so they never reached ``install_error_envelope``'s exception handlers. That
# left the single most common read-path failure class emitting a bare
# ``{"detail": ...}`` with no ``error.code`` and no ``correlation_id`` while
# every route-raised failure carried the full envelope.


def test_spoofed_proxy_role_rejection_uses_the_v1_error_envelope() -> None:
    """A middleware 401 must carry ``error.code``/``correlation_id`` like a route 401."""
    client = TestClient(app)
    response = client.get("/v1/posture", headers={"X-Agent-Bom-Role": "viewer", "X-Agent-Bom-Tenant-ID": "tenant-alpha"})

    from agent_bom.api.middleware import _error_code_for_status

    assert response.status_code == 401, response.text
    error = _envelope(response)
    # The same status must map to the same code whichever layer rejected it.
    assert error["code"] == _error_code_for_status(401), error
    # Backward compatibility: the historical top-level ``detail`` still parses.
    assert isinstance(response.json().get("detail"), str)


def test_scim_auth_rejection_uses_the_rfc7644_error_body() -> None:
    """SCIM failures must use the RFC 7644 Error schema, not the v1 envelope.

    RFC 7644 §3.12 fixes the body (``schemas`` + string ``status`` + ``detail``)
    and §3.1 fixes the media type. IdPs parse this shape; a bare
    ``{"detail": ...}`` is not conformant.
    """
    client = TestClient(app)
    response = client.get("/scim/v2/Users")

    assert response.status_code == 401, response.text
    body = response.json()
    assert body.get("schemas") == ["urn:ietf:params:scim:api:messages:2.0:Error"], body
    assert body.get("status") == "401", body
    assert isinstance(body.get("detail"), str) and body["detail"], body
    assert response.headers.get("content-type", "").startswith("application/scim+json"), response.headers
