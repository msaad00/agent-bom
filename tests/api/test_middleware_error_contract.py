"""Pre-routing rejections retain the same additive error contract as routes."""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from agent_bom.api.middleware import (
    APIKeyMiddleware,
    GlobalRateLimitMiddleware,
    MaxBodySizeMiddleware,
    RateLimitMiddleware,
    TrustHeadersMiddleware,
    install_error_envelope,
)


def _app(middleware, **kwargs):
    app = FastAPI()
    install_error_envelope(app)

    @app.get("/v1/jobs")
    def jobs():
        return {"jobs": []}

    @app.post("/v1/results/push")
    def push():
        return {"accepted": True}

    app.add_middleware(middleware, **kwargs)
    app.add_middleware(TrustHeadersMiddleware)
    return app


def _assert_envelope(response, status, code):
    assert response.status_code == status, response.text
    body = response.json()
    assert body["error"]["code"] == code
    assert body["error"]["details"] == body["detail"]
    assert body["error"]["correlation_id"] == response.headers["x-request-id"]


def test_auth_rejection_has_envelope_without_changing_auth():
    client = TestClient(_app(APIKeyMiddleware, api_key="qualification-static-key", allow_unauthenticated=False))
    denied = client.get("/v1/jobs", headers={"x-request-id": "auth-contract"})
    _assert_envelope(denied, 401, "AUTH_FAILED")
    assert client.get("/v1/jobs", headers={"Authorization": "Bearer qualification-static-key"}).status_code == 200


def test_oversized_body_preserves_budget_and_error_envelope():
    response = TestClient(_app(MaxBodySizeMiddleware, max_bytes=10)).post("/v1/results/push", content=b"x" * 11)
    _assert_envelope(response, 413, "PAYLOAD_TOO_LARGE")
    assert response.json()["max_bytes"] == 10


@pytest.mark.parametrize(
    "middleware, kwargs",
    [
        (GlobalRateLimitMiddleware, {"rpm": 1}),
        (RateLimitMiddleware, {"read_rpm": 1}),
    ],
)
def test_rate_limit_rejection_preserves_retry_headers(middleware, kwargs):
    client = TestClient(_app(middleware, **kwargs))
    assert client.get("/v1/jobs").status_code == 200
    rejected = client.get("/v1/jobs")
    _assert_envelope(rejected, 429, "RATE_LIMITED")
    assert int(rejected.headers["retry-after"]) >= 1


@pytest.mark.parametrize(
    "method,path,status,code",
    [
        ("GET", "/missing", 404, "NOT_FOUND"),
        ("DELETE", "/v1/jobs", 405, "METHOD_NOT_ALLOWED"),
    ],
)
def test_router_errors_keep_existing_envelope_and_allow_headers(method, path, status, code):
    client = TestClient(_app(MaxBodySizeMiddleware, max_bytes=10))
    response = client.request(method, path)
    _assert_envelope(response, status, code)
    if status == 405:
        assert "GET" in response.headers["allow"]


def test_middleware_wrapper_preserves_scim_and_streaming_protocols():
    from starlette.requests import Request
    from starlette.responses import JSONResponse, StreamingResponse

    from agent_bom.api.middleware import _with_middleware_error_envelope

    scim = Request({"type": "http", "path": "/scim/v2/Users", "headers": []})
    response = JSONResponse({"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": "Denied"}, status_code=401)
    original = response.body
    assert _with_middleware_error_envelope(scim, response) is response
    assert response.body == original
    stream = StreamingResponse(iter([b"event: error\n\n"]), status_code=400, media_type="text/event-stream")
    request = Request({"type": "http", "path": "/v1/events", "headers": []})
    assert _with_middleware_error_envelope(request, stream) is stream
