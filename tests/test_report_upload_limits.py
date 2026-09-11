"""Bound complete scan uploads without widening unrelated API request limits."""

import asyncio

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api.middleware import MaxBodySizeMiddleware


async def echo(request):
    return JSONResponse({"bytes": len(await request.body())})


def client():
    app = Starlette(routes=[Route(path, echo, methods=["POST"]) for path in ["/v1/results/push", "/v1/scan"]])
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=64, path_limits={"/v1/results/push": 256})
    return TestClient(app)


def test_complete_report_has_its_own_bounded_upload_budget():
    with client() as api:
        response = api.post("/v1/results/push", content=b"x" * 128)
        assert response.status_code == 200
        assert response.json() == {"bytes": 128}
        assert api.post("/v1/scan", content=b"x" * 128).status_code == 413
        assert api.post("/v1/results/push", content=b"x" * 257).status_code == 413


@pytest.mark.parametrize("length", [b"1", b"-1"])
def test_declared_length_cannot_bypass_actual_body_limit(length):
    async def run():
        async def receive():
            return {"type": "http.request", "body": b"x" * 128, "more_body": False}

        request = Request({"type": "http", "method": "POST", "path": "/v1/scan", "headers": [(b"content-length", length)]}, receive)
        middleware = MaxBodySizeMiddleware(lambda: None, max_bytes=64)
        response = await middleware.dispatch(request, echo)
        assert response.status_code in (400, 413)

    asyncio.run(run())


def test_declared_length_still_has_a_read_deadline(monkeypatch):
    async def run():
        async def receive():
            await asyncio.sleep(0.1)
            return {"type": "http.request", "body": b"x", "more_body": False}

        request = Request({"type": "http", "method": "POST", "path": "/v1/scan", "headers": [(b"content-length", b"1")]}, receive)
        middleware = MaxBodySizeMiddleware(lambda: None, max_bytes=64)
        monkeypatch.setattr(middleware, "_BODY_TIMEOUT_SECONDS", 0.01)
        response = await middleware.dispatch(request, echo)
        assert response.status_code == 408

    asyncio.run(run())


def test_gzip_report_is_decoded_without_losing_bytes():
    import gzip

    with client() as api:
        response = api.post("/v1/results/push", content=gzip.compress(b"x" * 200), headers={"Content-Encoding": "gzip"})
        assert response.status_code == 200
        assert response.json() == {"bytes": 200}


@pytest.mark.parametrize("payload_kind", ["oversized", "truncated", "corrupt", "trailing", "concatenated"])
def test_gzip_report_fails_closed(payload_kind):
    import gzip

    payload = gzip.compress(b"x" * (257 if payload_kind == "oversized" else 128))
    if payload_kind == "truncated":
        payload = payload[:-4]
    elif payload_kind == "corrupt":
        payload = b"invalid gzip"
    elif payload_kind == "trailing":
        payload += b"trailing"
    elif payload_kind == "concatenated":
        payload += gzip.compress(b"y")
    with client() as api:
        response = api.post("/v1/results/push", content=payload, headers={"Content-Encoding": "gzip"})
        assert response.status_code == (413 if payload_kind == "oversized" else 400)


def test_compression_does_not_widen_other_routes():
    import gzip

    with client() as api:
        assert api.post("/v1/scan", content=gzip.compress(b"x"), headers={"Content-Encoding": "gzip"}).status_code == 415


def test_chunked_gzip_and_identity_reach_the_parser():
    import gzip

    async def run(encoding):
        payload = b"x" * 128
        wire = gzip.compress(payload) if encoding == b"gzip" else payload
        chunks = iter(bytes([byte]) for byte in wire)

        async def receive():
            chunk = next(chunks, b"")
            return {"type": "http.request", "body": chunk, "more_body": bool(chunk)}

        request = Request(
            {"type": "http", "method": "POST", "path": "/v1/results/push", "headers": [(b"content-encoding", encoding)]}, receive
        )
        middleware = MaxBodySizeMiddleware(lambda: None, max_bytes=64, path_limits={"/v1/results/push": 256})
        response = await middleware.dispatch(request, echo)
        assert response.status_code == 200
        assert response.body == b'{"bytes":128}'

    for encoding in (b"gzip", b"identity"):
        asyncio.run(run(encoding))


def test_unauthenticated_report_is_rejected_before_body_consumption(monkeypatch):
    from agent_bom.api import server

    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    server.configure_api(api_key="upload-test-key", allow_unauthenticated=False)
    consumed = []

    def chunks():
        consumed.append(True)
        yield b"not valid gzip"

    response = TestClient(server.app).post("/v1/results/push", content=chunks(), headers={"Content-Encoding": "gzip"})
    assert response.status_code == 401
    assert consumed == []
