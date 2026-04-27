"""Slowloris throughput floor tests for MaxBodySizeMiddleware (audit-5 PR-C).

The middleware already had the per-request 30s read deadline; this PR
added a rolling-window throughput floor so an attacker cannot keep a
connection alive by trickling just enough bytes per second to dodge
the deadline. These tests use Starlette's TestClient which can't
itself stream slow bodies, so we drive the middleware via crafted
async iterables that simulate slow chunks at the asyncio layer.
"""

from __future__ import annotations

import asyncio

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api.middleware import MaxBodySizeMiddleware


async def _ok_handler(request):
    body = await request.body()
    return JSONResponse({"received": len(body)})


def _make_client(monkeypatch: pytest.MonkeyPatch, max_bytes: int = 1024 * 1024) -> TestClient:
    app = Starlette(routes=[Route("/v1/echo", _ok_handler, methods=["POST"])])
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=max_bytes)
    return TestClient(app)


@pytest.fixture(autouse=True)
def _restore_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AGENT_BOM_BODY_MIN_BPS", raising=False)
    yield


def test_normal_post_with_content_length_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _make_client(monkeypatch)
    response = client.post("/v1/echo", content=b"a" * 1024)
    assert response.status_code == 200
    assert response.json() == {"received": 1024}


def test_oversized_content_length_is_413_before_drain(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _make_client(monkeypatch, max_bytes=64)
    response = client.post("/v1/echo", content=b"a" * 256)
    assert response.status_code == 413


def test_throughput_floor_is_disabled_when_min_bps_is_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """Setting the floor to 0 is the documented escape hatch."""
    monkeypatch.setenv("AGENT_BOM_BODY_MIN_BPS", "0")
    assert MaxBodySizeMiddleware._throughput_floor_bps() == 0


def test_throughput_floor_default_is_256_bps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_BODY_MIN_BPS", raising=False)
    assert MaxBodySizeMiddleware._throughput_floor_bps() == 256


def test_throughput_floor_invalid_value_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_BODY_MIN_BPS", "not-a-number")
    assert MaxBodySizeMiddleware._throughput_floor_bps() == 256


def test_throughput_floor_negative_clamps_to_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_BODY_MIN_BPS", "-10")
    assert MaxBodySizeMiddleware._throughput_floor_bps() == 0


# ── Direct middleware exercise: slowloris simulation ─────────────────────


class _FakeRequest:
    """Minimal Starlette request stand-in for the middleware's drain path."""

    def __init__(self, method: str, chunks_with_delays: list[tuple[bytes, float]]) -> None:
        self.method = method
        self._chunks = chunks_with_delays
        self.headers = {}  # simulate no Content-Length

    async def stream(self):
        for chunk, delay in self._chunks:
            if delay > 0:
                await asyncio.sleep(delay)
            yield chunk


async def _drive_middleware(chunks_with_delays: list[tuple[bytes, float]]) -> tuple[int | None, str]:
    """Run MaxBodySizeMiddleware.dispatch() against a fake slow stream."""
    captured: dict[str, object] = {}

    async def _next(request):
        captured["body"] = b""
        return JSONResponse({"ok": True})

    middleware = MaxBodySizeMiddleware(app=lambda: None, max_bytes=10 * 1024 * 1024)
    request = _FakeRequest("POST", chunks_with_delays)
    response = await middleware.dispatch(request, _next)
    body = response.body.decode("utf-8") if hasattr(response, "body") else ""
    return getattr(response, "status_code", None), body


def test_fast_streaming_body_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """A normal client streams the body promptly — no floor violation."""
    monkeypatch.setenv("AGENT_BOM_BODY_MIN_BPS", "256")
    chunks: list[tuple[bytes, float]] = [(b"x" * 8192, 0.0)]
    status, _ = asyncio.run(_drive_middleware(chunks))
    assert status == 200


def test_slowloris_trickle_below_floor_aborts_408(monkeypatch: pytest.MonkeyPatch) -> None:
    """An attacker drips a few bytes per chunk at one-second intervals.

    Configure a 256 B/s floor + a tight 4 KB warmup. The attacker sends
    1 byte, waits 1.2s, sends 1 byte, etc. The first chunk past warmup
    after the rolling window has elapsed sees a sub-floor throughput
    and the request aborts with 408. The test runs with a tiny
    warmup so it doesn't have to push 4 KB of bytes in the asyncio
    test loop.
    """
    monkeypatch.setenv("AGENT_BOM_BODY_MIN_BPS", "256")
    monkeypatch.setattr(MaxBodySizeMiddleware, "_THROUGHPUT_WARMUP_BYTES", 4)
    monkeypatch.setattr(MaxBodySizeMiddleware, "_THROUGHPUT_WINDOW_SECONDS", 0.2)
    # 5 chunks of 1 byte spaced 0.1s apart → 1 byte per 0.1s = 10 B/s,
    # well below the 256 B/s floor. Warmup crosses by chunk 5.
    chunks: list[tuple[bytes, float]] = [
        (b"x", 0.05),
        (b"x", 0.05),
        (b"x", 0.05),
        (b"x", 0.05),
        (b"x", 0.5),  # this chunk is past warmup + window — must abort
        (b"x", 0.05),
    ]
    status, body = asyncio.run(_drive_middleware(chunks))
    assert status == 408
    assert "throughput" in body or "B/s" in body


def test_slowloris_floor_off_lets_slow_body_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """With AGENT_BOM_BODY_MIN_BPS=0 the floor is disabled completely."""
    monkeypatch.setenv("AGENT_BOM_BODY_MIN_BPS", "0")
    monkeypatch.setattr(MaxBodySizeMiddleware, "_THROUGHPUT_WARMUP_BYTES", 4)
    monkeypatch.setattr(MaxBodySizeMiddleware, "_THROUGHPUT_WINDOW_SECONDS", 0.2)
    chunks: list[tuple[bytes, float]] = [
        (b"x", 0.05),
        (b"x", 0.05),
        (b"x", 0.05),
        (b"x", 0.05),
        (b"x", 0.5),
    ]
    status, _ = asyncio.run(_drive_middleware(chunks))
    assert status == 200


def test_warmup_protects_tiny_post_from_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tiny POSTs (say 64 bytes total) must never trigger the throughput floor.

    The warmup threshold is the gate that protects them — the floor only
    activates after the body crosses ``_THROUGHPUT_WARMUP_BYTES``.
    """
    monkeypatch.setenv("AGENT_BOM_BODY_MIN_BPS", "256")
    # Default warmup 4096 — a 64-byte body never reaches it.
    chunks: list[tuple[bytes, float]] = [(b"x" * 64, 0.0), (b"y" * 32, 1.0)]
    status, _ = asyncio.run(_drive_middleware(chunks))
    assert status == 200
