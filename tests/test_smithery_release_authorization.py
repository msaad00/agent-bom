"""Bounded Smithery scan authorization recovery."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.request import Request

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "authorize_smithery_release.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("authorize_smithery_release", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_extracts_only_the_expected_upstream_authorization_endpoint() -> None:
    module = _load_script()
    payload = {
        "logs": [
            {"message": "ignore https://evil.example/oauth/authorize?state=bad"},
            {
                "message": (
                    "Authorization required: https://mcp.example.test/oauth/authorize?"
                    "client_id=abc&state=opaque&response_type=code&"
                    "redirect_uri=https%3A%2F%2Fserver.smithery.ai%2Foauth%2Fcallback"
                )
            },
        ]
    }

    assert module.extract_authorization_url(payload, "https://mcp.example.test/mcp") == (
        "https://mcp.example.test/oauth/authorize?client_id=abc&state=opaque&response_type=code&"
        "redirect_uri=https%3A%2F%2Fserver.smithery.ai%2Foauth%2Fcallback"
    )


@pytest.mark.parametrize(
    "candidate",
    [
        "http://mcp.example.test/oauth/authorize?state=x",
        "https://evil.example/oauth/authorize?state=x",
        "https://mcp.example.test/other?state=x",
        "https://mcp.example.test.evil.invalid/oauth/authorize?state=x",
    ],
)
def test_rejects_untrusted_authorization_urls(candidate: str) -> None:
    module = _load_script()

    assert module.extract_authorization_url({"logs": [{"message": candidate}]}, "https://mcp.example.test/mcp") is None


def test_authorization_follows_a_bounded_redirect_without_printing_the_url(capsys) -> None:
    module = _load_script()
    seen: list[tuple[str, float]] = []

    class _Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit: int) -> bytes:
            return b"ok"

        def geturl(self) -> str:
            return "https://server.smithery.ai/oauth/callback?code=opaque"

    def opener(request, *, timeout, redirect_handler):
        seen.append((request.full_url, timeout))
        assert redirect_handler.allowed_origins == {
            ("https", "mcp.example.test", 443),
            ("https", "server.smithery.ai", 443),
        }
        return _Response()

    secret_url = (
        "https://mcp.example.test/oauth/authorize?state=sensitive&response_type=code&"
        "redirect_uri=https%3A%2F%2Fserver.smithery.ai%2Foauth%2Fcallback"
    )
    module.complete_authorization(secret_url, opener=opener)

    assert seen == [(secret_url, 30.0)]
    assert "sensitive" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "redirect_url",
    [
        "http://server.smithery.ai/oauth/callback?code=secret",
        "https://evil.example/oauth/callback?code=secret",
        "https://127.0.0.1/oauth/callback?code=secret",
        "https://foo.smithery.ai/oauth/callback?code=secret",
        "https://server.smithery.ai:444/oauth/callback?code=secret",
        "https://server.smithery.ai/arbitrary?code=secret",
        "https://server.smithery.ai.evil.example/oauth/callback?code=secret",
    ],
)
def test_redirect_handler_rejects_cross_origin_and_insecure_redirects(redirect_url: str) -> None:
    module = _load_script()
    handler = module._BoundedRedirectHandler(
        authorization_url="https://mcp.example.test/oauth/authorize?state=opaque",
        callback_url="https://server.smithery.ai/oauth/callback",
    )

    with pytest.raises(ValueError, match="trusted HTTPS origin"):
        handler.redirect_request(
            Request("https://mcp.example.test/oauth/authorize?state=opaque"),
            None,
            302,
            "Found",
            {},
            redirect_url,
        )


def test_authorization_requires_a_smithery_https_callback() -> None:
    module = _load_script()

    with pytest.raises(ValueError, match="Smithery redirect_uri"):
        module.complete_authorization("https://mcp.example.test/oauth/authorize?state=x&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback")

    with pytest.raises(ValueError, match="Smithery redirect_uri"):
        module.complete_authorization(
            "https://mcp.example.test/oauth/authorize?state=x&"
            "redirect_uri=https%3A%2F%2Fserver.smithery.ai%2Foauth%2Fcallback%3Fnext%3Dopaque"
        )


def test_authorization_rejects_a_200_response_that_never_reaches_the_callback() -> None:
    module = _load_script()
    authorization_url = (
        "https://mcp.example.test/oauth/authorize?state=sensitive&redirect_uri=https%3A%2F%2Fserver.smithery.ai%2Foauth%2Fcallback"
    )

    class _Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit: int) -> bytes:
            return b"login required"

        def geturl(self) -> str:
            return authorization_url

    def opener(_request, *, timeout, redirect_handler):
        assert timeout == 30.0
        assert redirect_handler.allowed_origins
        return _Response()

    with pytest.raises(RuntimeError, match="callback failed"):
        module.complete_authorization(authorization_url, opener=opener)


def test_authorization_rejects_a_redirect_after_the_exact_callback() -> None:
    module = _load_script()
    handler = module._BoundedRedirectHandler(
        authorization_url="https://mcp.example.test/oauth/authorize?state=opaque",
        callback_url="https://server.smithery.ai/oauth/callback",
    )

    with pytest.raises(ValueError, match="one exact callback"):
        handler.redirect_request(
            Request("https://server.smithery.ai/oauth/callback?code=opaque"),
            None,
            302,
            "Found",
            {},
            "https://server.smithery.ai/oauth/success",
        )
