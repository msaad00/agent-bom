"""Bounded Smithery scan authorization recovery."""

from __future__ import annotations

import importlib.util
from pathlib import Path

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
            {"message": ("Authorization required: https://mcp.example.test/oauth/authorize?client_id=abc&state=opaque&response_type=code")},
        ]
    }

    assert module.extract_authorization_url(payload, "https://mcp.example.test/mcp") == (
        "https://mcp.example.test/oauth/authorize?client_id=abc&state=opaque&response_type=code"
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

    def opener(request, *, timeout):
        seen.append((request.full_url, timeout))
        return _Response()

    secret_url = "https://mcp.example.test/oauth/authorize?state=sensitive&response_type=code"
    module.complete_authorization(secret_url, opener=opener)

    assert seen == [(secret_url, 30.0)]
    assert "sensitive" not in capsys.readouterr().out
