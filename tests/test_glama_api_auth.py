"""Directory API credentials never reach overrides or redirected destinations."""

import importlib.util
import io
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def checker(monkeypatch):
    spec = importlib.util.spec_from_file_location("glama_auth_check", ROOT / "scripts/check_glama_listing.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.delenv("GLAMA_API_KEY", raising=False)
    return module


def test_directory_key_is_bearer_and_transport_cannot_redirect_or_proxy(checker, monkeypatch):
    monkeypatch.setenv("GLAMA_API_KEY", "test-key")
    monkeypatch.setattr(checker, "_fetch", MagicMock(side_effect=AssertionError("authenticated API must not use anonymous fetch")))
    opener = MagicMock()
    opener.open.return_value.__enter__.return_value = io.BytesIO(b'{"tools": []}')
    build = MagicMock(return_value=opener)
    monkeypatch.setattr(checker.urllib.request, "build_opener", build)
    assert checker._fetch_json(checker.DEFAULT_API_URL, 3) == {"tools": []}
    request = opener.open.call_args.args[0]
    assert request.get_header("Authorization") == "Bearer test-key"
    assert "Authorization" not in request.headers
    assert opener.open.call_args.kwargs == {"timeout": 3}
    proxy, redirect = build.call_args.args
    assert proxy.proxies == {}
    for code in (301, 302, 303, 307, 308):
        for destination in ("https://evil.example/", checker.DEFAULT_API_URL, "http://glama.ai/api/mcp/v1/servers"):
            assert redirect.redirect_request(request, None, code, "redirect", {}, destination) is None


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/api/mcp/v1/servers",
        "http://glama.ai/api/mcp/v1/servers",
        "https://glama.ai.evil.example/api/mcp/v1/servers",
        "https://user@glama.ai/api/mcp/v1/servers",
        "https://glama.ai:8443/api/mcp/v1/servers",
        "https://glama.ai/mcp/servers/example",
        "https://glama.ai/api/mcp/../../mcp/servers/example",
        "https://glama.ai/api/mcp/%2e%2e/other",
    ],
)
def test_key_never_sent_to_endpoint_override(checker, monkeypatch, url):
    monkeypatch.setenv("GLAMA_API_KEY", "test-key")
    build = MagicMock()
    monkeypatch.setattr(checker.urllib.request, "build_opener", build)
    with pytest.raises(ValueError, match="trusted HTTPS"):
        checker._fetch_json(url, 3)
    build.assert_not_called()


def test_no_key_preserves_anonymous_fetch(checker, monkeypatch):
    fetch = MagicMock(return_value='{"tools": []}')
    monkeypatch.setattr(checker, "_fetch", fetch)
    assert checker._fetch_json(checker.DEFAULT_API_URL, 3) == {"tools": []}
    fetch.assert_called_once_with(checker.DEFAULT_API_URL, 3)


def test_public_listing_fetch_never_receives_api_key(checker, monkeypatch):
    monkeypatch.setenv("GLAMA_API_KEY", "test-key")
    urlopen = MagicMock()
    urlopen.return_value.__enter__.return_value = io.BytesIO(b"listing")
    monkeypatch.setattr(checker.urllib.request, "urlopen", urlopen)
    assert checker._fetch(checker.DEFAULT_URL, 3) == "listing"
    assert urlopen.call_args.args[0].get_header("Authorization") is None


@pytest.mark.parametrize(
    "filename,step_name",
    [
        ("publish-registries.yml", "Verify Glama listing freshness"),
        ("surface-freshness.yml", "Probe every distribution surface"),
    ],
)
def test_workflows_supply_key_only_to_verification_step(filename, step_name):
    workflow = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
    steps = [step for job in workflow["jobs"].values() for step in job.get("steps", [])]
    wired = [step for step in steps if "GLAMA_API_KEY" in step.get("env", {})]
    assert len(wired) == 1
    assert wired[0]["name"] == step_name
    assert wired[0]["env"]["GLAMA_API_KEY"] == "${{ secrets.GLAMA_API_KEY }}"


def test_authenticated_error_cannot_echo_key(checker, monkeypatch):
    monkeypatch.setenv("GLAMA_API_KEY", "test-key")
    monkeypatch.setattr(checker, "_fetch", MagicMock(side_effect=AssertionError("authenticated API must not use anonymous fetch")))
    opener = MagicMock()
    opener.open.side_effect = checker.urllib.error.HTTPError(checker.DEFAULT_API_URL, 401, "test-key", {}, None)
    monkeypatch.setattr(checker.urllib.request, "build_opener", MagicMock(return_value=opener))
    with pytest.raises(ValueError, match="HTTP 401") as caught:
        checker._fetch_json(checker.DEFAULT_API_URL, 3)
    assert "test-key" not in str(caught.value)


def test_invalid_key_is_rejected_without_echo(checker, monkeypatch):
    monkeypatch.setenv("GLAMA_API_KEY", "private\nkey")
    with pytest.raises(ValueError, match="printable bearer-token") as caught:
        checker._fetch_json(checker.DEFAULT_API_URL, 3)
    assert "private" not in str(caught.value)
