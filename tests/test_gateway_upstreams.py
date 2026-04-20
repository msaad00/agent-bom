"""Tests for UpstreamRegistry — YAML loading + auth resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.gateway_upstreams import (
    UpstreamConfigError,
    UpstreamRegistry,
)


def _write_yaml(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "upstreams.yaml"
    path.write_text(content)
    return path


def test_from_yaml_minimal_http_upstream(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path,
        """
        upstreams:
          - name: filesystem
            url: http://localhost:8100
        """,
    )
    registry = UpstreamRegistry.from_yaml(path)
    assert registry.names() == ["filesystem"]
    upstream = registry.get("filesystem")
    assert upstream is not None
    assert upstream.url == "http://localhost:8100"
    assert upstream.auth == "none"


def test_from_yaml_multiple_upstreams_routable_by_name(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path,
        """
        upstreams:
          - name: jira
            url: https://snowflake.example.internal/mcp/jira
          - name: github
            url: https://mcp.github.example.com/sse
            auth: bearer
            token_env: GITHUB_MCP_TOKEN
        """,
    )
    registry = UpstreamRegistry.from_yaml(path)
    assert registry.names() == ["github", "jira"]
    assert "jira" in registry
    assert "github" in registry
    assert "nope" not in registry


def test_bearer_auth_resolves_token_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_yaml(
        tmp_path,
        """
        upstreams:
          - name: github
            url: https://mcp.github.example.com/sse
            auth: bearer
            token_env: GITHUB_MCP_TOKEN
        """,
    )
    monkeypatch.setenv("GITHUB_MCP_TOKEN", "sekret-token-xyz")
    registry = UpstreamRegistry.from_yaml(path)
    github = registry.get("github")
    assert github is not None
    headers = github.resolved_static_headers()
    assert headers.get("Authorization") == "Bearer sekret-token-xyz"


def test_bearer_auth_missing_token_env_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_yaml(
        tmp_path,
        """
        upstreams:
          - name: github
            url: https://mcp.github.example.com/sse
            auth: bearer
            token_env: MISSING_TOKEN_VAR
        """,
    )
    monkeypatch.delenv("MISSING_TOKEN_VAR", raising=False)
    registry = UpstreamRegistry.from_yaml(path)
    with pytest.raises(UpstreamConfigError, match="is not set"):
        registry.get("github").resolved_static_headers()  # type: ignore[union-attr]


def test_duplicate_upstream_name_rejected(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path,
        """
        upstreams:
          - name: same
            url: https://a.example.com
          - name: same
            url: https://b.example.com
        """,
    )
    with pytest.raises(UpstreamConfigError, match="duplicate"):
        UpstreamRegistry.from_yaml(path)


def test_empty_upstreams_list_rejected(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, "upstreams: []\n")
    with pytest.raises(UpstreamConfigError, match="non-empty"):
        UpstreamRegistry.from_yaml(path)


def test_non_http_url_rejected(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path,
        """
        upstreams:
          - name: bad
            url: stdio:///usr/local/bin/some-mcp
        """,
    )
    with pytest.raises(UpstreamConfigError, match="http"):
        UpstreamRegistry.from_yaml(path)


def test_unsupported_auth_rejected(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path,
        """
        upstreams:
          - name: weird
            url: https://a.example.com
            auth: magic
        """,
    )
    with pytest.raises(UpstreamConfigError, match="unsupported auth"):
        UpstreamRegistry.from_yaml(path)


def test_static_headers_resolved_alongside_bearer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_yaml(
        tmp_path,
        """
        upstreams:
          - name: github
            url: https://mcp.github.example.com/sse
            auth: bearer
            token_env: GH_TOKEN
            headers:
              X-Request-Source: agent-bom-gateway
        """,
    )
    monkeypatch.setenv("GH_TOKEN", "tok")
    registry = UpstreamRegistry.from_yaml(path)
    headers = registry.get("github").resolved_static_headers()  # type: ignore[union-attr]
    assert headers["Authorization"] == "Bearer tok"
    assert headers["X-Request-Source"] == "agent-bom-gateway"
