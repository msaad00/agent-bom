"""Tests for UpstreamRegistry — YAML loading + auth resolution + discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.gateway_upstreams import (
    UpstreamConfig,
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


def test_empty_upstreams_list_builds_empty_registry(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, "upstreams: []\n")
    registry = UpstreamRegistry.from_yaml(path)
    assert registry.names() == []


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


# ─── from_discovery_response + merged_with (fleet-driven auto-discovery) ───


def test_from_discovery_response_builds_registry_with_none_auth() -> None:
    """Discovery payload mirrors the control plane's /v1/gateway/upstreams/discovered shape."""
    payload = {
        "generated_at": "2026-04-20T00:00:00Z",
        "tenant_id": "pilot-acme",
        "source": "fleet_scan_aggregate",
        "upstreams": [
            {"name": "jira", "url": "https://snowflake.example.internal/mcp/jira", "auth": "none"},
            {"name": "github", "url": "https://mcp.github.example.com/sse", "auth": "none"},
        ],
    }
    registry = UpstreamRegistry.from_discovery_response(payload)
    assert registry.names() == ["github", "jira"]
    assert registry.get("jira").auth == "none"  # type: ignore[union-attr]
    # Discovery doesn't know bearer tokens — operator overlays them
    assert registry.get("jira").token_env is None  # type: ignore[union-attr]


def test_from_discovery_response_accepts_empty_upstreams_cleanly() -> None:
    """An empty discovery response produces an empty registry — no error.

    Pilot teams with fleet scans pending may see this briefly; the gateway
    should boot cleanly and serve zero upstreams, not crash.
    """
    registry = UpstreamRegistry.from_discovery_response({"upstreams": []})
    assert registry.names() == []


def test_from_discovery_response_rejects_non_list_upstreams() -> None:
    with pytest.raises(UpstreamConfigError, match="upstreams"):
        UpstreamRegistry.from_discovery_response({"upstreams": "not a list"})


def test_merged_with_overlay_adds_auth_to_discovered_upstream(monkeypatch: pytest.MonkeyPatch) -> None:
    """The key scenario: discovery finds jira at a URL; operator overlays bearer auth."""
    discovered = UpstreamRegistry.from_discovery_response(
        {
            "upstreams": [
                {"name": "jira", "url": "https://snowflake.example.internal/mcp/jira", "auth": "none"},
            ]
        }
    )

    operator_overlay = UpstreamRegistry(
        [
            UpstreamConfig(
                name="jira",
                url="https://snowflake.example.internal/mcp/jira",
                auth="bearer",
                token_env="SNOWFLAKE_JIRA_MCP_TOKEN",
            )
        ]
    )

    merged = discovered.merged_with(operator_overlay)
    assert merged.names() == ["jira"]
    jira = merged.get("jira")
    assert jira is not None
    assert jira.auth == "bearer"
    assert jira.token_env == "SNOWFLAKE_JIRA_MCP_TOKEN"

    # Resolving headers now works because the overlay wired the env var name.
    monkeypatch.setenv("SNOWFLAKE_JIRA_MCP_TOKEN", "sf-token")
    headers = jira.resolved_static_headers()
    assert headers["Authorization"] == "Bearer sf-token"


def test_merged_with_overlay_adds_new_upstreams_not_in_discovery() -> None:
    """Operator can add upstreams discovery doesn't know about (yet)."""
    discovered = UpstreamRegistry.from_discovery_response({"upstreams": [{"name": "jira", "url": "https://a.example.com", "auth": "none"}]})
    overlay = UpstreamRegistry([UpstreamConfig(name="custom-internal", url="http://custom.svc.cluster.local:8000")])
    merged = discovered.merged_with(overlay)
    assert sorted(merged.names()) == ["custom-internal", "jira"]


def test_tenant_scoped_registry_routes_same_name_to_tenant_specific_upstream() -> None:
    registry = UpstreamRegistry(
        [
            UpstreamConfig(name="jira", tenant_id="tenant-alpha", url="https://alpha.example.com/mcp"),
            UpstreamConfig(name="jira", tenant_id="tenant-beta", url="https://beta.example.com/mcp"),
        ]
    )
    alpha = registry.get("jira", tenant_id="tenant-alpha")
    beta = registry.get("jira", tenant_id="tenant-beta")
    assert alpha is not None
    assert beta is not None
    assert alpha.url == "https://alpha.example.com/mcp"
    assert beta.url == "https://beta.example.com/mcp"
    assert registry.names(tenant_id="tenant-alpha") == ["jira"]
    assert registry.names(tenant_id="tenant-beta") == ["jira"]


def test_tenant_scoped_registry_fails_closed_on_cross_tenant_fallback() -> None:
    registry = UpstreamRegistry(
        [
            UpstreamConfig(name="jira", tenant_id="tenant-alpha", url="https://alpha.example.com/mcp"),
            UpstreamConfig(name="jira", url="https://legacy-global.example.com/mcp"),
        ]
    )
    assert registry.get("jira", tenant_id="tenant-alpha") is not None
    # A different tenant must not silently fall through to the global route
    # once a tenant-bound upstream exists for this name.
    assert registry.get("jira", tenant_id="tenant-beta") is None


# ─── OAuth2 client-credentials ─────────────────────────────────────────────


def test_oauth2_fetches_token_and_caches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two resolve calls must share the cached token instead of double-fetching."""
    import asyncio

    import httpx

    from agent_bom.gateway_upstreams import reset_oauth_cache_for_tests

    reset_oauth_cache_for_tests()

    fetch_count = {"n": 0}

    class _FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"access_token": "oauth-tok-123", "expires_in": 3600, "token_type": "Bearer"}

    class _FakeAsyncClient:
        def __init__(self, *_, **__):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def post(self, *_args, **_kwargs):
            fetch_count["n"] += 1
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setenv("SF_CLIENT_ID", "cid")
    monkeypatch.setenv("SF_CLIENT_SECRET", "csec")

    path = _write_yaml(
        tmp_path,
        """
        upstreams:
          - name: jira-snowflake
            url: https://snowflake.example.com/mcp/jira
            auth: oauth2_client_credentials
            oauth_token_url: https://snowflake.example.com/oauth/token
            oauth_client_id_env: SF_CLIENT_ID
            oauth_client_secret_env: SF_CLIENT_SECRET
            scopes: ["jira.read", "jira.write"]
        """,
    )
    registry = UpstreamRegistry.from_yaml(path)
    upstream = registry.get("jira-snowflake")
    assert upstream is not None

    headers_a = asyncio.run(upstream.resolve_auth_headers())
    headers_b = asyncio.run(upstream.resolve_auth_headers())
    assert headers_a["Authorization"] == "Bearer oauth-tok-123"
    assert headers_b["Authorization"] == "Bearer oauth-tok-123"
    assert fetch_count["n"] == 1, "token must be cached across resolve calls within expiry"


def test_oauth2_concurrent_cache_miss_uses_singleflight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Concurrent first callers should share one IdP token request."""
    import asyncio

    import httpx

    from agent_bom.gateway_upstreams import reset_oauth_cache_for_tests

    reset_oauth_cache_for_tests()

    fetch_count = {"n": 0}

    class _FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"access_token": "oauth-tok-singleflight", "expires_in": 3600, "token_type": "Bearer"}

    class _FakeAsyncClient:
        def __init__(self, *_, **__):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def post(self, *_args, **_kwargs):
            fetch_count["n"] += 1
            await asyncio.sleep(0.01)
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setenv("SF_CLIENT_ID", "cid")
    monkeypatch.setenv("SF_CLIENT_SECRET", "csec")

    path = _write_yaml(
        tmp_path,
        """
        upstreams:
          - name: jira-snowflake
            url: https://snowflake.example.com/mcp/jira
            auth: oauth2_client_credentials
            oauth_token_url: https://snowflake.example.com/oauth/token
            oauth_client_id_env: SF_CLIENT_ID
            oauth_client_secret_env: SF_CLIENT_SECRET
            scopes: ["jira.read", "jira.write"]
        """,
    )
    registry = UpstreamRegistry.from_yaml(path)
    upstream = registry.get("jira-snowflake")
    assert upstream is not None

    async def _resolve_many() -> list[dict[str, str]]:
        return await asyncio.gather(*(upstream.resolve_auth_headers() for _ in range(8)))

    headers = asyncio.run(_resolve_many())
    assert {h["Authorization"] for h in headers} == {"Bearer oauth-tok-singleflight"}
    assert fetch_count["n"] == 1


def test_oauth2_missing_env_vars_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from agent_bom.gateway_upstreams import reset_oauth_cache_for_tests

    reset_oauth_cache_for_tests()
    monkeypatch.delenv("SF_CLIENT_ID", raising=False)
    monkeypatch.delenv("SF_CLIENT_SECRET", raising=False)

    path = _write_yaml(
        tmp_path,
        """
        upstreams:
          - name: jira-snowflake
            url: https://snowflake.example.com/mcp/jira
            auth: oauth2_client_credentials
            oauth_token_url: https://snowflake.example.com/oauth/token
            oauth_client_id_env: SF_CLIENT_ID
            oauth_client_secret_env: SF_CLIENT_SECRET
        """,
    )
    registry = UpstreamRegistry.from_yaml(path)
    upstream = registry.get("jira-snowflake")
    assert upstream is not None
    with pytest.raises(UpstreamConfigError, match="not set"):
        asyncio.run(upstream.resolve_auth_headers())


def test_oauth2_missing_required_fields_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from agent_bom.gateway_upstreams import reset_oauth_cache_for_tests

    reset_oauth_cache_for_tests()
    path = _write_yaml(
        tmp_path,
        """
        upstreams:
          - name: jira-broken
            url: https://snowflake.example.com/mcp/jira
            auth: oauth2_client_credentials
            # no oauth_token_url / env names
        """,
    )
    registry = UpstreamRegistry.from_yaml(path)
    upstream = registry.get("jira-broken")
    assert upstream is not None
    with pytest.raises(UpstreamConfigError, match="requires oauth_token_url"):
        asyncio.run(upstream.resolve_auth_headers())


def test_fetch_discovered_upstreams_hits_expected_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit-level check that the client hits /v1/gateway/upstreams/discovered with the bearer."""
    from agent_bom.gateway_upstreams import fetch_discovered_upstreams

    captured = {}

    class _FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"upstreams": []}

    def fake_get(url, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers or {}
        captured["timeout"] = timeout
        return _FakeResponse()

    import httpx

    monkeypatch.setattr(httpx, "get", fake_get)
    result = fetch_discovered_upstreams("https://agent-bom.example.com/", token="abc")
    assert captured["url"] == "https://agent-bom.example.com/v1/gateway/upstreams/discovered"
    assert captured["headers"]["Authorization"] == "Bearer abc"
    assert captured["timeout"] == 10.0
    assert result == {"upstreams": []}
