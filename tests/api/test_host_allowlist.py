"""Host-header allowlist and browser-origin checks for the control-plane API.

A loopback ``agent-bom serve`` must only answer requests whose Host header is a
loopback name, so a page that rebinds its own DNS name to 127.0.0.1 cannot
reach the dashboard bootstrap or mint a session. Cookie-authenticated writes
additionally require a trusted ``Origin`` (or ``Sec-Fetch-Site: same-origin``).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.responses import Response

from agent_bom.api import server
from agent_bom.api.browser_session import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME
from agent_bom.api.host_guard import HostPolicy, build_host_policy, hostname_from_authority
from agent_bom.cli._server import _generate_dev_api_key

_AUTH_ENV = (
    "AGENT_BOM_API_KEY",
    "AGENT_BOM_API_KEYS",
    "AGENT_BOM_OIDC_ISSUER",
    "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
    "AGENT_BOM_TRUST_PROXY_AUTH",
    "AGENT_BOM_SCIM_BEARER_TOKEN",
    "AGENT_BOM_ALLOW_UNAUTHENTICATED_API",
    "AGENT_BOM_NO_AUTH_ROLE",
    "AGENT_BOM_API_ALLOWED_HOSTS",
    "AGENT_BOM_API_HOST",
    "AGENT_BOM_NO_UI",
)


@pytest.fixture
def loopback_dev(monkeypatch, tmp_path):
    """Reproduce a zero-config loopback ``agent-bom serve`` with a bundled UI.

    Configuration happens lazily on first use so the shared conftest auth-env
    resync (which runs after fixture setup) cannot overwrite the listener.
    """
    for name in _AUTH_ENV:
        monkeypatch.delenv(name, raising=False)
    index = tmp_path / "index.html"
    index.write_text("<!doctype html><html><body>dashboard</body></html>", encoding="utf-8")
    monkeypatch.setattr(server, "_dashboard_index_file", lambda: server._DashboardFile(path=index, relative_path="index.html"))
    key = _generate_dev_api_key()

    def start() -> str:
        server.set_dev_api_key(key)
        server.configure_api(api_key=key, listener_host="127.0.0.1")
        return key

    yield start
    server.set_dev_api_key(None)
    server.configure_api(api_key=None)


def _set_cookie_headers(response) -> list[str]:
    return response.headers.get_list("set-cookie")


def test_rebinding_sequence_is_rejected_at_the_first_request(loopback_dev):
    loopback_dev()
    attacker = TestClient(server.app, base_url="http://evil.example:8422")

    bootstrap = attacker.get("/")
    assert bootstrap.status_code == 400
    assert _set_cookie_headers(bootstrap) == []
    assert SESSION_COOKIE_NAME not in attacker.cookies

    # Even a forged session cookie never reaches the key-minting route.
    create = attacker.post(
        "/v1/auth/keys",
        json={"name": "pwn", "role": "admin"},
        headers={"Origin": "http://evil.example:8422", CSRF_HEADER_NAME: "x"},
    )
    assert create.status_code == 400
    assert "raw_key" not in create.text


@pytest.mark.parametrize("authority", ["127.0.0.1:8422", "localhost:8422", "[::1]:8422", "LOCALHOST:9999"])
def test_loopback_hosts_complete_the_dashboard_flow(loopback_dev, authority):
    loopback_dev()
    client = TestClient(server.app, base_url="http://127.0.0.1:8422", headers={"host": authority})

    bootstrap = client.get("/")
    assert bootstrap.status_code == 200
    assert "dashboard" in bootstrap.text
    csrf = client.cookies.get(CSRF_COOKIE_NAME)
    assert csrf and client.cookies.get(SESSION_COOKIE_NAME)

    create = client.post(
        "/v1/auth/keys",
        json={"name": "ci", "role": "viewer"},
        headers={"Origin": f"http://{authority}", CSRF_HEADER_NAME: csrf},
    )
    assert create.status_code == 201, create.text
    assert create.json()["role"] == "viewer"


def test_cookie_write_with_foreign_origin_is_forbidden(loopback_dev):
    loopback_dev()
    client = TestClient(server.app, base_url="http://127.0.0.1:8422")
    client.get("/")
    csrf = client.cookies.get(CSRF_COOKIE_NAME)
    assert csrf

    foreign = client.post(
        "/v1/auth/keys",
        json={"name": "x", "role": "viewer"},
        headers={"Origin": "https://evil.example", CSRF_HEADER_NAME: csrf},
    )
    assert foreign.status_code == 403
    assert "origin" in foreign.text.lower()

    null_origin = client.post(
        "/v1/auth/keys",
        json={"name": "x", "role": "viewer"},
        headers={"Origin": "null", CSRF_HEADER_NAME: csrf},
    )
    assert null_origin.status_code == 403

    no_origin = client.post("/v1/auth/keys", json={"name": "x", "role": "viewer"}, headers={CSRF_HEADER_NAME: csrf})
    assert no_origin.status_code == 403

    cross_site = client.post(
        "/v1/auth/keys",
        json={"name": "x", "role": "viewer"},
        headers={"Sec-Fetch-Site": "cross-site", CSRF_HEADER_NAME: csrf},
    )
    assert cross_site.status_code == 403

    same_origin = client.post(
        "/v1/auth/keys",
        json={"name": "x", "role": "viewer"},
        headers={"Sec-Fetch-Site": "same-origin", CSRF_HEADER_NAME: csrf},
    )
    assert same_origin.status_code == 201, same_origin.text


def test_local_next_dev_origin_is_trusted_for_cookie_writes(loopback_dev):
    """The Next dev server proxies to the API; its Origin is a loopback UI port."""
    loopback_dev()
    client = TestClient(server.app, base_url="http://localhost:8422")
    client.get("/")
    csrf = client.cookies.get(CSRF_COOKIE_NAME)
    response = client.post(
        "/v1/auth/keys",
        json={"name": "ui", "role": "viewer"},
        headers={"Origin": "http://localhost:3000", CSRF_HEADER_NAME: csrf},
    )
    assert response.status_code == 201, response.text


def test_bearer_requests_are_unaffected_by_origin(loopback_dev):
    dev_key = loopback_dev()
    client = TestClient(server.app, base_url="http://127.0.0.1:8422")
    response = client.post(
        "/v1/auth/keys",
        json={"name": "automation", "role": "viewer"},
        headers={"Authorization": f"Bearer {dev_key}", "Origin": "https://elsewhere.example"},
    )
    assert response.status_code == 201, response.text


def test_bearer_requests_still_need_an_allowed_host(loopback_dev):
    dev_key = loopback_dev()
    client = TestClient(server.app, base_url="http://evil.example:8422")
    response = client.get("/v1/overview", headers={"Authorization": f"Bearer {dev_key}"})
    assert response.status_code == 400


def test_dev_session_cookie_is_only_minted_for_loopback_hosts(loopback_dev):
    loopback_dev()
    for host, expected in (("127.0.0.1:8422", True), ("evil.example:8422", False), ("", False)):
        response = Response()
        server._maybe_attach_dev_session_cookie(response, SimpleNamespace(cookies={}, headers={"host": host}))
        minted = any(value.decode().startswith(f"{SESSION_COOKIE_NAME}=") for key, value in response.raw_headers if key == b"set-cookie")
        assert minted is expected, host


def test_insecure_no_auth_loopback_is_also_host_guarded(monkeypatch):
    for name in _AUTH_ENV:
        monkeypatch.delenv(name, raising=False)
    try:
        server.configure_api(api_key=None, allow_unauthenticated=True, listener_host="127.0.0.1")
        assert TestClient(server.app, base_url="http://evil.example:8422").get("/v1/overview").status_code == 400
        assert TestClient(server.app, base_url="http://127.0.0.1:8422").get("/v1/overview").status_code == 200
    finally:
        server.configure_api(api_key=None)


def test_non_loopback_listener_honors_configured_allowlist(monkeypatch):
    for name in _AUTH_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AGENT_BOM_API_ALLOWED_HOSTS", "agentbom.example.com, *.internal.example")
    try:
        server.configure_api(api_key="test-key-123", listener_host="0.0.0.0")
        auth = {"Authorization": "Bearer test-key-123"}
        for allowed in ("agentbom.example.com", "AgentBom.Example.com:443", "api.internal.example", "localhost:8422"):
            assert TestClient(server.app, base_url=f"http://{allowed}").get("/v1/overview", headers=auth).status_code == 200, allowed
        for denied in ("evil.example", "internal.example", "agentbom.example.com.evil.example"):
            assert TestClient(server.app, base_url=f"http://{denied}").get("/v1/overview", headers=auth).status_code == 400, denied
        # Orchestrator probes connect by pod IP; liveness/readiness stay reachable.
        probe = TestClient(server.app, base_url="http://10.12.0.7:8422")
        assert probe.get("/healthz").status_code == 200
        assert probe.get("/health").status_code == 200
        assert probe.get("/v1/overview", headers=auth).status_code == 400
    finally:
        server.configure_api(api_key=None)


def test_non_loopback_listener_without_allowlist_keeps_accepting_any_host(monkeypatch):
    for name in _AUTH_ENV:
        monkeypatch.delenv(name, raising=False)
    try:
        server.configure_api(api_key="test-key-123", listener_host="0.0.0.0")
        response = TestClient(server.app, base_url="http://api.example.org").get(
            "/v1/overview", headers={"Authorization": "Bearer test-key-123"}
        )
        assert response.status_code == 200
    finally:
        server.configure_api(api_key=None)


def test_proxied_ui_origin_matches_forwarded_host_when_any_host_is_allowed(monkeypatch):
    """A separately deployed UI proxies to the API service; the API sees the
    service Host while the browser Origin names the public UI host."""
    from agent_bom.api.host_guard import browser_origin_trusted

    policy = build_host_policy("0.0.0.0", "", trusted_origins=())
    headers = {"host": "api:8422", "x-forwarded-host": "ui.example.com", "origin": "https://ui.example.com"}
    assert browser_origin_trusted(headers, policy) is True
    assert browser_origin_trusted({**headers, "origin": "https://evil.example"}, policy) is False


@pytest.mark.parametrize(
    ("authority", "expected"),
    [
        ("127.0.0.1:8422", "127.0.0.1"),
        ("[::1]:8422", "::1"),
        ("[::1]", "::1"),
        ("Example.COM", "example.com"),
        ("example.com:", "example.com"),
        ("", None),
        ("[::1", None),
        ("exa mple.com", None),
        ("example.com:80:80", None),
    ],
)
def test_hostname_from_authority(authority, expected):
    assert hostname_from_authority(authority) == expected


def test_policy_modes():
    assert build_host_policy("127.0.0.1", "", trusted_origins=()).mode == "loopback"
    assert build_host_policy("::1", "", trusted_origins=()).mode == "loopback"
    assert build_host_policy("0.0.0.0", "", trusted_origins=()).mode == "any"
    assert build_host_policy(None, "", trusted_origins=()).mode == "any"
    assert build_host_policy("0.0.0.0", "*", trusted_origins=()).mode == "any"
    configured = build_host_policy("127.0.0.1", "dev.example", trusted_origins=())
    assert configured.mode == "allowlist"
    assert configured.allows("dev.example") and configured.allows("127.0.0.1") and not configured.allows("x.example")
    assert isinstance(configured, HostPolicy)
