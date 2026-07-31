"""Cold deep-links into the SPA must not 401.

The public-route allowlist used to be a hand-maintained set that drifted from
``ui/app/``: ``/overview`` (the header CTA and left-nav target), ``/inventory``,
``/reports``, ``/runtime``, ``/threat-intel``, ``/self-posture``,
``/blueprints``, ``/integrations`` and ``/accounts/*`` returned a raw JSON 401
on a cold request, while ``/settings`` and ``/dashboard`` — which do not exist —
returned 200. It only worked because landing on ``/`` first set the session
cookie. The allowlist is now derived from the same shipped dashboard files the
SPA catch-all resolves against.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.api import middleware as middleware_module
from agent_bom.api.middleware import APIKeyMiddleware, dashboard_spa_routes_from_files

UI_APP = Path(__file__).resolve().parents[2] / "ui" / "app"

# Routes the audit proved were unreachable cold. Kept explicit so a regression
# names the page that broke rather than a set difference.
REGRESSION_ROUTES = (
    "/overview",
    "/inventory",
    "/reports",
    "/runtime",
    "/threat-intel",
    "/self-posture",
    "/blueprints",
    "/integrations",
    "/accounts/aws-prod",
)


def _exported_relative_paths() -> list[str]:
    """Approximate a Next.js static export of ``ui/app`` (one page per route)."""
    paths = ["index.html", "404.html", "favicon.ico"]
    for entry in sorted(UI_APP.iterdir()):
        if entry.is_dir() and not entry.name.startswith(("_", "(")):
            paths.append(f"{entry.name}/index.html")
    return paths


@pytest.fixture
def _registered_spa_routes(monkeypatch):
    monkeypatch.setattr(
        middleware_module,
        "_DASHBOARD_SPA_ROUTES",
        dashboard_spa_routes_from_files(_exported_relative_paths()),
    )


def test_ui_app_route_directories_are_discovered() -> None:
    routes = dashboard_spa_routes_from_files(_exported_relative_paths())
    assert "" in routes
    assert "overview" in routes
    assert "findings" in routes


def test_every_shipped_ui_route_is_reachable_on_a_cold_deep_link(_registered_spa_routes) -> None:
    unreachable = [
        entry.name
        for entry in sorted(UI_APP.iterdir())
        if entry.is_dir()
        and not entry.name.startswith(("_", "("))
        and not APIKeyMiddleware._is_dashboard_public_request(f"/{entry.name}", "GET")
    ]
    assert unreachable == []


@pytest.mark.parametrize("path", REGRESSION_ROUTES)
def test_audited_deep_links_are_public(path: str, _registered_spa_routes) -> None:
    assert APIKeyMiddleware._is_dashboard_public_request(path, "GET") is True


def test_root_and_index_stay_public(_registered_spa_routes) -> None:
    assert APIKeyMiddleware._is_dashboard_public_request("/", "GET") is True
    assert APIKeyMiddleware._is_dashboard_public_request("/index.html", "GET") is True


def test_routes_that_do_not_exist_are_not_public(_registered_spa_routes) -> None:
    """``/settings`` and ``/dashboard`` have no page; they must not be allowlisted."""
    assert APIKeyMiddleware._is_dashboard_public_request("/settings", "GET") is False
    assert APIKeyMiddleware._is_dashboard_public_request("/dashboard", "GET") is False


def test_api_paths_are_never_treated_as_dashboard_routes(_registered_spa_routes) -> None:
    assert APIKeyMiddleware._is_dashboard_public_request("/v1/findings", "GET") is False
    assert APIKeyMiddleware._is_dashboard_public_request("/metrics", "GET") is False
    assert APIKeyMiddleware._is_dashboard_public_request("/overview", "POST") is False


def test_mounting_the_dashboard_registers_the_allowlist(tmp_path: Path, monkeypatch) -> None:
    """The wiring, not just the derivation: mounting publishes the allowlist.

    Mirrors a Next.js ``output: export`` layout (``trailingSlash`` is unset, so
    a page becomes ``<route>.html`` and a dynamic segment becomes
    ``<route>/<param>.html``).
    """
    from fastapi import FastAPI

    from agent_bom.api import server as server_module

    ui_dist = tmp_path / "ui_dist"
    (ui_dist / "accounts").mkdir(parents=True)
    (ui_dist / "_next" / "static").mkdir(parents=True)
    (ui_dist / "index.html").write_text("<html></html>")
    (ui_dist / "overview.html").write_text("<html></html>")
    (ui_dist / "findings.html").write_text("<html></html>")
    (ui_dist / "accounts" / "_.html").write_text("<html></html>")
    (ui_dist / "_next" / "static" / "app.js").write_text("//")

    monkeypatch.setattr(middleware_module, "_DASHBOARD_SPA_ROUTES", frozenset())
    monkeypatch.setattr(server_module, "_dashboard_dist_dir", lambda: ui_dist)
    monkeypatch.delenv("AGENT_BOM_NO_UI", raising=False)
    server_module._mount_dashboard(FastAPI())

    assert APIKeyMiddleware._is_dashboard_public_request("/overview", "GET") is True
    assert APIKeyMiddleware._is_dashboard_public_request("/accounts/aws-prod", "GET") is True
    assert APIKeyMiddleware._is_dashboard_public_request("/", "GET") is True
    assert APIKeyMiddleware._is_dashboard_public_request("/settings", "GET") is False
    assert APIKeyMiddleware._is_dashboard_public_request("/_next/static/app.js", "GET") is True


def test_no_spa_mounted_means_no_public_spa_routes(monkeypatch) -> None:
    """A REST-only deployment has no SPA to serve, so nothing is allowlisted."""
    monkeypatch.setattr(middleware_module, "_DASHBOARD_SPA_ROUTES", frozenset())
    assert APIKeyMiddleware._is_dashboard_public_request("/overview", "GET") is False
    # Static asset routes that do not depend on the SPA stay public.
    assert APIKeyMiddleware._is_dashboard_public_request("/favicon.ico", "GET") is True
    assert APIKeyMiddleware._is_dashboard_public_request("/_next/static/x.js", "GET") is True
