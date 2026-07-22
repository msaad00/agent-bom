"""Tests for GitHub repo trust-card fetch + graph overlay."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.repo_trust_overlay import apply_repo_trust_overlay
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import to_json
from agent_bom.repo_scan import fetch_repo_trust, parse_github_owner_repo


@pytest.fixture(autouse=True)
def _stub_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def _gai(host, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("140.82.112.3", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _gai)


def test_parse_github_owner_repo() -> None:
    assert parse_github_owner_repo("https://github.com/msaad00/agent-bom") == ("msaad00", "agent-bom")
    assert parse_github_owner_repo("https://github.com/msaad00/agent-bom.git") == ("msaad00", "agent-bom")
    assert parse_github_owner_repo("https://gitlab.com/org/repo") is None


def test_fetch_repo_trust_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent_bom.config.REPO_TRUST_ENABLED", False)
    assert fetch_repo_trust("https://github.com/msaad00/agent-bom") is None


def test_fetch_repo_trust_unsupported_host() -> None:
    card = fetch_repo_trust("https://gitlab.com/org/repo")
    assert card is not None
    assert card["status"] == "unsupported_host"
    assert card["host"] == "gitlab.com"


def test_fetch_repo_trust_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        status_code = 200
        headers = {"Link": '<https://api.github.com/repositories/1/contributors?per_page=1&page=42>; rel="last"'}

        @staticmethod
        def json() -> list[dict[str, str]]:
            return [{"login": "a"}]

    def _fake_fetch(url: str, **kwargs: Any) -> dict[str, Any]:
        assert "api.github.com/repos/acme/demo" in url
        return {
            "html_url": "https://github.com/acme/demo",
            "clone_url": "https://github.com/acme/demo.git",
            "full_name": "acme/demo",
            "description": "A demo repository used in tests",
            "language": "Python",
            "license": {"spdx_id": "Apache-2.0"},
            "default_branch": "main",
            "stargazers_count": 12,
            "forks_count": 3,
            "subscribers_count": 5,
            "open_issues_count": 1,
            "pushed_at": "2026-07-01T00:00:00Z",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2026-07-01T00:00:00Z",
            "visibility": "public",
            "archived": False,
            "fork": False,
            "topics": ["security", "mcp"],
            "homepage": "https://example.com",
        }

    monkeypatch.setattr("agent_bom.http_client.fetch_json", _fake_fetch)
    monkeypatch.setattr("agent_bom.http_client.sync_get", lambda *a, **k: _Resp())

    card = fetch_repo_trust("https://github.com/acme/demo")
    assert card is not None
    assert card["status"] == "ok"
    assert card["stars"] == 12
    assert card["contributors"] == 42
    assert card["license"] == "Apache-2.0"
    assert card["language"] == "Python"
    assert "security" in card["topics"]


def test_report_json_includes_repo_trust() -> None:
    report = AIBOMReport(agents=[], blast_radii=[])
    report.repo_trust_data = {
        "status": "ok",
        "full_name": "acme/demo",
        "stars": 9,
        "repo_url": "https://github.com/acme/demo",
    }
    report.project_inventory_data = {"manifest_files": 1, "package_count": 2}
    payload = to_json(report)
    assert payload["repo_trust"]["stars"] == 9
    assert payload["project_inventory"]["repo_trust"]["full_name"] == "acme/demo"


def test_repo_trust_overlay_creates_application() -> None:
    g = UnifiedGraph(scan_id="t1")
    g.add_node(
        UnifiedNode(
            id="directory:.",
            entity_type=EntityType.DIRECTORY,
            label=".",
            attributes={"path": "."},
        )
    )
    counts = apply_repo_trust_overlay(
        g,
        {
            "repo_trust": {
                "status": "ok",
                "full_name": "acme/demo",
                "repo_url": "https://github.com/acme/demo",
                "stars": 7,
                "contributors": 3,
                "license": "MIT",
            }
        },
        datetime.now(timezone.utc),
    )
    assert counts["applications"] == 1
    assert counts["directory_stamps"] == 1
    app = g.nodes["application:repo:acme/demo"]
    assert app.entity_type == EntityType.APPLICATION
    assert app.attributes["stars"] == 7
    assert g.nodes["directory:."].attributes["stars"] == 7


def test_builder_wires_repo_trust() -> None:
    g = build_unified_graph_from_report(
        {
            "project_inventory": {
                "directories": [{"path": ".", "manifest_files": ["pyproject.toml"], "lockfiles": [], "declaration_files": []}],
            },
            "repo_trust": {
                "status": "ok",
                "full_name": "acme/demo",
                "repo_url": "https://github.com/acme/demo",
                "stars": 4,
            },
        }
    )
    assert "application:repo:acme/demo" in g.nodes
    # repo-structure should have placed the root directory
    if "directory:." in g.nodes:
        assert g.nodes["directory:."].attributes.get("stars") == 4
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    # no accidental CONTAINS invented solely by trust
    assert not any(e.relationship == RelationshipType.CONTAINS and e.source.startswith("application:") for e in edges)


def test_fetch_unavailable_on_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(url: str, **kwargs: Any) -> dict[str, Any]:
        raise ConnectionError("down")

    monkeypatch.setattr("agent_bom.http_client.fetch_json", _boom)
    card = fetch_repo_trust("https://github.com/acme/demo")
    assert card is not None
    assert card["status"] == "unavailable"
    assert card["full_name"] == "acme/demo"
