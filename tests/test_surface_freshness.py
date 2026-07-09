"""Regression tests for public marketplace freshness automation."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str) -> ModuleType:
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_glama_listing_json_contract_reports_stale_listing(monkeypatch, capsys):
    script = _load_script("check_glama_listing.py")
    stale_page = """
    uses: msaad00/agent-bom@v0.88.4
    MCP server mode advertises 55 MCP tools
    18 tools for CVE scanning
    git checkout 98c3e543
    """

    monkeypatch.setattr(script, "_load_readme_tool_count", lambda: "69")
    monkeypatch.setattr(script, "_fetch", lambda _url, _timeout: stale_page)

    assert script.main(["--expected", "0.89.2", "--json", "--retries", "1"]) == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip().splitlines()[-1])

    assert payload["surface"] == "Glama"
    assert payload["status"] == "stale"
    assert payload["expected"] == "0.89.2"
    assert payload["listing_version"] == "0.88.4"
    assert "missing current Glama listing token" in payload["error"]


def test_glama_build_manifest_verify_passes():
    script = _load_script("check_glama_listing.py")
    assert script.main(["--verify-manifest"]) == 0


def test_glama_build_manifest_verify_reads_git_ref():
    script = _load_script("check_glama_listing.py")
    assert script.main(["--verify-manifest", "--git-ref", "HEAD"]) == 0


def test_glama_build_manifest_verify_falls_back_for_head_checkout(monkeypatch):
    script = _load_script("check_glama_listing.py")

    def fake_check_output(*_args, **_kwargs):
        raise subprocess.CalledProcessError(128, ["git", "show"], stderr="not a git repository")

    monkeypatch.setattr(script.subprocess, "check_output", fake_check_output)

    assert script.main(["--verify-manifest", "--git-ref", "HEAD"]) == 0


def test_glama_build_manifest_verify_rejects_missing_dockerfile(monkeypatch):
    script = _load_script("check_glama_listing.py")
    monkeypatch.setattr(script, "GLAMA_DOCKERFILE", "integrations/glama/does-not-exist.dockerfile")
    failures = script.verify_build_manifest()
    assert any("missing Glama Dockerfile" in failure for failure in failures)


def test_surface_freshness_reads_smithery_catalog_listing(monkeypatch):
    script = _load_script("check_surface_freshness.py")

    def fake_http_json(url, **_kwargs):
        assert url == "https://api.smithery.ai/servers/agent-bom/agent-bom"
        return {
            "qualifiedName": "agent-bom/agent-bom",
            "remote": True,
            "deploymentUrl": "https://agent-bom--agent-bom.run.tools",
            "tools": [{"name": "scan"}, {"name": "check"}],
        }

    monkeypatch.setattr(script, "_http_json", fake_http_json)

    result = script.probe_smithery("0.89.2", "agent-bom/agent-bom", timeout=1, attempts=1, backoff=0)

    assert result["surface"] == "Smithery"
    assert result["status"] == "fresh"
    assert result["version"] == "catalog-live"
    assert result["deployment_url"] == "https://agent-bom--agent-bom.run.tools"
    assert result["tool_count"] == 2


def test_surface_freshness_reads_paginated_ghcr_tags(monkeypatch):
    script = _load_script("check_surface_freshness.py")

    class Headers(dict):
        def get(self, key, default=None):
            return super().get(key, default)

    def fake_http_json(url, **_kwargs):
        assert url.startswith("https://ghcr.io/token?")
        return {"token": "token"}

    pages = iter(
        [
            (
                {"tags": ["v0.81.1"]},
                Headers({"Link": '</v2/msaad00/agent-bom/tags/list?last=v0.81.1&n=100>; rel="next"'}),
            ),
            ({"tags": ["v0.89.2"]}, Headers({})),
        ]
    )

    def fake_http_json_response(url, **kwargs):
        assert kwargs["headers"] == {"Authorization": "Bearer token"}
        assert url.startswith("https://ghcr.io/v2/msaad00/agent-bom/tags/list")
        return next(pages)

    monkeypatch.setattr(script, "_http_json", fake_http_json)
    monkeypatch.setattr(script, "_http_json_response", fake_http_json_response)

    result = script.probe_docker("0.89.2", "ghcr.io/msaad00/agent-bom", timeout=1, attempts=1, backoff=0)

    assert result["surface"] == "Docker"
    assert result["status"] == "fresh"
    assert result["version"] == "0.89.2"
