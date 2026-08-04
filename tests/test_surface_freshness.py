"""Regression tests for public marketplace freshness automation."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import urllib.error
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
    monkeypatch.setattr(
        script,
        "_fetch_json",
        lambda _url, _timeout: {"tools": [{"name": f"tool_{index}"} for index in range(69)]},
    )

    assert script.main(["--expected", "0.89.2", "--json", "--retries", "1"]) == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip().splitlines()[-1])

    assert payload["surface"] == "Glama"
    assert payload["status"] == "stale"
    assert payload["expected"] == "0.89.2"
    assert payload["listing_version"] == "0.88.4"
    assert "missing current Glama listing token" in payload["error"]


def test_glama_listing_requires_public_api_tool_inventory(monkeypatch, capsys):
    """Rendered README claims do not substitute for Glama-indexed MCP tools."""
    script = _load_script("check_glama_listing.py")
    current_page = "v0.98.2 MCP server mode exposes 77 MCP tools"

    monkeypatch.setattr(script, "_fetch", lambda _url, _timeout: current_page)
    monkeypatch.setattr(script, "_fetch_json", lambda _url, _timeout: {"tools": []})

    assert script.main(["--expected", "0.98.2", "--expected-tool-count", "77", "--json", "--retries", "1"]) == 1
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "stale"
    assert payload["tool_count"] == 0
    assert payload["expected_tool_count"] == 77
    assert "public API exposes 0 tools; expected 77" in payload["error"]


def test_glama_listing_accepts_exact_public_api_tool_inventory(monkeypatch, capsys):
    script = _load_script("check_glama_listing.py")
    current_page = "v0.98.2 MCP server mode exposes 77 MCP tools"

    monkeypatch.setattr(script, "_fetch", lambda _url, _timeout: current_page)
    monkeypatch.setattr(
        script,
        "_fetch_json",
        lambda _url, _timeout: {"tools": [{"name": f"tool_{index}"} for index in range(77)]},
    )

    assert script.main(["--expected", "0.98.2", "--expected-tool-count", "77", "--json", "--retries", "1"]) == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "fresh"
    assert payload["tool_count"] == 77
    assert payload["expected_tool_count"] == 77


def test_glama_listing_accepts_exact_public_schema_when_directory_api_is_empty(monkeypatch, capsys):
    """The rendered Schema inventory is evidence even when the directory API lags."""
    script = _load_script("check_glama_listing.py")
    current_page = "v0.98.3 MCP server mode exposes 77 MCP tools"
    schema_page = "".join(
        f'<a href="/mcp/servers/msaad00/agent-bom/tools/tool_{index}">tool_{index}</a>'
        for index in range(77)
    )

    def fetch(url, _timeout):
        return schema_page if url.endswith("/schema") else current_page

    monkeypatch.setattr(script, "_fetch", fetch)
    monkeypatch.setattr(script, "_fetch_json", lambda _url, _timeout: {"tools": []})

    assert script.main(["--expected", "0.98.3", "--expected-tool-count", "77", "--json", "--retries", "1"]) == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "fresh"
    assert payload["tool_count"] == 77
    assert payload["inventory_source"] == "schema"


def test_glama_listing_checks_visible_copy_not_hidden_stale_metadata(monkeypatch, capsys):
    """Serialized metadata must not masquerade as user-visible stale copy."""
    script = _load_script("check_glama_listing.py")
    current_page = """
    <html>
      <head><meta name="description" content="18 tools for CVE scanning"></head>
      <body>
        <main>v0.98.3 MCP server mode exposes 77 MCP tools</main>
        <script>window.__data = "18 tools for CVE scanning"</script>
      </body>
    </html>
    """

    monkeypatch.setattr(script, "_fetch", lambda _url, _timeout: current_page)
    monkeypatch.setattr(
        script,
        "_fetch_json",
        lambda _url, _timeout: {"tools": [{"name": f"tool_{index}"} for index in range(77)]},
    )

    assert script.main(["--expected", "0.98.3", "--expected-tool-count", "77", "--json", "--retries", "1"]) == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "fresh"


def test_glama_api_failure_is_unreachable_and_resets_previous_retry_count(monkeypatch, capsys):
    """A later API outage must not retain an earlier attempt's observed count."""
    script = _load_script("check_glama_listing.py")
    current_page = "v0.98.2 MCP server mode exposes 77 MCP tools"
    api_results = iter(
        [
            {"tools": [{"name": f"tool_{index}"} for index in range(76)]},
            urllib.error.URLError("temporary outage"),
        ]
    )

    def fetch_json(_url, _timeout):
        result = next(api_results)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(script, "_fetch", lambda _url, _timeout: current_page)
    monkeypatch.setattr(script, "_fetch_json", fetch_json)

    assert (
        script.main(
            [
                "--expected",
                "0.98.2",
                "--expected-tool-count",
                "77",
                "--json",
                "--retries",
                "2",
                "--delay-seconds",
                "0",
            ]
        )
        == 1
    )
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "unreachable"
    assert payload["tool_count"] is None
    assert "failed to verify Glama public API tool inventory" in payload["error"]


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


def test_glama_build_manifest_requires_locked_uv_sync(monkeypatch):
    script = _load_script("check_glama_listing.py")
    read_repo_file = script._read_repo_file

    def read_unlocked_dockerfile(relative_path, *, git_ref=None):
        text = read_repo_file(relative_path, git_ref=git_ref)
        if relative_path == script.GLAMA_DOCKERFILE:
            return text.replace("uv sync --locked", "uv sync", 1)
        return text

    monkeypatch.setattr(script, "_read_repo_file", read_unlocked_dockerfile)

    failures = script.verify_build_manifest()
    assert any("reviewed uv.lock" in failure for failure in failures)


def test_glama_build_manifest_requires_venv_on_mcp_proxy_path(monkeypatch):
    script = _load_script("check_glama_listing.py")
    read_repo_file = script._read_repo_file

    def read_dockerfile_without_venv_path(relative_path, *, git_ref=None):
        text = read_repo_file(relative_path, git_ref=git_ref)
        if relative_path == script.GLAMA_DOCKERFILE:
            return text.replace('ENV PATH="/app/.venv/bin:${PATH}"', 'ENV PATH="${PATH}"', 1)
        return text

    monkeypatch.setattr(script, "_read_repo_file", read_dockerfile_without_venv_path)

    failures = script.verify_build_manifest()
    assert any("mcp-proxy PATH" in failure for failure in failures)


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


def _smithery_listing_with(tool_count):
    def fake_http_json(_url, **_kwargs):
        return {
            "qualifiedName": "agent-bom/agent-bom",
            "remote": True,
            "deploymentUrl": "https://agent-bom--agent-bom.run.tools",
            "tools": [{"name": f"tool_{index}"} for index in range(tool_count)],
        }

    return fake_http_json


def test_smithery_listing_advertising_fewer_tools_than_shipped_is_stale(monkeypatch):
    """A partial catalog is the drift this monitor exists to catch.

    The live listing advertised 36 of the 77 tools the release ships — a strict
    subset, i.e. a stale snapshot — while the probe reported "fresh" because it
    only asserted the tool list was non-empty. Under-advertising by 41 tools on
    a public discovery surface is exactly the months-long drift this script was
    written to prevent, and it was invisible.
    """
    script = _load_script("check_surface_freshness.py")
    monkeypatch.setattr(script, "_http_json", _smithery_listing_with(36))

    result = script.probe_smithery("0.98.3", "agent-bom/agent-bom", expected_tool_count=77, timeout=1, attempts=1, backoff=0)

    assert result["status"] == "stale"
    assert result["tool_count"] == 36
    assert result["expected_tool_count"] == 77
    assert "36" in result["error"] and "77" in result["error"]


def test_smithery_listing_matching_the_shipped_tool_count_is_fresh(monkeypatch):
    script = _load_script("check_surface_freshness.py")
    monkeypatch.setattr(script, "_http_json", _smithery_listing_with(77))

    result = script.probe_smithery("0.98.3", "agent-bom/agent-bom", expected_tool_count=77, timeout=1, attempts=1, backoff=0)

    assert result["status"] == "fresh"
    assert result["tool_count"] == 77


def test_legacy_glama_tool_count_flag_is_still_accepted(monkeypatch, tmp_path):
    """Renaming the flag must not break anything still passing the old spelling."""
    script = _load_script("check_surface_freshness.py")
    seen = {}

    def record(name):
        def probe(expected, *args, **kwargs):
            seen[name] = kwargs.get("expected_tool_count")
            return {"surface": name, "status": "fresh", "version": expected, "expected": expected}

        return probe

    monkeypatch.setattr(script, "probe_pypi", record("PyPI"))
    monkeypatch.setattr(script, "probe_docker", record("Docker"))
    monkeypatch.setattr(script, "probe_glama", record("Glama"))
    monkeypatch.setattr(script, "probe_smithery", record("Smithery"))

    out = tmp_path / "report.json"
    script.main(["--expected", "0.98.3", "--expected-glama-tool-count", "77", "--out", str(out)])

    # The one expectation reaches BOTH surfaces that advertise a tool list.
    assert seen["Glama"] == 77
    assert seen["Smithery"] == 77


def test_smithery_tool_count_is_not_gated_when_no_expectation_is_supplied(monkeypatch):
    """Without an expected count the contract check stands on its own."""
    script = _load_script("check_surface_freshness.py")
    monkeypatch.setattr(script, "_http_json", _smithery_listing_with(36))

    result = script.probe_smithery("0.98.3", "agent-bom/agent-bom", timeout=1, attempts=1, backoff=0)

    assert result["status"] == "fresh"


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


def test_env_or_treats_blank_as_unset():
    script = _load_script("check_surface_freshness.py")
    glama = _load_script("check_glama_listing.py")

    assert script._env_or("MISSING_VAR_XYZ", "fallback") == "fallback"
    assert glama._env_or("MISSING_VAR_XYZ", "fallback") == "fallback"


def test_surface_freshness_blank_env_vars_use_defaults(monkeypatch):
    """GitHub Actions injects unset vars.* as empty strings into env:."""
    script = _load_script("check_surface_freshness.py")
    monkeypatch.setenv("DOCKER_IMAGE", "")
    monkeypatch.setenv("SMITHERY_SERVER_QUALIFIED_NAME", "   ")
    monkeypatch.setenv("GLAMA_LISTING_URL", "")

    assert script._env_or("DOCKER_IMAGE", script.DEFAULT_DOCKER_IMAGE) == script.DEFAULT_DOCKER_IMAGE
    assert script._env_or("SMITHERY_SERVER_QUALIFIED_NAME", script.DEFAULT_SMITHERY_SERVER) == script.DEFAULT_SMITHERY_SERVER

    glama = _load_script("check_glama_listing.py")
    assert glama._env_or("GLAMA_LISTING_URL", glama.DEFAULT_URL) == glama.DEFAULT_URL


def test_surface_freshness_main_skips_blank_docker_and_smithery_env(monkeypatch, tmp_path):
    script = _load_script("check_surface_freshness.py")
    monkeypatch.setenv("DOCKER_IMAGE", "")
    monkeypatch.setenv("SMITHERY_SERVER_QUALIFIED_NAME", "")

    monkeypatch.setattr(
        script,
        "probe_pypi",
        lambda expected, **_kw: {
            "surface": "PyPI",
            "status": "fresh",
            "version": expected,
            "expected": expected,
        },
    )
    monkeypatch.setattr(
        script,
        "probe_glama",
        lambda expected, **_kw: {
            "surface": "Glama",
            "status": "fresh",
            "version": expected,
            "expected": expected,
        },
    )

    seen: dict[str, str] = {}

    def fake_docker(expected, image, **_kw):
        seen["docker"] = image
        return {"surface": "Docker", "status": "fresh", "version": expected, "expected": expected}

    def fake_smithery(expected, qualified_name, **_kw):
        seen["smithery"] = qualified_name
        return {"surface": "Smithery", "status": "fresh", "version": "catalog-live", "expected": expected}

    monkeypatch.setattr(script, "probe_docker", fake_docker)
    monkeypatch.setattr(script, "probe_smithery", fake_smithery)

    out = tmp_path / "report.json"
    assert script.main(["--expected", "0.97.5", "--out", str(out)]) == 0
    report = json.loads(out.read_text())
    assert report["all_fresh"] is True
    assert seen["docker"] == script.DEFAULT_DOCKER_IMAGE
    assert seen["smithery"] == script.DEFAULT_SMITHERY_SERVER
