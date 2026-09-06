"""Regression tests for public marketplace freshness automation."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import urllib.error
from pathlib import Path
from types import ModuleType

import pytest

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


def test_glama_listing_rejects_same_count_with_a_different_tool(monkeypatch, capsys, tmp_path):
    script = _load_script("check_glama_listing.py")
    expected_names = ["graph_correlate", "graph_correlation_status"]
    names_file = tmp_path / "expected-tools.json"
    names_file.write_text(json.dumps(expected_names), encoding="utf-8")
    current_page = "v0.103.2 MCP server mode exposes 2 MCP tools"

    monkeypatch.setattr(script, "_fetch", lambda _url, _timeout: current_page)
    monkeypatch.setattr(
        script,
        "_fetch_json",
        lambda _url, _timeout: {"tools": [{"name": "graph_correlate"}, {"name": "unrelated_tool"}]},
    )

    assert (
        script.main(
            [
                "--expected",
                "0.103.2",
                "--expected-tool-count",
                "2",
                "--expected-tool-names-file",
                str(names_file),
                "--json",
                "--retries",
                "1",
            ]
        )
        == 1
    )
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "stale"
    assert payload["exact_tool_set"] is False
    assert "missing expected tools: graph_correlation_status" in payload["error"]
    assert "unexpected tools: unrelated_tool" in payload["error"]


@pytest.mark.parametrize("bad_name", [None, ["nested"], {"nested": "value"}, " scan "])
def test_glama_listing_reports_malformed_tool_names_as_stale(monkeypatch, capsys, tmp_path, bad_name):
    script = _load_script("check_glama_listing.py")
    names_file = tmp_path / "expected-tools.json"
    names_file.write_text(json.dumps(["scan", "check"]), encoding="utf-8")
    current_page = "v0.103.2 MCP server mode exposes 2 MCP tools"

    monkeypatch.setattr(script, "_fetch", lambda _url, _timeout: current_page)
    monkeypatch.setattr(script, "_fetch_json", lambda _url, _timeout: {"tools": [{"name": "scan"}, {"name": bad_name}]})

    assert (
        script.main(
            [
                "--expected",
                "0.103.2",
                "--expected-tool-count",
                "2",
                "--expected-tool-names-file",
                str(names_file),
                "--json",
                "--retries",
                "1",
            ]
        )
        == 1
    )
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "stale"
    assert payload["exact_tool_set"] is False
    assert "tool without a name" in payload["error"]


def test_glama_tool_names_are_extracted_inertly_from_the_release_ref(tmp_path):
    script = _load_script("check_glama_listing.py")
    destination = tmp_path / "tool-names.json"

    assert script.main(["--write-tool-names", str(destination), "--git-ref", "HEAD"]) == 0
    names = json.loads(destination.read_text(encoding="utf-8"))

    assert names == sorted(names)
    assert len(names) == len(set(names)) == 86
    assert "graph_correlate" in names
    assert "graph_correlation_status" in names


def test_glama_listing_rejects_exact_public_schema_when_directory_api_is_stale(monkeypatch, capsys):
    """One fresh public surface must not hide a reachable stale machine API."""
    script = _load_script("check_glama_listing.py")
    current_page = "v0.98.3 MCP server mode exposes 77 MCP tools"
    schema_page = "".join(f'<a href="/mcp/servers/msaad00/agent-bom/tools/tool_{index}">tool_{index}</a>' for index in range(77))

    def fetch(url, _timeout):
        return schema_page if url.endswith("/schema") else current_page

    monkeypatch.setattr(script, "_fetch", fetch)
    monkeypatch.setattr(script, "_fetch_json", lambda _url, _timeout: {"tools": []})

    assert script.main(["--expected", "0.98.3", "--expected-tool-count", "77", "--json", "--retries", "1"]) == 1
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "stale"
    assert payload["inventory_source"] == "schema+api"
    assert "public API exposes 0 tools; expected 77" in payload["error"]


def test_glama_listing_marks_schema_only_success_as_degraded(monkeypatch, capsys):
    script = _load_script("check_glama_listing.py")
    current_page = "v0.98.3 MCP server mode exposes 2 MCP tools"
    schema_page = "".join(f'<a href="/mcp/servers/msaad00/agent-bom/tools/tool_{index}">tool_{index}</a>' for index in range(2))

    def fetch(url, _timeout):
        return schema_page if url.endswith("/schema") else current_page

    monkeypatch.setattr(script, "_fetch", fetch)
    monkeypatch.setattr(script, "_fetch_json", lambda _url, _timeout: (_ for _ in ()).throw(urllib.error.URLError("401")))

    assert script.main(["--expected", "0.98.3", "--expected-tool-count", "2", "--json", "--retries", "1"]) == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "fresh_degraded"
    assert payload["inventory_source"] == "schema"
    assert payload["degraded_reason"] == "Glama public API inventory was unreachable"


def test_glama_listing_rejects_stale_input_schema_from_reachable_api(monkeypatch, capsys, tmp_path):
    script = _load_script("check_glama_listing.py")
    expected_contract = [
        {"name": "scan", "inputSchema": {"type": "object", "additionalProperties": False}},
        {"name": "check", "inputSchema": {"type": "object", "required": ["package"]}},
    ]
    contract_file = tmp_path / "expected-contract.json"
    contract_file.write_text(json.dumps(expected_contract), encoding="utf-8")
    current_page = "v0.103.2 MCP server mode exposes 2 MCP tools"

    monkeypatch.setattr(script, "_fetch", lambda _url, _timeout: current_page)
    monkeypatch.setattr(
        script,
        "_fetch_json",
        lambda _url, _timeout: {"tools": [expected_contract[0], {"name": "check", "inputSchema": {"type": "object"}}]},
    )

    assert (
        script.main(
            [
                "--expected",
                "0.103.2",
                "--expected-tool-count",
                "2",
                "--expected-tool-contract-file",
                str(contract_file),
                "--json",
                "--retries",
                "1",
            ]
        )
        == 1
    )
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "stale"
    assert payload["exact_input_schemas"] is False
    assert "input schema differs for tool: check" in payload["error"]


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
        assert url == "https://api.smithery.ai/servers/agentbom/agent-bom"
        return {
            "qualifiedName": "agentbom/agent-bom",
            "remote": True,
            "deploymentUrl": "https://agent-bom--agent-bom.run.tools",
            "tools": [{"name": "scan"}, {"name": "check"}],
        }

    monkeypatch.setattr(script, "_http_json", fake_http_json)

    result = script.probe_smithery("0.89.2", "agentbom/agent-bom", timeout=1, attempts=1, backoff=0)

    assert result["surface"] == "Smithery"
    assert result["status"] == "fresh"
    assert result["version"] == "catalog-live"
    assert result["deployment_url"] == "https://agent-bom--agent-bom.run.tools"
    assert result["tool_count"] == 2


def _smithery_listing_with(tool_count):
    def fake_http_json(_url, **_kwargs):
        return {
            "qualifiedName": "agentbom/agent-bom",
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

    result = script.probe_smithery("0.98.3", "agentbom/agent-bom", expected_tool_count=77, timeout=1, attempts=1, backoff=0)

    assert result["status"] == "stale"
    assert result["tool_count"] == 36
    assert result["expected_tool_count"] == 77
    assert "36" in result["error"] and "77" in result["error"]


def test_smithery_listing_matching_the_shipped_tool_count_is_fresh(monkeypatch):
    script = _load_script("check_surface_freshness.py")
    monkeypatch.setattr(script, "_http_json", _smithery_listing_with(77))

    result = script.probe_smithery("0.98.3", "agentbom/agent-bom", expected_tool_count=77, timeout=1, attempts=1, backoff=0)

    assert result["status"] == "fresh"
    assert result["tool_count"] == 77


def test_smithery_listing_rejects_count_collision_with_wrong_tool_names(monkeypatch):
    """A matching count must not substitute for the immutable name set."""
    script = _load_script("check_surface_freshness.py")
    monkeypatch.setattr(script, "_http_json", _smithery_listing_with(2))

    result = script.probe_smithery(
        "0.103.2",
        "agentbom/agent-bom",
        expected_tool_count=2,
        expected_tool_names=["graph_correlate", "scan"],
        timeout=1,
        attempts=1,
        backoff=0,
    )

    assert result["status"] == "stale"
    assert result["exact_tool_set"] is False
    assert "tool-name set differs" in result["error"]


def test_glama_probe_forwards_immutable_tool_name_contract(monkeypatch, tmp_path):
    script = _load_script("check_surface_freshness.py")
    names_file = tmp_path / "expected-tool-names.json"
    names_file.write_text('["graph_correlate", "scan"]\n', encoding="utf-8")
    seen: list[str] = []

    def fake_run(command, **_kwargs):
        seen.extend(command)
        return subprocess.CompletedProcess(command, 0, stdout='{"status":"fresh"}\n', stderr="")

    monkeypatch.setattr(script.subprocess, "run", fake_run)

    result = script.probe_glama(
        "0.103.2",
        expected_tool_count=2,
        expected_tool_names_file=names_file,
        timeout=1,
        attempts=1,
        backoff=0,
    )

    assert result["status"] == "fresh"
    assert seen[seen.index("--expected-tool-names-file") + 1] == str(names_file)


def test_surface_freshness_does_not_close_on_degraded_evidence(monkeypatch, tmp_path):
    """An unavailable machine inventory is partial evidence, never all-fresh."""
    script = _load_script("check_surface_freshness.py")

    def fresh(name):
        return lambda expected, *args, **kwargs: {
            "surface": name,
            "status": "fresh",
            "version": expected,
            "expected": expected,
        }

    monkeypatch.setattr(script, "probe_pypi", fresh("PyPI"))
    monkeypatch.setattr(script, "probe_docker", fresh("Docker"))
    monkeypatch.setattr(
        script,
        "probe_glama",
        lambda expected, **_kwargs: {
            "surface": "Glama",
            "status": "fresh_degraded",
            "version": expected,
            "expected": expected,
            "degraded_reason": "Glama public API inventory was unreachable",
        },
    )
    monkeypatch.setattr(script, "probe_smithery", fresh("Smithery"))

    out = tmp_path / "report.json"
    assert script.main(["--expected", "0.103.2", "--out", str(out)]) == 0

    report = json.loads(out.read_text())
    assert report["all_fresh"] is False


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

    result = script.probe_smithery("0.98.3", "agentbom/agent-bom", timeout=1, attempts=1, backoff=0)

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


def test_default_invocation_derives_the_expected_tool_count(monkeypatch, tmp_path):
    """Running the monitor with no flags must still gate the tool count.

    ``--expected-tool-count`` defaulted to ``None``, and only the Glama probe
    fell back to deriving it from the README. So the workflows — which pass the
    flag — gated the count, while a bare ``python scripts/check_surface_freshness.py``
    reported Smithery **fresh at 36 of 77**: the exact drift the sibling test
    above calls "invisible". One shipped inventory means one derivation, not one
    derivation and one caller-supplied argument that silently defaults to off.
    """
    script = _load_script("check_surface_freshness.py")
    seen = {}

    def record(name):
        def probe(expected, *args, **kwargs):
            seen[name] = kwargs.get("expected_tool_count")
            return {"surface": name, "status": "fresh", "version": expected, "expected": expected}

        return probe

    for name, attribute in (
        ("PyPI", "probe_pypi"),
        ("Docker", "probe_docker"),
        ("Glama", "probe_glama"),
        ("Smithery", "probe_smithery"),
    ):
        monkeypatch.setattr(script, attribute, record(name))

    out = tmp_path / "report.json"
    script.main(["--expected", "0.98.3", "--out", str(out)])

    expected = int(script.expected_tool_count())
    assert expected > 1, "the README contract should be a real inventory, not a placeholder"
    assert seen["Glama"] == expected
    assert seen["Smithery"] == expected


def test_expected_tool_count_has_a_single_derivation():
    """Both scripts must read the same sentence, not keep separate copies."""
    freshness = _load_script("check_surface_freshness.py")
    glama = _load_script("check_glama_listing.py")

    assert int(freshness.expected_tool_count()) == int(glama._load_readme_tool_count())


def test_ghcr_pagination_never_carries_the_token_off_origin(monkeypatch):
    """A registry-supplied ``next`` link must not redirect our bearer token.

    The GHCR tag walk resolved each page with
    ``urljoin("https://ghcr.io", link)``, and ``urljoin`` returns an absolute
    URL unchanged — so a ``Link: <https://attacker.example/...>; rel="next"``
    header replaced the host while ``auth_headers`` kept the GHCR bearer token
    attached. #4626 closed exactly this on the Docker Hub cleanup path; the
    monitor kept the second copy.
    """
    script = _load_script("check_surface_freshness.py")
    dialled = []

    monkeypatch.setattr(script, "_http_json", lambda url, **_kw: {"token": "ghcr-secret"})

    def fake_http_json_response(url, headers=None, **_kw):
        dialled.append((url, dict(headers or {})))
        if "attacker.example" in url:
            return {"tags": ["9.9.9"]}, {}
        return {"tags": ["0.98.3"]}, {"Link": '<https://attacker.example/v2/x/tags/list?n=100>; rel="next"'}

    monkeypatch.setattr(script, "_http_json_response", fake_http_json_response)

    result = script.probe_docker("0.98.3", "ghcr.io/msaad00/agent-bom", timeout=1, attempts=1, backoff=0)

    off_origin = [url for url, _ in dialled if "ghcr.io" not in url]
    assert not off_origin, f"followed a link off ghcr.io: {off_origin}"
    leaked = [url for url, sent in dialled if "ghcr.io" not in url and sent.get("Authorization")]
    assert not leaked, f"bearer token sent off-origin to {leaked}"
    # Fail closed rather than judging on the pages we did get. The expected tag
    # was on page one here, so a laxer probe would report "fresh" and bury the
    # fact that the registry handed back a link pointing somewhere else.
    assert result["status"] == "unreachable"
    assert "off-origin" in result["error"]


def test_ghcr_pagination_still_follows_a_same_origin_next_link(monkeypatch):
    """The guard must not break real pagination — the tag is on page two."""
    script = _load_script("check_surface_freshness.py")
    monkeypatch.setattr(script, "_http_json", lambda url, **_kw: {"token": "ghcr-secret"})
    pages = iter(
        [
            ({"tags": ["0.98.1"]}, {"Link": '</v2/msaad00/agent-bom/tags/list?n=100&last=0.98.1>; rel="next"'}),
            ({"tags": ["0.98.3"]}, {}),
        ]
    )
    monkeypatch.setattr(script, "_http_json_response", lambda url, headers=None, **_kw: next(pages))

    result = script.probe_docker("0.98.3", "ghcr.io/msaad00/agent-bom", timeout=1, attempts=1, backoff=0)

    assert result["status"] == "fresh"


def _glama_schema_state(tools, *, namespace="msaad00", slug="agent-bom", null_reference=-5):
    """Encode the public schema route's reference-table JSON, without JS execution."""
    values = []

    def encode(value):
        if value is None:
            return null_reference
        index = len(values)
        values.append(None)
        if isinstance(value, dict):
            values[index] = {f"_{encode(key)}": encode(item) for key, item in value.items()}
        elif isinstance(value, list):
            values[index] = [encode(item) for item in value]
        else:
            values[index] = value
        return index

    encode(
        {
            "loaderData": {
                "routes/_public/mcp/servers/~namespace/~slug/_pages/schema/_route": {
                    "mcpServer": {"namespace": {"slug": namespace}, "slug": slug},
                    "schema": {"tools": tools},
                }
            }
        }
    )
    return "<script>window.__reactRouterContext.streamController.enqueue(" + json.dumps(json.dumps(values)) + ");</script>"


@pytest.mark.parametrize("mismatch", [False, True])
def test_glama_checks_public_embedded_schemas_when_api_requires_auth(monkeypatch, capsys, tmp_path, mismatch):
    script = _load_script("check_glama_listing.py")
    expected = [{"name": "scan", "inputSchema": {"type": "object", "additionalProperties": False}}]
    tools = [{"name": "scan", "inputSchema": {"type": "object"}}] if mismatch else expected
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps(expected))
    schema = '<a href="/mcp/servers/msaad00/agent-bom/tools/scan">scan</a>' + _glama_schema_state(tools)
    monkeypatch.setattr(
        script, "_fetch", lambda url, timeout: schema if url.endswith("/schema") else "v0.103.2 MCP server mode exposes 1 MCP tools"
    )
    monkeypatch.setattr(
        script,
        "_fetch_json",
        lambda *args: (_ for _ in ()).throw(urllib.error.HTTPError("https://glama.ai/api", 401, "Unauthorized", {}, None)),
    )
    result = script.main(
        ["--expected", "0.103.2", "--expected-tool-count", "1", "--expected-tool-contract-file", str(contract), "--json", "--retries", "1"]
    )
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert result == int(mismatch)
    assert payload["status"] == ("stale" if mismatch else "fresh")
    assert payload["exact_input_schemas"] is not mismatch
    assert payload["inventory_source"] == "schema-state"


def test_glama_embedded_schema_parser_rejects_unrelated_or_incomplete_evidence():
    script = _load_script("check_glama_listing.py")
    tools = [{"name": "scan", "inputSchema": {"type": "object"}}]
    assert script._extract_schema_tool_contract(_glama_schema_state(tools), script.DEFAULT_URL) == tools
    for page in (
        _glama_schema_state(tools, slug="another-server"),
        _glama_schema_state([{"name": "scan"}]),
        '<script>window.__reactRouterContext.streamController.enqueue("[0]");</script>',
        '<script>window.__reactRouterContext.streamController.enqueue("[{\\"_9\\":9}]");</script>',
        "x" * (2 * 1024 * 1024 + 1),
    ):
        with pytest.raises(ValueError):
            script._extract_schema_tool_contract(page, script.DEFAULT_URL)


def test_glama_requires_exact_schema_proof_when_contract_is_requested(monkeypatch, capsys, tmp_path):
    script = _load_script("check_glama_listing.py")
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps([{"name": "scan", "inputSchema": {"type": "object"}}]))
    monkeypatch.setattr(
        script,
        "_fetch",
        lambda url, timeout: (
            '<a href="/mcp/servers/msaad00/agent-bom/tools/scan">scan</a>'
            if url.endswith("/schema")
            else "v0.103.2 MCP server mode exposes 1 MCP tools"
        ),
    )
    monkeypatch.setattr(script, "_fetch_json", lambda *args: (_ for _ in ()).throw(urllib.error.URLError("401")))
    assert (
        script.main(
            [
                "--expected",
                "0.103.2",
                "--expected-tool-count",
                "1",
                "--expected-tool-contract-file",
                str(contract),
                "--json",
                "--retries",
                "1",
            ]
        )
        == 1
    )
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["exact_input_schemas"] is None
    assert "could not verify requested input schemas" in payload["error"]


@pytest.mark.parametrize(
    "table",
    [
        [0],
        [{"_9": 9}],
        [{"_1": 2, "_3": 4}, "duplicate", 1, "duplicate", 2],
        [[index + 1] for index in range(70)] + [None],
        [None] * 50_001,
    ],
)
def test_glama_schema_reference_tables_fail_closed(table):
    script = _load_script("check_glama_listing.py")
    page = "<script>window.__reactRouterContext.streamController.enqueue(" + json.dumps(json.dumps(table)) + ");</script>"
    with pytest.raises(ValueError):
        script._extract_schema_tool_contract(page, script.DEFAULT_URL)


def test_glama_schema_does_not_conflate_undefined_with_json_null():
    script = _load_script("check_glama_listing.py")
    tools = [{"name": "scan", "inputSchema": {"type": "object", "default": None}}]
    assert script._extract_schema_tool_contract(_glama_schema_state(tools), script.DEFAULT_URL) == tools
    with pytest.raises(ValueError):
        script._extract_schema_tool_contract(_glama_schema_state(tools, null_reference=-7), script.DEFAULT_URL)


def test_default_smithery_listing_uses_product_namespace():
    script = _load_script("check_surface_freshness.py")
    assert script.DEFAULT_SMITHERY_SERVER == "agentbom/agent-bom"
    assert script._smithery_catalog_url(script.DEFAULT_SMITHERY_SERVER) == "https://api.smithery.ai/servers/agentbom/agent-bom"


def _strict_marketplace_tool():
    return {
        "name": "check",
        "inputSchema": {
            "type": "object",
            "properties": {"package": {"type": "string"}},
            "required": ["package"],
            "additionalProperties": False,
        },
    }


@pytest.mark.parametrize("missing", ["required", "additionalProperties"])
def test_smithery_rejects_schema_constraint_loss(monkeypatch, missing):
    script = _load_script("check_surface_freshness.py")

    def unavailable(*_a, **_kw):
        raise ValueError("public evidence unavailable")

    monkeypatch.setattr(script, "_smithery_public_contract", unavailable)

    expected = [_strict_marketplace_tool()]
    actual = json.loads(json.dumps(expected))
    actual[0]["inputSchema"].pop(missing)
    monkeypatch.setattr(
        script,
        "_http_json",
        lambda *_a, **_kw: {
            "qualifiedName": "agentbom/agent-bom",
            "remote": True,
            "deploymentUrl": "https://agent-bom--agentbom.run.tools",
            "tools": actual,
        },
    )
    result = script.probe_smithery(
        "0.103.2", "agentbom/agent-bom", expected_tool_count=1, expected_tool_names=["check"], expected_tool_contract=expected
    )
    assert result["status"] == "stale"
    assert result["exact_input_schemas"] is False


def test_smithery_accepts_exact_schemas(monkeypatch):
    script = _load_script("check_surface_freshness.py")
    tools = [_strict_marketplace_tool()]
    monkeypatch.setattr(
        script,
        "_http_json",
        lambda *_a, **_kw: {
            "qualifiedName": "agentbom/agent-bom",
            "remote": True,
            "deploymentUrl": "https://agent-bom--agentbom.run.tools",
            "tools": tools,
        },
    )
    result = script.probe_smithery(
        "0.103.2", "agentbom/agent-bom", expected_tool_count=1, expected_tool_names=["check"], expected_tool_contract=tools
    )
    assert result["status"] == "fresh"
    assert result["exact_input_schemas"] is True


@pytest.mark.parametrize("fault", ["version", "names", "duplicate", "schema"])
def test_monitor_rejects_unbound_server_card(monkeypatch, tmp_path, fault):
    script = _load_script("check_surface_freshness.py")
    card = {"serverInfo": {"version": "0.103.2"}, "tools": [_strict_marketplace_tool()]}
    if fault == "version":
        card["serverInfo"]["version"] = "0.1.0"
    elif fault == "names":
        card["tools"][0]["name"] = "wrong"
    elif fault == "duplicate":
        card["tools"].append(_strict_marketplace_tool())
    else:
        card["tools"][0]["inputSchema"] = None
    monkeypatch.setattr(script, "_http_json", lambda *_a, **_kw: card)
    names = tmp_path / "names.json"
    names.write_text('["check"]')
    dest = tmp_path / "contract.json"
    with pytest.raises(SystemExit):
        script.main(
            [
                "--expected",
                "0.103.2",
                "--expected-tool-count",
                "1",
                "--expected-tool-names-file",
                str(names),
                "--server-card-url",
                "https://example.com/.well-known/mcp/server-card.json",
                "--write-tool-contract",
                str(dest),
            ]
        )
    assert not dest.exists()


def test_smithery_schema_drift_keeps_consolidated_issue_open(monkeypatch, tmp_path, capsys):
    script = _load_script("check_surface_freshness.py")

    def unavailable(*_a, **_kw):
        raise ValueError("public evidence unavailable")

    monkeypatch.setattr(script, "_smithery_public_contract", unavailable)

    tools = [_strict_marketplace_tool()]
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps(tools))
    actual = json.loads(json.dumps(tools))
    actual[0]["inputSchema"].pop("required")
    monkeypatch.setattr(
        script,
        "_http_json",
        lambda *_a, **_kw: {
            "qualifiedName": "agentbom/agent-bom",
            "remote": True,
            "deploymentUrl": "https://agent-bom--agentbom.run.tools",
            "tools": actual,
        },
    )
    assert (
        script.main(
            [
                "--surface",
                "smithery",
                "--expected",
                "0.103.2",
                "--expected-tool-count",
                "1",
                "--expected-tool-contract-file",
                str(contract),
                "--fail-on-stale",
            ]
        )
        == 1
    )
    result = json.loads(capsys.readouterr().out)
    assert result["all_fresh"] is False
    assert result["surfaces"][0]["exact_input_schemas"] is False


def test_both_daily_monitors_require_exact_schema_evidence():
    for name in ("surface-freshness.yml", "deployment-freshness.yml"):
        workflow = (ROOT / ".github/workflows" / name).read_text()
        assert "--write-tool-contract" in workflow
        assert "--expected-tool-contract-file" in workflow
        assert "--expected-tool-names-file" in workflow


def test_monitor_writes_only_validated_release_schemas(monkeypatch, tmp_path):
    script = _load_script("check_surface_freshness.py")
    tools = [_strict_marketplace_tool()]
    monkeypatch.setattr(script, "_http_json", lambda *_a, **_kw: {"serverInfo": {"version": "0.103.2"}, "tools": tools})
    names = tmp_path / "names.json"
    names.write_text('["check"]')
    dest = tmp_path / "contract.json"
    assert (
        script.main(
            [
                "--expected",
                "0.103.2",
                "--expected-tool-count",
                "1",
                "--expected-tool-names-file",
                str(names),
                "--server-card-url",
                "https://example.com/.well-known/mcp/server-card.json",
                "--write-tool-contract",
                str(dest),
            ]
        )
        == 0
    )
    assert json.loads(dest.read_text()) == tools


@pytest.mark.parametrize(
    "url",
    ["http://example.com/card", "https://user:secret@example.com/card", "https://example.com/card?token=x", "https://example.com/card#x"],
)
def test_release_schema_source_rejects_unsafe_urls(monkeypatch, url):
    script = _load_script("check_surface_freshness.py")
    monkeypatch.setattr(script, "_http_json", lambda *_a, **_kw: pytest.fail("must reject URL before network access"))
    with pytest.raises(ValueError):
        script._released_server_card(url, "0.103.2", ["check"])


def test_monitor_does_not_ignore_missing_requested_contract(tmp_path):
    script = _load_script("check_surface_freshness.py")
    with pytest.raises(SystemExit, match="could not load expected schema contract"):
        script.main(["--expected-tool-count", "1", "--expected-tool-contract-file", str(tmp_path / "missing.json")])


def test_glama_monitor_forwards_required_schema_contract(monkeypatch, tmp_path):
    script = _load_script("check_surface_freshness.py")
    contract = tmp_path / "contract.json"
    seen = []

    def run(command, **_kw):
        seen.extend(command)
        return subprocess.CompletedProcess(command, 1, stdout=json.dumps({"status": "stale", "exact_input_schemas": False}))

    monkeypatch.setattr(script.subprocess, "run", run)
    result = script.probe_glama("0.103.2", expected_tool_contract_file=contract)
    assert seen[seen.index("--expected-tool-contract-file") + 1] == str(contract)
    assert result["status"] == "stale"
    assert result["exact_input_schemas"] is False


def test_deployment_issue_closure_requires_explicit_verified_success():
    workflow = (ROOT / ".github/workflows/deployment-freshness.yml").read_text()
    close_step = workflow.split("- name: Close supply-chain drift issue when deployment is fresh", 1)[1]
    assert "steps.public.outputs.public_version == 'fresh'" in close_step
    assert "steps.public.outputs.probe_failed == 'false'" in close_step


def _smithery_public_page(tools, *, qualified_name="agentbom/agent-bom", prefix=""):
    namespace, slug = qualified_name.split("/")
    server = {"qualifiedName": qualified_name, "namespace": namespace, "slug": slug, "remote": True, "tools": tools}
    flight = prefix + "1:" + json.dumps({"server": server}) + "\n"
    return "<script>self.__next_f.push(" + json.dumps([1, flight]) + ")</script>"


def test_smithery_public_schema_preserves_exact_constraints():
    script = _load_script("check_surface_freshness.py")
    tools = [_strict_marketplace_tool()]
    assert script._extract_smithery_public_contract(_smithery_public_page(tools), "agentbom/agent-bom") == tools


@pytest.mark.parametrize(
    "fault", ["wrong_server", "duplicate_record", "truncated", "oversized", "duplicate_tool", "deep", "malformed_schema"]
)
def test_smithery_public_schema_fails_closed(fault):
    script = _load_script("check_surface_freshness.py")
    tools = [_strict_marketplace_tool()]
    page = _smithery_public_page(tools)
    if fault == "wrong_server":
        page = _smithery_public_page(tools, qualified_name="other/server")
    elif fault == "duplicate_record":
        page += page
    elif fault == "truncated":
        page = '<script>self.__next_f.push([1,"2:Tff,short"])</script>'
    elif fault == "oversized":
        page += " " * (2 * 1024 * 1024)
    elif fault == "duplicate_tool":
        page = _smithery_public_page(tools + tools)
    elif fault == "malformed_schema":
        page = _smithery_public_page([{"name": "check", "inputSchema": None}])
    else:
        value = "end"
        for _ in range(70):
            value = [value]
        tools[0]["inputSchema"]["default"] = value
        page = _smithery_public_page(tools)
    with pytest.raises((ValueError, RecursionError)):
        script._extract_smithery_public_contract(page, "agentbom/agent-bom")


def test_smithery_public_text_records_cannot_inject_schema_candidates():
    script = _load_script("check_surface_freshness.py")
    fake = "1:" + json.dumps({"qualifiedName": "agentbom/agent-bom", "tools": []}) + "\n"
    prefix = "0:T" + format(len(fake.encode()), "x") + "," + fake
    tools = [_strict_marketplace_tool()]
    assert script._extract_smithery_public_contract(_smithery_public_page(tools, prefix=prefix), "agentbom/agent-bom") == tools


def test_smithery_complete_public_evidence_resolves_catalog_projection(monkeypatch):
    script = _load_script("check_surface_freshness.py")
    tools = [_strict_marketplace_tool()]
    reduced = json.loads(json.dumps(tools))
    reduced[0]["inputSchema"].pop("required")
    reduced[0]["inputSchema"].pop("additionalProperties")
    monkeypatch.setattr(
        script,
        "_http_json",
        lambda *_a, **_kw: {
            "qualifiedName": "agentbom/agent-bom",
            "remote": True,
            "deploymentUrl": "https://agent-bom--agentbom.run.tools",
            "tools": reduced,
        },
    )
    monkeypatch.setattr(script, "_smithery_public_contract", lambda *_a, **_kw: tools)
    result = script.probe_smithery(
        "0.103.2", "agentbom/agent-bom", expected_tool_count=1, expected_tool_names=["check"], expected_tool_contract=tools
    )
    assert result["status"] == "fresh"
    assert result["exact_input_schemas"] is True
    assert result["catalog_exact_input_schemas"] is False
    assert result["inventory_source"] == "public-page"


@pytest.mark.parametrize("mismatch", [False, True])
def test_smithery_public_schemas_must_agree_with_catalog_values(monkeypatch, mismatch):
    import io

    script = _load_script("check_surface_freshness.py")
    tools = [_strict_marketplace_tool()]
    reduced = json.loads(json.dumps(tools))
    reduced[0]["inputSchema"].pop("required")
    if mismatch:
        reduced[0]["inputSchema"]["properties"]["package"]["type"] = "integer"
    monkeypatch.setattr(script.urllib.request, "urlopen", lambda *_a, **_kw: io.BytesIO(_smithery_public_page(tools).encode()))
    if mismatch:
        with pytest.raises(ValueError, match="schema values disagree"):
            script._smithery_public_contract("agentbom/agent-bom", reduced)
    else:
        assert script._smithery_public_contract("agentbom/agent-bom", reduced) == tools


def test_smithery_contract_comparison_preserves_types_and_numeric_values():
    script = _load_script("check_surface_freshness.py")
    assert script._contract_json({"default": 3.0}) == script._contract_json({"default": 3})
    assert script._contract_json({"default": 0.5}) != script._contract_json({"default": 0})
    assert script._contract_json({"additionalProperties": False}) != script._contract_json({"additionalProperties": 0})
    assert script._contract_json({"type": "integer"}) != script._contract_json({"type": "number"})


def test_smithery_publisher_uses_complete_public_schema_evidence():
    workflow = (ROOT / ".github/workflows/publish-registries.yml").read_text()
    assert workflow.count("--write-smithery-tool-contract /tmp/smithery-actual-tool-contract.json") == 2
    assert (
        workflow.count("--compare-tool-contract-files /tmp/smithery-expected-tool-contract.json /tmp/smithery-actual-tool-contract.json")
        == 2
    )
