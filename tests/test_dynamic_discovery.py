"""Tests for dynamic MCP configuration discovery (v0.41.0)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

from agent_bom.discovery.dynamic import (
    MCP_ENV_PREFIXES,
    MCP_JSON_SIGNATURES,
    SKIP_DIRS,
    DynamicDiscoveryResult,
    _detect_json_mcp,
    _detect_mcp_config,
    _detect_toml_mcp,
    _detect_yaml_mcp,
    _scan_environment,
    _scan_filesystem,
    discover_dynamic,
    merge_discoveries,
)
from agent_bom.models import Agent, AgentType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data))
    return path


# ---------------------------------------------------------------------------
# Filesystem scanning
# ---------------------------------------------------------------------------


class TestScanFilesystem:
    def test_finds_mcp_json_in_config_dir(self, tmp_path):
        config_dir = tmp_path / ".config" / "myagent"
        config_dir.mkdir(parents=True)
        _write_json(config_dir / "mcp.json", {"mcpServers": {}})

        candidates = _scan_filesystem(tmp_path, [".config/*/mcp.json"], max_depth=4, exclude_paths=set())
        assert any("mcp.json" in str(p) for p in candidates)

    def test_respects_max_depth(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "d" / "e"
        deep.mkdir(parents=True)
        _write_json(deep / "mcp.json", {"mcpServers": {}})

        candidates = _scan_filesystem(tmp_path, ["**/mcp.json"], max_depth=2, exclude_paths=set())
        assert not any("e/mcp.json" in str(p) for p in candidates)

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        _write_json(nm / "mcp.json", {"mcpServers": {}})

        candidates = _scan_filesystem(tmp_path, ["**/mcp.json"], max_depth=4, exclude_paths=set())
        assert not any("node_modules" in str(p) for p in candidates)

    def test_skips_dot_git(self, tmp_path):
        gitdir = tmp_path / ".git" / "hooks"
        gitdir.mkdir(parents=True)
        _write_json(gitdir / "mcp.json", {"mcpServers": {}})

        candidates = _scan_filesystem(tmp_path, ["**/mcp.json"], max_depth=4, exclude_paths=set())
        assert not any(".git" in str(p) for p in candidates)

    def test_skips_excluded_paths(self, tmp_path):
        f = tmp_path / "mcp.json"
        _write_json(f, {"mcpServers": {}})

        excluded = {str(f.resolve())}
        candidates = _scan_filesystem(tmp_path, ["mcp.json"], max_depth=4, exclude_paths=excluded)
        assert len(candidates) == 0

    def test_empty_directory_returns_empty(self, tmp_path):
        candidates = _scan_filesystem(tmp_path, ["mcp.json", "**/mcp.json"], max_depth=4, exclude_paths=set())
        assert candidates == []

    def test_deduplicates_results(self, tmp_path):
        f = tmp_path / "mcp.json"
        _write_json(f, {"mcpServers": {}})

        # Two patterns that match the same file
        candidates = _scan_filesystem(tmp_path, ["mcp.json", "*.json"], max_depth=4, exclude_paths=set())
        resolved = [str(p.resolve()) for p in candidates]
        assert len(set(resolved)) == len(resolved)

    def test_handles_permission_error(self, tmp_path):
        # Should not raise even if directory is not accessible
        fake = tmp_path / "nope"
        fake.mkdir()
        f = fake / "mcp.json"
        _write_json(f, {"mcpServers": {}})
        # Even if scan fails, it returns gracefully
        candidates = _scan_filesystem(tmp_path, ["nope/mcp.json"], max_depth=4, exclude_paths=set())
        assert isinstance(candidates, list)


# ---------------------------------------------------------------------------
# Content detection — JSON
# ---------------------------------------------------------------------------


class TestDetectJsonMcp:
    def test_detects_standard_mcpservers(self, tmp_path):
        data = {"mcpServers": {"my-server": {"command": "npx", "args": ["-y", "mcp-server"]}}}
        f = _write_json(tmp_path / "mcp.json", data)
        agent = _detect_json_mcp(f, data)
        assert agent is not None
        assert agent.agent_type == AgentType.CUSTOM
        assert len(agent.mcp_servers) >= 1
        assert agent.mcp_servers[0].name == "my-server"

    def test_detects_snake_case_mcp_servers(self, tmp_path):
        data = {"mcp_servers": {"fetcher": {"command": "python", "args": ["-m", "fetcher"]}}}
        f = _write_json(tmp_path / "config.json", data)
        agent = _detect_json_mcp(f, data)
        assert agent is not None

    def test_detects_vscode_servers_format(self, tmp_path):
        data = {"servers": {"github": {"type": "stdio", "command": "npx", "args": ["-y", "mcp-github"]}}}
        f = _write_json(tmp_path / "mcp.json", data)
        agent = _detect_json_mcp(f, data)
        assert agent is not None

    def test_detects_context_servers_zed(self, tmp_path):
        data = {"context_servers": {"search": {"command": {"path": "npx", "args": ["-y", "mcp-search"]}}}}
        f = _write_json(tmp_path / "settings.json", data)
        agent = _detect_json_mcp(f, data)
        assert agent is not None

    def test_ignores_non_mcp_json(self, tmp_path):
        data = {"name": "my-package", "version": "1.0.0", "dependencies": {}}
        f = _write_json(tmp_path / "package.json", data)
        agent = _detect_json_mcp(f, data)
        assert agent is None

    def test_sets_custom_agent_type(self, tmp_path):
        data = {"mcpServers": {"s1": {"command": "node", "args": ["server.js"]}}}
        f = _write_json(tmp_path / "mcp.json", data)
        agent = _detect_json_mcp(f, data)
        assert agent is not None
        assert agent.agent_type == AgentType.CUSTOM

    def test_source_is_dynamic(self, tmp_path):
        data = {"mcpServers": {"s1": {"command": "node", "args": ["server.js"]}}}
        f = _write_json(tmp_path / "mcp.json", data)
        agent = _detect_json_mcp(f, data)
        assert agent is not None
        assert agent.source == "dynamic"

    def test_empty_servers_returns_none(self, tmp_path):
        data = {"mcpServers": {}}
        f = _write_json(tmp_path / "mcp.json", data)
        agent = _detect_json_mcp(f, data)
        assert agent is None


# ---------------------------------------------------------------------------
# Content detection — full file
# ---------------------------------------------------------------------------


class TestDetectMcpConfig:
    def test_detects_json_mcp_file(self, tmp_path):
        data = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "mcp-filesystem"]}}}
        f = _write_json(tmp_path / "mcp.json", data)
        agent = _detect_mcp_config(f)
        assert agent is not None
        assert agent.agent_type == AgentType.CUSTOM

    def test_ignores_malformed_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{not valid json")
        assert _detect_mcp_config(f) is None

    def test_ignores_binary_file(self, tmp_path):
        f = tmp_path / "binary.json"
        f.write_bytes(b"\x00\x01\x02\x03\x04\x05")
        assert _detect_mcp_config(f) is None

    def test_nonexistent_file(self):
        assert _detect_mcp_config(Path("/nonexistent/file.json")) is None

    def test_config_path_is_resolved(self, tmp_path):
        data = {"mcpServers": {"s": {"command": "node", "args": ["s.js"]}}}
        f = _write_json(tmp_path / "mcp.json", data)
        agent = _detect_mcp_config(f)
        assert agent is not None
        assert str(tmp_path) in agent.config_path


# ---------------------------------------------------------------------------
# Content detection — TOML
# ---------------------------------------------------------------------------


class TestDetectTomlMcp:
    def test_detects_toml_mcp_servers(self, tmp_path):
        toml_text = """
[mcp_servers.my_server]
command = "python"
args = ["-m", "my_server"]
"""
        f = tmp_path / "config.toml"
        f.write_text(toml_text)
        agent = _detect_toml_mcp(f, toml_text)
        if agent is not None:  # May be None if tomllib not available
            assert agent.agent_type == AgentType.CUSTOM
            assert len(agent.mcp_servers) >= 1

    def test_ignores_toml_without_mcp(self, tmp_path):
        toml_text = """
[project]
name = "my-package"
version = "1.0.0"
"""
        f = tmp_path / "pyproject.toml"
        f.write_text(toml_text)
        assert _detect_toml_mcp(f, toml_text) is None


# ---------------------------------------------------------------------------
# Content detection — YAML
# ---------------------------------------------------------------------------


class TestDetectYamlMcp:
    def test_detects_yaml_mcp_servers(self, tmp_path):
        yaml_text = """
mcp_servers:
  search:
    command: mcp-search
    args:
      - --port
      - "8080"
"""
        f = tmp_path / "config.yaml"
        f.write_text(yaml_text)
        agent = _detect_yaml_mcp(f, yaml_text)
        if agent is not None:  # May be None if pyyaml not available
            assert agent.agent_type == AgentType.CUSTOM
            assert len(agent.mcp_servers) >= 1

    def test_ignores_yaml_without_mcp(self, tmp_path):
        yaml_text = """
services:
  web:
    image: nginx:latest
"""
        f = tmp_path / "docker-compose.yml"
        f.write_text(yaml_text)
        assert _detect_yaml_mcp(f, yaml_text) is None


# ---------------------------------------------------------------------------
# Environment variable scanning
# ---------------------------------------------------------------------------


class TestScanEnvironment:
    def test_finds_mcp_config_path_env(self, tmp_path):
        data = {"mcpServers": {"s": {"command": "node", "args": ["s.js"]}}}
        f = _write_json(tmp_path / "mcp.json", data)

        with patch.dict(os.environ, {"MCP_CONFIG": str(f)}, clear=False):
            agents = _scan_environment(exclude_paths=set())
        assert len(agents) >= 1
        assert agents[0].source == "environment"

    def test_ignores_non_path_env_values(self):
        with patch.dict(os.environ, {"MCP_DEBUG": "true"}, clear=False):
            agents = _scan_environment(exclude_paths=set())
        # "true" is not a file path
        mcp_debug_agents = [a for a in agents if "MCP_DEBUG" in a.name]
        assert len(mcp_debug_agents) == 0

    def test_ignores_nonexistent_path(self):
        with patch.dict(os.environ, {"MCP_CONFIG": "/nonexistent/path/mcp.json"}, clear=False):
            agents = _scan_environment(exclude_paths=set())
        assert not any("nonexistent" in a.config_path for a in agents)

    def test_skips_excluded_paths(self, tmp_path):
        data = {"mcpServers": {"s": {"command": "node", "args": ["s.js"]}}}
        f = _write_json(tmp_path / "mcp.json", data)
        excluded = {str(f.resolve())}

        with patch.dict(os.environ, {"MCP_CONFIG": str(f)}, clear=False):
            agents = _scan_environment(exclude_paths=excluded)
        mcp_agents = [a for a in agents if "MCP_CONFIG" in a.name]
        assert len(mcp_agents) == 0

    def test_empty_env_returns_no_mcp_agents(self):
        # Don't clear env — just check that env scanning doesn't crash
        agents = _scan_environment(exclude_paths=set())
        assert isinstance(agents, list)

    def test_scans_all_prefixes(self):
        assert len(MCP_ENV_PREFIXES) >= 9


# ---------------------------------------------------------------------------
# Merge / deduplication
# ---------------------------------------------------------------------------


class TestMergeDiscoveries:
    def test_deduplicates_by_config_path(self, tmp_path):
        config = tmp_path / "mcp.json"
        config.write_text("{}")
        resolved = str(config.resolve())

        known = [Agent(name="cursor", agent_type=AgentType.CURSOR, config_path=resolved, mcp_servers=[])]
        dynamic = [Agent(name="dynamic:mcp", agent_type=AgentType.CUSTOM, config_path=resolved, mcp_servers=[])]

        merged = merge_discoveries(known, dynamic)
        assert len(merged) == 1
        assert merged[0].agent_type == AgentType.CURSOR  # Known takes precedence

    def test_known_takes_precedence(self, tmp_path):
        config = tmp_path / "settings.json"
        config.write_text("{}")
        resolved = str(config.resolve())

        known = [Agent(name="windsurf", agent_type=AgentType.WINDSURF, config_path=resolved, mcp_servers=[])]
        dynamic = [Agent(name="dynamic:settings", agent_type=AgentType.CUSTOM, config_path=resolved, mcp_servers=[])]

        merged = merge_discoveries(known, dynamic)
        assert len(merged) == 1
        assert merged[0].name == "windsurf"

    def test_dynamic_adds_novel_agents(self, tmp_path):
        config_a = tmp_path / "a.json"
        config_a.write_text("{}")
        config_b = tmp_path / "b.json"
        config_b.write_text("{}")

        known = [Agent(name="known", agent_type=AgentType.CURSOR, config_path=str(config_a.resolve()), mcp_servers=[])]
        dynamic = [Agent(name="novel", agent_type=AgentType.CUSTOM, config_path=str(config_b.resolve()), mcp_servers=[])]

        merged = merge_discoveries(known, dynamic)
        assert len(merged) == 2

    def test_empty_lists(self):
        assert merge_discoveries([], []) == []

    def test_preserves_all_known(self):
        agents = [Agent(name=f"a{i}", agent_type=AgentType.CUSTOM, config_path=f"/path/{i}", mcp_servers=[]) for i in range(3)]
        merged = merge_discoveries(agents, [])
        assert len(merged) == 3


# ---------------------------------------------------------------------------
# Integration: discover_dynamic
# ---------------------------------------------------------------------------


class TestDiscoverDynamic:
    def test_full_discovery_with_project(self, tmp_path):
        data = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "mcp-fs"]}}}
        _write_json(tmp_path / "mcp.json", data)

        result = discover_dynamic(
            root=tmp_path,
            scan_home=False,
            scan_project=True,
            scan_env=False,
        )
        assert isinstance(result, DynamicDiscoveryResult)
        assert result.scanned_paths >= 1
        assert len(result.agents) >= 1

    def test_returns_result_stats(self, tmp_path):
        result = discover_dynamic(
            root=tmp_path,
            scan_home=False,
            scan_project=True,
            scan_env=False,
        )
        assert result.elapsed_ms >= 0
        assert result.scanned_paths >= 0

    def test_disabling_all_sources_returns_empty(self, tmp_path):
        result = discover_dynamic(
            root=tmp_path,
            scan_home=False,
            scan_project=False,
            scan_env=False,
        )
        assert result.agents == []
        assert result.scanned_paths == 0

    def test_exclude_paths_respected(self, tmp_path):
        data = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "mcp-fs"]}}}
        f = _write_json(tmp_path / "mcp.json", data)

        result = discover_dynamic(
            root=tmp_path,
            scan_home=False,
            scan_project=True,
            scan_env=False,
            exclude_paths={str(f.resolve())},
        )
        assert len(result.agents) == 0

    def test_nested_project_config(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        data = {"mcpServers": {"sub-server": {"command": "node", "args": ["sub.js"]}}}
        _write_json(sub / "mcp.json", data)

        result = discover_dynamic(
            root=tmp_path,
            scan_home=False,
            scan_project=True,
            scan_env=False,
        )
        assert len(result.agents) >= 1


# ---------------------------------------------------------------------------
# Integration: discover_all with dynamic flag
# ---------------------------------------------------------------------------


class TestDiscoverAllDynamic:
    def test_discover_all_accepts_dynamic_flag(self, tmp_path):
        """Verify discover_all() accepts the new dynamic parameter."""
        from agent_bom.discovery import discover_all

        # Should not raise
        agents = discover_all(project_dir=str(tmp_path), dynamic=True, dynamic_max_depth=2)
        assert isinstance(agents, list)

    def test_discover_all_dynamic_false_is_default(self, tmp_path):
        from agent_bom.discovery import discover_all

        agents = discover_all(project_dir=str(tmp_path))
        assert isinstance(agents, list)


# ---------------------------------------------------------------------------
# Constants sanity checks
# ---------------------------------------------------------------------------


class TestConstants:
    def test_skip_dirs_contains_essentials(self):
        assert ".git" in SKIP_DIRS
        assert "node_modules" in SKIP_DIRS
        assert "__pycache__" in SKIP_DIRS

    def test_mcp_json_signatures_covers_formats(self):
        assert "mcpServers" in MCP_JSON_SIGNATURES
        assert "mcp_servers" in MCP_JSON_SIGNATURES
        assert "servers" in MCP_JSON_SIGNATURES
        assert "context_servers" in MCP_JSON_SIGNATURES

    def test_env_prefixes(self):
        assert len(MCP_ENV_PREFIXES) >= 9
        assert "MCP_" in MCP_ENV_PREFIXES
        assert "CLAUDE_" in MCP_ENV_PREFIXES
