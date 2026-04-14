"""Tests for proxy auto-configure (#302).

Tests cover:
- auto_configure_proxies(): generates ProxyConfig for STDIO servers
- Skips SSE/HTTP servers (no stdio pipe)
- Skips servers with empty command
- policy_path injects --policy flag
- log_dir injects --log flag with slugified filename
- detect_credentials injects --detect-credentials flag
- block_undeclared injects --block-undeclared flag
- ProxyConfig.as_json_entry() structure
- apply_proxy_configs() dry_run=True returns 0, no file changes
- apply_proxy_configs() patches mcpServers in JSON config file
- apply_proxy_configs() skips non-JSON config paths
- apply_proxy_configs() gracefully handles missing files
- Multiple agents / servers in one call
- Server name slug sanitization in log filename
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from agent_bom.models import Agent, AgentType, MCPServer, TransportType
from agent_bom.proxy_configure import ProxyConfig, apply_proxy_configs, auto_configure_proxies

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _agent(servers: list[MCPServer], config_path: str = "/tmp/mcp.json") -> Agent:
    return Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path=config_path,
        mcp_servers=servers,
    )


def _stdio(name: str = "fs", command: str = "npx", args: list | None = None, config_path: str = "/tmp/mcp.json") -> MCPServer:
    return MCPServer(
        name=name,
        command=command,
        args=args or ["@modelcontextprotocol/server-fs", "/tmp"],
        transport=TransportType.STDIO,
        config_path=config_path,
    )


def _sse(name: str = "remote") -> MCPServer:
    return MCPServer(name=name, command="", url="http://localhost:9000", transport=TransportType.SSE)


# ─── auto_configure_proxies() ─────────────────────────────────────────────────


def test_generates_config_for_stdio_server():
    agents = [_agent([_stdio()])]
    configs = auto_configure_proxies(agents)
    assert len(configs) == 1
    cfg = configs[0]
    assert cfg.server_name == "fs"
    assert cfg.proxied_command == "agent-bom"
    assert "--" in cfg.proxied_args
    assert "npx" in cfg.proxied_args
    assert "@modelcontextprotocol/server-fs" in cfg.proxied_args
    assert "--detect-credentials" in cfg.proxied_args
    assert "--block-undeclared" in cfg.proxied_args


def test_skips_sse_server():
    agents = [_agent([_sse()])]
    configs = auto_configure_proxies(agents)
    assert configs == []


def test_skips_server_with_empty_command():
    server = MCPServer(name="no-cmd", command="", transport=TransportType.STDIO)
    agents = [_agent([server])]
    configs = auto_configure_proxies(agents)
    assert configs == []


def test_policy_path_injected():
    agents = [_agent([_stdio()])]
    configs = auto_configure_proxies(agents, policy_path="/etc/policy.json")
    cfg = configs[0]
    assert "--policy" in cfg.proxied_args
    assert "/etc/policy.json" in cfg.proxied_args


def test_log_dir_injected():
    agents = [_agent([_stdio(name="my-server")])]
    configs = auto_configure_proxies(agents, log_dir="/var/log/agent-bom")
    cfg = configs[0]
    assert "--log" in cfg.proxied_args
    log_arg = cfg.proxied_args[cfg.proxied_args.index("--log") + 1]
    assert "/var/log/agent-bom" in log_arg
    assert ".jsonl" in log_arg


def test_detect_credentials_injected():
    agents = [_agent([_stdio()])]
    configs = auto_configure_proxies(agents, detect_credentials=True)
    assert "--detect-credentials" in configs[0].proxied_args


def test_block_undeclared_injected():
    agents = [_agent([_stdio()])]
    configs = auto_configure_proxies(agents, block_undeclared=True)
    assert "--block-undeclared" in configs[0].proxied_args


def test_all_flags_together():
    agents = [_agent([_stdio()])]
    configs = auto_configure_proxies(
        agents,
        policy_path="/p.json",
        log_dir="/logs",
        detect_credentials=True,
        block_undeclared=True,
    )
    args = configs[0].proxied_args
    assert "--policy" in args
    assert "--log" in args
    assert "--detect-credentials" in args
    assert "--block-undeclared" in args


def test_no_flags_minimal_proxied_args():
    server = _stdio(command="uvx", args=["mcp-server-git"])
    agents = [_agent([server])]
    configs = auto_configure_proxies(agents, secure_defaults=False)
    cfg = configs[0]
    # Should be: ["--", "uvx", "mcp-server-git"]
    assert cfg.proxied_args == ["--", "uvx", "mcp-server-git"]


def test_secure_defaults_can_be_disabled():
    agents = [_agent([_stdio()])]
    configs = auto_configure_proxies(agents, secure_defaults=False)
    args = configs[0].proxied_args
    assert "--detect-credentials" not in args
    assert "--block-undeclared" not in args


def test_original_command_and_args_preserved():
    server = _stdio(command="python", args=["-m", "mcp_server"])
    agents = [_agent([server])]
    cfg = auto_configure_proxies(agents)[0]
    assert cfg.original_command == "python"
    assert cfg.original_args == ["-m", "mcp_server"]


def test_multiple_servers_across_agents():
    a1 = _agent([_stdio("s1"), _stdio("s2")])
    a2 = _agent([_stdio("s3")])
    configs = auto_configure_proxies([a1, a2])
    assert len(configs) == 3
    names = {c.server_name for c in configs}
    assert names == {"s1", "s2", "s3"}


def test_mixed_transports_only_stdio_included():
    servers = [_stdio("good"), _sse("skip-me")]
    agents = [_agent(servers)]
    configs = auto_configure_proxies(agents)
    assert len(configs) == 1
    assert configs[0].server_name == "good"


# ─── ProxyConfig.as_json_entry() ──────────────────────────────────────────────


def test_as_json_entry_structure():
    cfg = ProxyConfig(
        server_name="fs",
        config_path="/tmp/mcp.json",
        original_command="npx",
        original_args=["@mcp/server-fs"],
        proxied_args=["--", "npx", "@mcp/server-fs"],
    )
    entry = cfg.as_json_entry()
    assert entry["command"] == "agent-bom"
    assert entry["args"] == ["--", "npx", "@mcp/server-fs"]


def test_as_json_entry_serializable():
    cfg = ProxyConfig(
        server_name="x",
        config_path="/tmp/x.json",
        original_command="node",
        original_args=["server.js"],
        proxied_args=["--", "node", "server.js"],
    )
    # Should not raise
    json.dumps(cfg.as_json_entry())


# ─── log filename slugification ───────────────────────────────────────────────


def test_log_filename_slugified():
    server = _stdio(name="my/weird server:name!")
    agents = [_agent([server])]
    configs = auto_configure_proxies(agents, log_dir="/logs")
    log_arg = configs[0].proxied_args[configs[0].proxied_args.index("--log") + 1]
    # Special chars replaced with underscores
    assert "/" not in Path(log_arg).name.replace("/", "")
    assert ".jsonl" in log_arg


# ─── apply_proxy_configs() ────────────────────────────────────────────────────


def test_apply_dry_run_returns_zero():
    cfg = ProxyConfig(
        server_name="fs",
        config_path="/nonexistent/path.json",
        original_command="npx",
        original_args=[],
        proxied_args=["--", "npx"],
    )
    result = apply_proxy_configs([cfg], dry_run=True)
    assert result == 0


def test_apply_patches_mcp_servers_in_json():
    data = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-filesystem", "/tmp"],
            }
        }
    }
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump(data, f)
        tmp_path = f.name

    try:
        cfg = ProxyConfig(
            server_name="filesystem",
            config_path=tmp_path,
            original_command="npx",
            original_args=["@modelcontextprotocol/server-filesystem", "/tmp"],
            proxied_args=["--", "npx", "@modelcontextprotocol/server-filesystem", "/tmp"],
        )
        result = apply_proxy_configs([cfg], dry_run=False)
        assert result == 1

        patched = json.loads(Path(tmp_path).read_text())
        entry = patched["mcpServers"]["filesystem"]
        assert entry["command"] == "agent-bom"
        assert entry["args"][0] == "--"
    finally:
        os.unlink(tmp_path)


def test_apply_skips_non_json_config():
    cfg = ProxyConfig(
        server_name="srv",
        config_path="/etc/config.toml",
        original_command="npx",
        original_args=[],
        proxied_args=["--", "npx"],
    )
    result = apply_proxy_configs([cfg], dry_run=False)
    assert result == 0


def test_apply_handles_missing_file_gracefully():
    cfg = ProxyConfig(
        server_name="srv",
        config_path="/totally/nonexistent/file.json",
        original_command="npx",
        original_args=[],
        proxied_args=["--", "npx"],
    )
    # Should not raise
    result = apply_proxy_configs([cfg], dry_run=False)
    assert result == 0


def test_apply_uses_servers_key_fallback():
    """Some clients use 'servers' instead of 'mcpServers'."""
    data = {"servers": {"my-srv": {"command": "uvx", "args": ["mcp-git"]}}}
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump(data, f)
        tmp_path = f.name

    try:
        cfg = ProxyConfig(
            server_name="my-srv",
            config_path=tmp_path,
            original_command="uvx",
            original_args=["mcp-git"],
            proxied_args=["--", "uvx", "mcp-git"],
        )
        result = apply_proxy_configs([cfg], dry_run=False)
        assert result == 1
        patched = json.loads(Path(tmp_path).read_text())
        assert patched["servers"]["my-srv"]["command"] == "agent-bom"
    finally:
        os.unlink(tmp_path)
