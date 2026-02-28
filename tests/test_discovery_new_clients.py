"""Tests for new CLI client discovery: Codex CLI, Gemini CLI, Goose, Snowflake CLI, Cortex Code."""

import json

import toml
import yaml

from agent_bom.discovery import (
    AGENT_BINARIES,
    CONFIG_LOCATIONS,
    PROJECT_CONFIG_FILES,
    get_all_discovery_paths,
    parse_codex_config,
    parse_cortex_code_metadata,
    parse_goose_config,
    parse_snowflake_connections,
)
from agent_bom.models import AgentType, TransportType

# ── 1. AgentType enum existence ────────────────────────────────────────────


def test_codex_cli_agent_type_exists():
    assert AgentType.CODEX_CLI.value == "codex-cli"


def test_gemini_cli_agent_type_exists():
    assert AgentType.GEMINI_CLI.value == "gemini-cli"


def test_goose_agent_type_exists():
    assert AgentType.GOOSE.value == "goose"


def test_snowflake_cli_agent_type_exists():
    assert AgentType.SNOWFLAKE_CLI.value == "snowflake-cli"


# ── 2. CONFIG_LOCATIONS entries ────────────────────────────────────────────


def test_codex_cli_in_config_locations():
    assert AgentType.CODEX_CLI in CONFIG_LOCATIONS
    paths = CONFIG_LOCATIONS[AgentType.CODEX_CLI]
    assert "Darwin" in paths
    assert any("config.toml" in p for p in paths["Darwin"])


def test_gemini_cli_in_config_locations():
    assert AgentType.GEMINI_CLI in CONFIG_LOCATIONS
    paths = CONFIG_LOCATIONS[AgentType.GEMINI_CLI]
    assert "Darwin" in paths
    assert any("settings.json" in p for p in paths["Darwin"])


def test_goose_in_config_locations():
    assert AgentType.GOOSE in CONFIG_LOCATIONS
    paths = CONFIG_LOCATIONS[AgentType.GOOSE]
    assert "Darwin" in paths
    assert any("config.yaml" in p for p in paths["Darwin"])


def test_snowflake_cli_in_config_locations():
    assert AgentType.SNOWFLAKE_CLI in CONFIG_LOCATIONS
    paths = CONFIG_LOCATIONS[AgentType.SNOWFLAKE_CLI]
    assert "Darwin" in paths
    assert any("connections.toml" in p for p in paths["Darwin"])


def test_cortex_code_has_full_config_paths():
    """Cortex Code should have mcp.json, settings, permissions, and hooks."""
    paths = CONFIG_LOCATIONS[AgentType.CORTEX_CODE]
    darwin_paths = paths["Darwin"]
    assert any("mcp.json" in p for p in darwin_paths)
    assert any("settings.json" in p for p in darwin_paths)
    assert any("permissions.json" in p for p in darwin_paths)
    assert any("hooks.json" in p for p in darwin_paths)


# ── 3. AGENT_BINARIES entries ──────────────────────────────────────────────


def test_cortex_code_in_agent_binaries():
    assert AgentType.CORTEX_CODE in AGENT_BINARIES
    assert AGENT_BINARIES[AgentType.CORTEX_CODE] == "cortex"


def test_codex_cli_in_agent_binaries():
    assert AgentType.CODEX_CLI in AGENT_BINARIES
    assert AGENT_BINARIES[AgentType.CODEX_CLI] == "codex"


def test_gemini_cli_in_agent_binaries():
    assert AgentType.GEMINI_CLI in AGENT_BINARIES
    assert AGENT_BINARIES[AgentType.GEMINI_CLI] == "gemini"


def test_goose_in_agent_binaries():
    assert AgentType.GOOSE in AGENT_BINARIES
    assert AGENT_BINARIES[AgentType.GOOSE] == "goose"


def test_snowflake_cli_in_agent_binaries():
    assert AgentType.SNOWFLAKE_CLI in AGENT_BINARIES
    assert AGENT_BINARIES[AgentType.SNOWFLAKE_CLI] == "snow"


# ── 4. PROJECT_CONFIG_FILES entries ────────────────────────────────────────


def test_codex_project_config_in_list():
    assert ".codex/config.toml" in PROJECT_CONFIG_FILES


def test_gemini_project_config_in_list():
    assert ".gemini/settings.json" in PROJECT_CONFIG_FILES


# ── 5. Codex CLI TOML parser ──────────────────────────────────────────────


def test_parse_codex_stdio_server(tmp_path):
    """Codex TOML config with stdio MCP server."""
    config = {
        "mcp_servers": {
            "context7": {
                "command": "npx",
                "args": ["-y", "@upstash/context7-mcp"],
                "env": {"API_KEY": "secret123"},
                "enabled": True,
            }
        }
    }
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml.dumps(config))

    servers = parse_codex_config(str(config_file))
    assert len(servers) == 1
    assert servers[0].name == "context7"
    assert servers[0].command == "npx"
    assert servers[0].args == ["-y", "@upstash/context7-mcp"]
    assert servers[0].transport == TransportType.STDIO


def test_parse_codex_http_server(tmp_path):
    """Codex TOML config with HTTP MCP server + bearer token."""
    config = {
        "mcp_servers": {
            "figma": {
                "url": "https://mcp.figma.com/mcp",
                "bearer_token_env_var": "FIGMA_OAUTH_TOKEN",
                "enabled": True,
            }
        }
    }
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml.dumps(config))

    servers = parse_codex_config(str(config_file))
    assert len(servers) == 1
    assert servers[0].name == "figma"
    assert servers[0].url == "https://mcp.figma.com/mcp"
    assert servers[0].transport == TransportType.STREAMABLE_HTTP
    assert "FIGMA_OAUTH_TOKEN" in servers[0].env


def test_parse_codex_disabled_server_skipped(tmp_path):
    """Disabled Codex MCP server is not included."""
    config = {
        "mcp_servers": {
            "disabled_server": {
                "command": "npx",
                "args": ["some-server"],
                "enabled": False,
            }
        }
    }
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml.dumps(config))

    servers = parse_codex_config(str(config_file))
    assert len(servers) == 0


def test_parse_codex_empty_config(tmp_path):
    """Empty Codex config returns no servers."""
    config_file = tmp_path / "config.toml"
    config_file.write_text("")

    servers = parse_codex_config(str(config_file))
    assert len(servers) == 0


def test_parse_codex_nonexistent_file():
    """Nonexistent file returns no servers."""
    servers = parse_codex_config("/nonexistent/path/config.toml")
    assert len(servers) == 0


# ── 6. Gemini CLI parser (standard JSON format) ───────────────────────────


def test_gemini_uses_standard_mcp_format(tmp_path):
    """Gemini CLI uses standard mcpServers JSON — verify parse_mcp_config handles it."""
    from agent_bom.discovery import parse_mcp_config

    config = {
        "mcpServers": {
            "agent-bom": {
                "command": "uvx",
                "args": ["agent-bom", "--mcp"],
            }
        }
    }
    servers = parse_mcp_config(config, str(tmp_path / "settings.json"))
    assert len(servers) == 1
    assert servers[0].name == "agent-bom"


def test_gemini_sse_server(tmp_path):
    """Gemini CLI SSE transport via url field."""
    from agent_bom.discovery import parse_mcp_config

    config = {
        "mcpServers": {
            "remote": {
                "url": "http://localhost:8080/sse",
            }
        }
    }
    servers = parse_mcp_config(config, str(tmp_path / "settings.json"))
    assert len(servers) == 1
    assert servers[0].transport == TransportType.SSE


# ── 7. Goose YAML parser ──────────────────────────────────────────────────


def test_parse_goose_stdio_extension(tmp_path):
    """Goose YAML config with stdio extension."""
    config = {
        "extensions": {
            "github": {
                "name": "GitHub",
                "type": "stdio",
                "cmd": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "enabled": True,
                "envs": {"GITHUB_TOKEN": "ghp_xxx"},
                "timeout": 300,
            }
        }
    }
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump(config))

    servers = parse_goose_config(str(config_file))
    assert len(servers) == 1
    assert servers[0].name == "GitHub"
    assert servers[0].command == "npx"
    assert servers[0].transport == TransportType.STDIO


def test_parse_goose_http_extension(tmp_path):
    """Goose YAML config with streamable_http extension."""
    config = {
        "extensions": {
            "remote": {
                "name": "Remote Server",
                "type": "streamable_http",
                "uri": "https://mcp-server.example.com/sse",
                "enabled": True,
            }
        }
    }
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump(config))

    servers = parse_goose_config(str(config_file))
    assert len(servers) == 1
    assert servers[0].name == "Remote Server"
    assert servers[0].transport == TransportType.STREAMABLE_HTTP
    assert servers[0].url == "https://mcp-server.example.com/sse"


def test_parse_goose_builtin_skipped(tmp_path):
    """Goose builtin extensions are skipped."""
    config = {
        "extensions": {
            "developer": {
                "name": "developer",
                "type": "builtin",
                "bundled": True,
                "enabled": True,
            }
        }
    }
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump(config))

    servers = parse_goose_config(str(config_file))
    assert len(servers) == 0


def test_parse_goose_disabled_skipped(tmp_path):
    """Disabled Goose extensions are skipped."""
    config = {
        "extensions": {
            "github": {
                "name": "GitHub",
                "type": "stdio",
                "cmd": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "enabled": False,
            }
        }
    }
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump(config))

    servers = parse_goose_config(str(config_file))
    assert len(servers) == 0


def test_parse_goose_empty_config(tmp_path):
    """Empty Goose config returns no servers."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text("")

    servers = parse_goose_config(str(config_file))
    assert len(servers) == 0


def test_parse_goose_mixed_extensions(tmp_path):
    """Goose config with mix of builtin, stdio, and disabled extensions."""
    config = {
        "extensions": {
            "developer": {
                "name": "developer",
                "type": "builtin",
                "bundled": True,
                "enabled": True,
            },
            "github": {
                "name": "GitHub",
                "type": "stdio",
                "cmd": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "enabled": True,
                "envs": {"GITHUB_TOKEN": "ghp_xxx"},
            },
            "disabled_one": {
                "name": "Disabled",
                "type": "stdio",
                "cmd": "some-cmd",
                "enabled": False,
            },
        }
    }
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump(config))

    servers = parse_goose_config(str(config_file))
    assert len(servers) == 1
    assert servers[0].name == "GitHub"


# ── 8. Snowflake CLI connections parser ────────────────────────────────────


def test_parse_snowflake_connections_toml(tmp_path):
    """Parse Snowflake connections.toml with connection profiles."""
    config = {
        "myconnection": {
            "account": "myorg-myaccount",
            "user": "jdoe",
            "password": "secret",
            "warehouse": "my-wh",
            "database": "my_db",
        },
        "prod": {
            "account": "myorg-prod",
            "user": "svc_user",
            "authenticator": "SNOWFLAKE_JWT",
            "private_key_file": "/path/to/key.p8",
        },
    }
    config_file = tmp_path / "connections.toml"
    config_file.write_text(toml.dumps(config))

    servers = parse_snowflake_connections(str(config_file))
    assert len(servers) == 2
    names = {s.name for s in servers}
    assert "sf-connection:myconnection" in names
    assert "sf-connection:prod" in names

    # Password should be redacted
    my_conn = [s for s in servers if "myconnection" in s.name][0]
    assert my_conn.env.get("password") == "***REDACTED***"
    assert my_conn.env.get("account") == "myorg-myaccount"


def test_parse_snowflake_config_toml_nested(tmp_path):
    """Parse Snowflake config.toml with [connections.*] sections."""
    config = {
        "default_connection_name": "dev",
        "connections": {
            "dev": {
                "account": "myorg-dev",
                "user": "developer",
            },
        },
        "cli": {
            "logs": {"save_logs": True},
        },
    }
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml.dumps(config))

    servers = parse_snowflake_connections(str(config_file))
    assert len(servers) == 1
    assert servers[0].name == "sf-connection:dev"
    assert servers[0].env.get("account") == "myorg-dev"


def test_parse_snowflake_empty_config(tmp_path):
    """Empty Snowflake config returns no servers."""
    config_file = tmp_path / "connections.toml"
    config_file.write_text("")

    servers = parse_snowflake_connections(str(config_file))
    assert len(servers) == 0


# ── 9. Cortex Code metadata parser ────────────────────────────────────────


def test_parse_cortex_permissions(tmp_path):
    """Cortex Code permissions.json parsed as metadata."""
    perms = {
        "/path/to/project": {
            "Bash": {"npm test": "allow"},
            "Write": {"*": "allow"},
        }
    }
    perms_file = tmp_path / "permissions.json"
    perms_file.write_text(json.dumps(perms))

    metadata = parse_cortex_code_metadata(str(perms_file))
    assert "cortex_permissions" in metadata
    assert "/path/to/project" in metadata["cortex_permissions"]


def test_parse_cortex_hooks(tmp_path):
    """Cortex Code hooks.json parsed as metadata."""
    hooks = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "validate.sh"}],
                }
            ]
        }
    }
    hooks_file = tmp_path / "hooks.json"
    hooks_file.write_text(json.dumps(hooks))

    metadata = parse_cortex_code_metadata(str(hooks_file))
    assert "cortex_hooks" in metadata


def test_parse_cortex_settings(tmp_path):
    """Cortex Code settings.json (non-MCP) parsed as metadata."""
    settings = {"compactMode": True, "autoUpdate": True}
    settings_file = tmp_path / "settings.json"
    settings_file.write_text(json.dumps(settings))

    metadata = parse_cortex_code_metadata(str(settings_file))
    assert "cortex_settings" in metadata


def test_parse_cortex_mcp_settings_not_metadata(tmp_path):
    """settings.json with mcpServers should not be returned as metadata."""
    settings = {"mcpServers": {"server1": {"command": "cmd"}}}
    settings_file = tmp_path / "settings.json"
    settings_file.write_text(json.dumps(settings))

    metadata = parse_cortex_code_metadata(str(settings_file))
    assert metadata == {}


# ── 10. Discovery path enumeration ────────────────────────────────────────


def test_discovery_paths_include_new_clients():
    """get_all_discovery_paths() includes all new client paths."""
    paths = get_all_discovery_paths("Darwin")
    client_names = {name for name, _ in paths}
    assert "codex-cli" in client_names
    assert "gemini-cli" in client_names
    assert "goose" in client_names
    assert "snowflake-cli" in client_names
    assert "cortex-code" in client_names


def test_total_agent_types_is_18():
    """AgentType enum should now have 18 values (14 original + 4 new)."""
    assert len(AgentType) == 19  # 14 + 4 new + CUSTOM


# ── 11. Binary detection ──────────────────────────────────────────────────


def test_detect_cortex_binary(monkeypatch):
    """Cortex binary on PATH detected as installed-not-configured."""
    import shutil

    from agent_bom.discovery import detect_installed_agents

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/local/bin/cortex" if cmd == "cortex" else None)

    installed = detect_installed_agents(discovered_types=set())
    agent_types = {a.agent_type for a in installed}
    assert AgentType.CORTEX_CODE in agent_types


def test_detect_codex_binary(monkeypatch):
    """Codex binary on PATH detected as installed-not-configured."""
    import shutil

    from agent_bom.discovery import detect_installed_agents

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/local/bin/codex" if cmd == "codex" else None)

    installed = detect_installed_agents(discovered_types=set())
    agent_types = {a.agent_type for a in installed}
    assert AgentType.CODEX_CLI in agent_types


def test_detect_goose_binary(monkeypatch):
    """Goose binary on PATH detected as installed-not-configured."""
    import shutil

    from agent_bom.discovery import detect_installed_agents

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/local/bin/goose" if cmd == "goose" else None)

    installed = detect_installed_agents(discovered_types=set())
    agent_types = {a.agent_type for a in installed}
    assert AgentType.GOOSE in agent_types


def test_detect_snow_binary(monkeypatch):
    """snow binary on PATH detected as installed-not-configured."""
    import shutil

    from agent_bom.discovery import detect_installed_agents

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/local/bin/snow" if cmd == "snow" else None)

    installed = detect_installed_agents(discovered_types=set())
    agent_types = {a.agent_type for a in installed}
    assert AgentType.SNOWFLAKE_CLI in agent_types
