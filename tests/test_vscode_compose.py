"""Tests for VS Code native MCP format and Docker Compose discovery."""

from __future__ import annotations

import yaml

from agent_bom.models import TransportType

# ── VS Code Native MCP Format ────────────────────────────────────────────────


def test_vscode_servers_key_parsed():
    """VS Code mcp.json with 'servers' key (not 'mcpServers') is parsed."""
    from agent_bom.discovery import parse_mcp_config

    config = {
        "servers": {
            "my-server": {
                "type": "stdio",
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            }
        }
    }
    servers = parse_mcp_config(config, "/fake/mcp.json")
    assert len(servers) == 1
    assert servers[0].name == "my-server"
    assert servers[0].command == "npx"
    assert servers[0].transport == TransportType.STDIO


def test_vscode_http_type_parsed():
    """VS Code mcp.json with type='http' and 'uri' is parsed as STREAMABLE_HTTP."""
    from agent_bom.discovery import parse_mcp_config

    config = {
        "servers": {
            "remote-server": {
                "type": "http",
                "uri": "http://localhost:3000/mcp",
            }
        }
    }
    servers = parse_mcp_config(config, "/fake/mcp.json")
    assert len(servers) == 1
    assert servers[0].name == "remote-server"
    assert servers[0].transport == TransportType.STREAMABLE_HTTP
    assert servers[0].url == "http://localhost:3000/mcp"


def test_vscode_sse_type_parsed():
    """VS Code mcp.json with type='sse' is parsed as SSE transport."""
    from agent_bom.discovery import parse_mcp_config

    config = {
        "servers": {
            "sse-server": {
                "type": "sse",
                "uri": "http://localhost:8080/events",
            }
        }
    }
    servers = parse_mcp_config(config, "/fake/mcp.json")
    assert len(servers) == 1
    assert servers[0].transport == TransportType.SSE
    assert servers[0].url == "http://localhost:8080/events"


def test_vscode_env_vars_redacted():
    """VS Code server env vars with sensitive names are redacted."""
    from agent_bom.discovery import parse_mcp_config

    config = {
        "servers": {
            "github": {
                "type": "stdio",
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {
                    "GITHUB_TOKEN": "ghp_secret123",
                    "NODE_ENV": "production",
                },
            }
        }
    }
    servers = parse_mcp_config(config, "/fake/mcp.json")
    assert len(servers) == 1
    # Token should be redacted, NODE_ENV preserved
    assert servers[0].env.get("GITHUB_TOKEN") == "***REDACTED***"


def test_vscode_uri_fallback_to_url():
    """Parser handles both 'uri' (VS Code) and 'url' (standard) fields."""
    from agent_bom.discovery import parse_mcp_config

    # Standard format with "url"
    config1 = {
        "mcpServers": {
            "remote": {
                "url": "http://localhost:9000/mcp",
            }
        }
    }
    servers1 = parse_mcp_config(config1, "/fake/config.json")
    assert len(servers1) == 1
    assert servers1[0].url == "http://localhost:9000/mcp"

    # VS Code format with "uri"
    config2 = {
        "servers": {
            "remote": {
                "uri": "http://localhost:9000/mcp",
            }
        }
    }
    servers2 = parse_mcp_config(config2, "/fake/mcp.json")
    assert len(servers2) == 1
    assert servers2[0].url == "http://localhost:9000/mcp"


# ── Docker Compose MCP Discovery ─────────────────────────────────────────────


def test_compose_discovers_mcp_services(tmp_path):
    """Docker Compose file with mcp/ image services are discovered."""
    from agent_bom.discovery import discover_compose_mcp_servers

    compose = {
        "version": "3.8",
        "services": {
            "playwright": {
                "image": "mcp/playwright:latest",
                "environment": {
                    "DISPLAY": ":99",
                },
            },
            "fetch": {
                "image": "mcp/fetch:latest",
            },
            "redis": {
                "image": "redis:7-alpine",
            },
        },
    }
    (tmp_path / "docker-compose.yml").write_text(yaml.dump(compose))

    agent = discover_compose_mcp_servers(str(tmp_path))
    assert agent is not None
    assert len(agent.mcp_servers) == 2  # playwright + fetch, NOT redis
    names = {s.name for s in agent.mcp_servers}
    assert names == {"playwright", "fetch"}


def test_compose_extracts_env_vars(tmp_path):
    """Docker Compose env vars in list format are extracted and redacted."""
    from agent_bom.discovery import discover_compose_mcp_servers

    compose = {
        "services": {
            "github-mcp": {
                "image": "mcp/github",
                "environment": [
                    "GITHUB_TOKEN=ghp_secret",
                    "NODE_ENV=production",
                ],
            },
        },
    }
    (tmp_path / "compose.yml").write_text(yaml.dump(compose))

    agent = discover_compose_mcp_servers(str(tmp_path))
    assert agent is not None
    assert len(agent.mcp_servers) == 1
    srv = agent.mcp_servers[0]
    assert srv.env.get("GITHUB_TOKEN") == "***REDACTED***"


def test_compose_creates_docker_packages(tmp_path):
    """Docker Compose services get Package objects with ecosystem='docker'."""
    from agent_bom.discovery import discover_compose_mcp_servers

    compose = {
        "services": {
            "filesystem": {
                "image": "mcp/filesystem:1.2.3",
            },
        },
    }
    (tmp_path / "docker-compose.yaml").write_text(yaml.dump(compose))

    agent = discover_compose_mcp_servers(str(tmp_path))
    assert agent is not None
    assert len(agent.mcp_servers) == 1
    pkg = agent.mcp_servers[0].packages[0]
    assert pkg.name == "mcp/filesystem"
    assert pkg.version == "1.2.3"
    assert pkg.ecosystem == "docker"


def test_compose_handles_sha_digest(tmp_path):
    """Docker Compose image with sha256 digest extracts short digest as version."""
    from agent_bom.discovery import discover_compose_mcp_servers

    compose = {
        "services": {
            "playwright": {
                "image": "mcp/playwright@sha256:4e403fabcdef1234567890",
            },
        },
    }
    (tmp_path / "compose.yaml").write_text(yaml.dump(compose))

    agent = discover_compose_mcp_servers(str(tmp_path))
    assert agent is not None
    pkg = agent.mcp_servers[0].packages[0]
    assert pkg.name == "mcp/playwright"
    assert pkg.version == "4e403fabcdef"  # First 12 chars


def test_compose_no_mcp_services(tmp_path):
    """Docker Compose with no MCP images returns None."""
    from agent_bom.discovery import discover_compose_mcp_servers

    compose = {
        "services": {
            "redis": {"image": "redis:7-alpine"},
            "postgres": {"image": "postgres:15"},
        },
    }
    (tmp_path / "docker-compose.yml").write_text(yaml.dump(compose))

    agent = discover_compose_mcp_servers(str(tmp_path))
    assert agent is None


def test_compose_no_file(tmp_path):
    """No Compose file returns None."""
    from agent_bom.discovery import discover_compose_mcp_servers

    agent = discover_compose_mcp_servers(str(tmp_path))
    assert agent is None


def test_compose_ghcr_prefix(tmp_path):
    """Docker Compose with ghcr.io MCP image prefix is discovered."""
    from agent_bom.discovery import discover_compose_mcp_servers

    compose = {
        "services": {
            "grafana-mcp": {
                "image": "ghcr.io/modelcontextprotocol/server-grafana:latest",
            },
        },
    }
    (tmp_path / "compose.yml").write_text(yaml.dump(compose))

    agent = discover_compose_mcp_servers(str(tmp_path))
    assert agent is not None
    assert len(agent.mcp_servers) == 1
    assert agent.mcp_servers[0].name == "grafana-mcp"
