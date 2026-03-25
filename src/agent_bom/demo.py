"""Bundled demo inventory for ``agent-bom agents --demo``.

Contains realistic agents with known-vulnerable packages so users can see
a real scan with CVE findings, blast radius, and remediation output.

Includes packages with CRITICAL CVEs (CVSS 9.0+) to demonstrate blast radius
mapping from vulnerability → package → MCP server → agent → credentials → tools.
"""

from __future__ import annotations

DEMO_INVENTORY: dict = {
    "agents": [
        {
            "name": "cursor",
            "agent_type": "cursor",
            "source": "agent-bom --demo",
            "mcp_servers": [
                {
                    "name": "filesystem-server",
                    "command": "npx @modelcontextprotocol/server-filesystem /",
                    "transport": "stdio",
                    "packages": [
                        {"name": "express", "version": "4.17.1", "ecosystem": "npm"},
                        {"name": "node-fetch", "version": "2.6.1", "ecosystem": "npm"},
                        {"name": "jsonwebtoken", "version": "8.5.1", "ecosystem": "npm"},
                    ],
                    "tools": [
                        {"name": "read_file"},
                        {"name": "write_file"},
                        {"name": "list_directory"},
                    ],
                },
                {
                    "name": "database-server",
                    "command": "python -m mcp_database",
                    "transport": "stdio",
                    "packages": [
                        {"name": "flask", "version": "2.2.0", "ecosystem": "pypi"},
                        {"name": "werkzeug", "version": "2.2.2", "ecosystem": "pypi"},
                        {"name": "requests", "version": "2.28.0", "ecosystem": "pypi"},
                        {"name": "cryptography", "version": "39.0.0", "ecosystem": "pypi"},
                        {"name": "pillow", "version": "9.0.0", "ecosystem": "pypi"},
                    ],
                    "env": {"DATABASE_URL": "***", "ANTHROPIC_API_KEY": "***"},
                    "tools": [
                        {"name": "run_query"},
                        {"name": "execute_sql"},
                        {"name": "export_csv"},
                    ],
                },
            ],
        },
        {
            "name": "claude-desktop",
            "agent_type": "claude-desktop",
            "source": "agent-bom --demo",
            "mcp_servers": [
                {
                    "name": "github-server",
                    "command": "npx @modelcontextprotocol/server-github",
                    "transport": "stdio",
                    "packages": [
                        {"name": "axios", "version": "1.4.0", "ecosystem": "npm"},
                        {"name": "semver", "version": "7.5.2", "ecosystem": "npm"},
                    ],
                    "env": {"GITHUB_TOKEN": "***"},
                    "tools": [
                        {"name": "create_issue"},
                        {"name": "search_repos"},
                        {"name": "push_files"},
                    ],
                },
                {
                    "name": "team-chat-server",
                    "command": "python -m slack_mcp",
                    "transport": "stdio",
                    "packages": [
                        {"name": "jinja2", "version": "3.0.0", "ecosystem": "pypi"},
                        {"name": "certifi", "version": "2022.12.7", "ecosystem": "pypi"},
                    ],
                    "env": {"SLACK_BOT_TOKEN": "***", "SLACK_SIGNING_SECRET": "***"},
                    "tools": [
                        {"name": "send_message"},
                        {"name": "list_channels"},
                    ],
                },
            ],
        },
    ],
}
