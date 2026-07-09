"""Bundled demo inventory for ``agent-bom agents --demo``.

Contains a realistic, connected multi-agent estate with known-vulnerable
packages so users see a real scan with CVE findings, blast radius, and
remediation output on the very first run — no local vuln DB required.

The estate is intentionally curated and deterministic (it must reproduce the
same findings on every machine). It spans five agents and ten MCP servers and
includes:
  * CRITICAL / KEV CVEs (PyYAML RCE, LangChain RCE, Pillow libwebp KEV) so the
    hero blast-radius chain vuln → package → MCP server → agent → credential →
    tool → potential RCE renders end to end.
  * Credential-backed ``env`` on servers so credential-exposure edges light up.
  * A typosquat package (``reqeusts``) so the malicious-package differentiator
    shows in the findings list.
"""

from __future__ import annotations

DEMO_INVENTORY: dict = {
    "agents": [
        {
            # IDE coding agent — the developer's day-to-day copilot.
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
                        {"name": "ws", "version": "8.5.0", "ecosystem": "npm"},
                    ],
                    "tools": [
                        {"name": "read_file"},
                        {"name": "write_file"},
                        {"name": "list_directory"},
                    ],
                },
                {
                    # Hero chain: shell-runner holds AWS creds AND a run_shell
                    # tool, and depends on PyYAML with a CRITICAL RCE.
                    "name": "shell-runner-server",
                    "command": "python -m mcp_shell_runner",
                    "transport": "stdio",
                    "packages": [
                        {"name": "pyyaml", "version": "5.3", "ecosystem": "pypi"},
                        {"name": "requests", "version": "2.28.0", "ecosystem": "pypi"},
                    ],
                    "env": {
                        "AWS_ACCESS_KEY_ID": "***",
                        "AWS_SECRET_ACCESS_KEY": "***",
                    },
                    "tools": [
                        {"name": "run_shell"},
                        {"name": "exec_command"},
                        {"name": "read_file"},
                    ],
                },
            ],
        },
        {
            # LangChain-based application/service agent.
            "name": "langchain-service",
            "agent_type": "custom",
            "source": "agent-bom --demo",
            "mcp_servers": [
                {
                    "name": "llm-orchestrator-server",
                    "command": "python -m mcp_orchestrator",
                    "transport": "streamable-http",
                    "packages": [
                        {"name": "langchain", "version": "0.0.150", "ecosystem": "pypi"},
                        {"name": "jinja2", "version": "3.0.0", "ecosystem": "pypi"},
                    ],
                    "env": {
                        "OPENAI_API_KEY": "***",
                        "ANTHROPIC_API_KEY": "***",
                    },
                    "tools": [
                        {"name": "run_chain"},
                        {"name": "eval_expression"},
                        {"name": "http_get"},
                    ],
                },
                {
                    "name": "vector-db-server",
                    "command": "python -m mcp_vectors",
                    "transport": "stdio",
                    "packages": [
                        {"name": "cryptography", "version": "39.0.0", "ecosystem": "pypi"},
                        {"name": "requests", "version": "2.28.0", "ecosystem": "pypi"},
                    ],
                    "env": {
                        "PINECONE_API_KEY": "***",
                        "DATABASE_URL": "***",
                    },
                    "tools": [
                        {"name": "query_vectors"},
                        {"name": "upsert_vectors"},
                    ],
                },
            ],
        },
        {
            # Customer-support copilot handling tickets and email.
            "name": "support-copilot",
            "agent_type": "custom",
            "source": "agent-bom --demo",
            "mcp_servers": [
                {
                    "name": "helpdesk-server",
                    "command": "python -m mcp_helpdesk",
                    "transport": "sse",
                    "packages": [
                        {"name": "axios", "version": "1.4.0", "ecosystem": "npm"},
                        {"name": "jsonwebtoken", "version": "8.5.1", "ecosystem": "npm"},
                    ],
                    "env": {
                        "HELPDESK_API_TOKEN": "***",
                        "JWT_SECRET": "***",
                    },
                    "tools": [
                        {"name": "create_ticket"},
                        {"name": "search_tickets"},
                        {"name": "send_reply"},
                    ],
                },
                {
                    "name": "email-server",
                    "command": "python -m mcp_email",
                    "transport": "stdio",
                    "packages": [
                        {"name": "node-fetch", "version": "2.6.1", "ecosystem": "npm"},
                        {"name": "certifi", "version": "2022.12.7", "ecosystem": "pypi"},
                    ],
                    "env": {"SMTP_PASSWORD": "***"},
                    "tools": [
                        {"name": "send_email"},
                        {"name": "list_inbox"},
                    ],
                },
            ],
        },
        {
            # Data-pipeline / ETL orchestration agent.
            "name": "data-pipeline",
            "agent_type": "custom",
            "source": "agent-bom --demo",
            "mcp_servers": [
                {
                    "name": "warehouse-server",
                    "command": "python -m mcp_warehouse",
                    "transport": "stdio",
                    "packages": [
                        {"name": "pyyaml", "version": "5.3", "ecosystem": "pypi"},
                        {"name": "cryptography", "version": "39.0.0", "ecosystem": "pypi"},
                    ],
                    "env": {
                        "SNOWFLAKE_PASSWORD": "***",
                        "DATABASE_URL": "***",
                    },
                    "tools": [
                        {"name": "run_query"},
                        {"name": "execute_sql"},
                        {"name": "export_csv"},
                    ],
                },
                {
                    # Ships a KEV package (Pillow/libwebp) alongside a typosquat
                    # of "requests" — the malicious-package differentiator.
                    "name": "etl-server",
                    "command": "python -m mcp_etl",
                    "transport": "stdio",
                    "packages": [
                        {"name": "pillow", "version": "9.0.0", "ecosystem": "pypi"},
                        {"name": "reqeusts", "version": "2.99.0", "ecosystem": "pypi"},
                    ],
                    "env": {"GCS_SERVICE_ACCOUNT_KEY": "***"},
                    "tools": [
                        {"name": "transform_image"},
                        {"name": "load_data"},
                    ],
                },
            ],
        },
        {
            # Desktop assistant wired to source control and team chat.
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
                        {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
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
                        {"name": "flask", "version": "2.2.0", "ecosystem": "pypi"},
                        {"name": "werkzeug", "version": "2.2.2", "ecosystem": "pypi"},
                        {"name": "jinja2", "version": "3.0.0", "ecosystem": "pypi"},
                    ],
                    "env": {
                        "SLACK_BOT_TOKEN": "***",
                        "SLACK_SIGNING_SECRET": "***",
                    },
                    "tools": [
                        {"name": "send_message"},
                        {"name": "list_channels"},
                    ],
                },
            ],
        },
    ],
}
