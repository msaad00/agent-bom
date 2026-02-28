"""Bundled demo inventory for ``agent-bom scan --demo``.

Contains realistic agents with known-vulnerable packages so users can see
a real scan with CVE findings, blast radius, and remediation output.
"""

from __future__ import annotations

DEMO_INVENTORY: dict = {
    "agents": [
        {
            "name": "demo-web-agent",
            "agent_type": "demo",
            "source": "agent-bom --demo",
            "mcp_servers": [
                {
                    "name": "web-search-server",
                    "command": "npx @anthropic/web-search-mcp",
                    "transport": "stdio",
                    "packages": [
                        {"name": "express", "version": "4.17.1", "ecosystem": "npm"},
                        {"name": "node-fetch", "version": "2.6.1", "ecosystem": "npm"},
                        {"name": "jsonwebtoken", "version": "8.5.1", "ecosystem": "npm"},
                    ],
                    "env": {"SEARCH_API_KEY": "***"},
                    "tools": [
                        {"name": "web_search"},
                        {"name": "fetch_page"},
                    ],
                },
                {
                    "name": "data-analysis-server",
                    "command": "python -m data_analysis_mcp",
                    "transport": "stdio",
                    "packages": [
                        {"name": "flask", "version": "2.2.0", "ecosystem": "pypi"},
                        {"name": "werkzeug", "version": "2.2.2", "ecosystem": "pypi"},
                        {"name": "requests", "version": "2.28.0", "ecosystem": "pypi"},
                        {"name": "cryptography", "version": "39.0.0", "ecosystem": "pypi"},
                    ],
                    "env": {"DATABASE_URL": "***", "SECRET_KEY": "***"},
                    "tools": [
                        {"name": "run_query"},
                        {"name": "analyze_data"},
                        {"name": "export_csv"},
                    ],
                },
            ],
        },
        {
            "name": "demo-code-agent",
            "agent_type": "demo",
            "source": "agent-bom --demo",
            "mcp_servers": [
                {
                    "name": "code-executor-server",
                    "command": "npx @demo/code-executor",
                    "transport": "stdio",
                    "packages": [
                        {"name": "semver", "version": "7.5.2", "ecosystem": "npm"},
                        {"name": "axios", "version": "1.4.0", "ecosystem": "npm"},
                    ],
                    "env": {"GITHUB_TOKEN": "***"},
                    "tools": [
                        {"name": "execute_code"},
                        {"name": "read_file"},
                        {"name": "write_file"},
                    ],
                },
            ],
        },
    ],
}
