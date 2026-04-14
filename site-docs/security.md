# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report via [GitHub Security Advisories](https://github.com/msaad00/agent-bom/security/advisories/new).

We aim to respond within 48 hours and provide a fix within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < Latest | No — upgrade to the latest release |

## Security Design

agent-bom has three distinct security postures:

- **Scanner mode** (`agent-bom agents`, `agent-bom fs`, `agent-bom check`) is read-only. It reads config files and queries public APIs (OSV.dev, NVD, EPSS, CISA KEV).
- **MCP server mode** (`agent-bom mcp server`) is read-only. It exposes scan/governance tools and does not execute third-party MCP servers.
- **Proxy mode** (`agent-bom proxy`) is an execution and enforcement surface. It intentionally launches or connects to the target MCP server so it can inspect, block, and audit tool traffic in real time.

Across all modes, agent-bom never stores credential values — only their names appear in output as `***REDACTED***`.
