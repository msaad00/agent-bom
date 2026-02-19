# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report via [GitHub Security Advisories](https://github.com/agent-bom/agent-bom/security/advisories/new).

We aim to respond within 48 hours and provide a fix within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < Latest | No — upgrade to the latest release |

## Security Design

agent-bom is a read-only scanner. It reads config files and queries public APIs (OSV.dev, NVD, EPSS, CISA KEV). It never writes to agent configs, never executes MCP servers, and never stores credentials — only their names appear in output as `***REDACTED***`.
