# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](https://github.com/msaad00/agent-bom/security/advisories/new).

**Response SLA:**
- Acknowledgement within **48 hours**
- Triage and severity assessment within **5 business days**
- Fix for critical issues within **7 days** of triage
- Fix for high issues within **30 days** of triage

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | ✓ Yes     |
| < Latest | ✗ No — upgrade to the latest release |

## Security Design

agent-bom is a **read-only scanner**. It does not modify agent configurations, execute MCP servers, write credentials, or alter any external system state.

### What it reads
- Local config files (`~/.config/`, `~/.claude/`, etc.) — for agent discovery
- Public APIs: OSV.dev, NVD, EPSS, CISA KEV — for CVE enrichment
- Cloud provider APIs — when explicitly configured with credentials (AWS, GCP, Azure, Snowflake, Databricks)
- Docker daemon socket — when `--image` flag is used
- Kubernetes API — when `--k8s` flag is used

### Credential handling
- Credentials are **never stored** by agent-bom
- Credential names/env var keys appear in output as `***REDACTED***`
- Redaction is heuristic-based (regex patterns) and may miss obfuscated or non-standard key names
- Cloud credentials must be pre-configured in the environment (AWS profile, GCP application default, etc.)

### Known limitations
- **Credential redaction is heuristic** — non-standard or obfuscated key names may not be flagged
- **Grype/Syft dependency** — container image scanning relies on external binaries; their CVEs apply to those tools
- **Network dependency** — OSV/NVD/EPSS enrichment requires outbound HTTPS; air-gapped environments see reduced coverage
- **MCP server execution** — agent-bom does NOT execute MCP servers it discovers; it only reads their configs
- **Runtime proxy enforcement** — the proxy intercepts MCP traffic using a trust-on-first-use model; pre-existing compromised servers must be identified via scanning before proxy deployment

### API security (when running `agent-bom api`)
- Defaults to localhost-only binding (`127.0.0.1:8422`)
- API key auth via `AGENT_BOM_API_KEY` env var; OIDC/JWT via `AGENT_BOM_OIDC_ISSUER`
- WebSocket endpoints require the same auth when `AGENT_BOM_API_KEY` is set
- JWKS public key caching (1h TTL); RS256/RS384/RS512/ES256/ES384/ES512 supported; `alg: none` rejected

## Security Testing

- **Static analysis**: ruff + mypy on every PR (required CI checks)
- **Dependency scanning**: Dependabot weekly (Python + npm)
- **Container image scanning**: Trivy in CI pipeline
- **Pre-commit hooks**: ruff, ruff-format, detect-private-key, check-yaml, end-of-file-fixer
- No third-party penetration testing yet (planned for v1.0)

## Vulnerability Disclosure Timeline

1. Reporter submits via GitHub Security Advisories
2. Maintainer acknowledges within 48 hours
3. Issue triaged, CVSS severity assigned within 5 business days
4. Fix developed on private branch; CVE ID requested if warranted
5. Coordinated disclosure: patch released, advisory published simultaneously
6. Reporter credited in release notes (unless anonymity requested)
