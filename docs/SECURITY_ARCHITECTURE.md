# Security Architecture

This document answers the security questions enterprise teams ask before adopting agent-bom.

## Data Flow — What Leaves Your Machine?

agent-bom sends **package names and versions only** to external APIs. No source code, no configuration files, no credentials ever leave your machine.

### External API Calls

| API | Data Sent | Data Received | When |
|-----|-----------|---------------|------|
| **OSV** (Google) | Bulk download (no query) | All vulnerability advisories | `db update --source osv` |
| **GHSA** (GitHub) | Ecosystem name, page number | Security advisories | `db update --source ghsa` |
| **NVD** (NIST) | CVE IDs | CVSS scores, CWE mappings | `--enrich` flag |
| **EPSS** (FIRST) | Bulk download (no query) | Exploit probability scores | `db update --source epss` |
| **KEV** (CISA) | Bulk download (no query) | Known-exploited CVE list | `db update --source kev` |
| **deps.dev** (Google) | Package name + version | Transitive dependencies | `--deps-dev` flag |
| **PyPI** | Package name | Latest version number | Update check (1x/24h) |

### Offline Mode

```bash
# Pre-sync databases
agent-bom db update --source osv --source ghsa --source epss --source kev

# Scan with zero network calls
agent-bom agents --offline
```

In offline mode, **zero external API calls** are made. All scanning uses the pre-synced local database only.

### Network Enforcement

- All external calls use HTTPS with full TLS certificate verification (`verify=True`)
- `http://` and `file://` URLs are rejected by `_validate_sync_url()`
- API keys (NVD, GitHub) are read from environment variables, never hardcoded
- URL query parameters are redacted from logs to prevent token leakage

## Runtime Proxy — Not a MITM

The agent-bom proxy is a **stdio relay**, not a network MITM proxy. It does not:

- Generate certificates
- Intercept TLS connections
- Modify network traffic
- Inject CA bundles

### How the Proxy Works

```
MCP Client (Claude Desktop) → agent-bom proxy → MCP Server (stdio)
```

The proxy sits between the MCP client and server on the **stdio transport layer** (stdin/stdout). It:

1. Reads JSON-RPC messages from the client
2. Inspects message content (tool calls, tool responses)
3. Applies policy rules (allow/deny/log)
4. Runs 8 detectors (tool drift, prompt injection, credential/PII leak, rate-limit abuse, exfiltration sequences, response cloaking, vector DB injection, cross-agent correlation)
5. Forwards allowed messages to the server
6. Logs all activity to JSONL audit file

### Security Controls

- **Message size limit**: 10 MB max per JSON-RPC message (DoS mitigation)
- **Regex timeout**: 0.1s per pattern evaluation (ReDoS mitigation)
- **PII detection**: Email, SSN, credit card, phone, internal IP
- **Secrets detection**: API keys, tokens, private keys
- **Audit trail**: JSONL logging to configurable path (`AGENT_BOM_LOG`)
- **Rate limiting**: Per-tool call rate limits (configurable)

## Self-Assessment Coverage

### Automated Security Testing (in CI)

| Tool | What It Checks | Frequency |
|------|----------------|-----------|
| **Bandit** | Python SAST (injection, hardcoded secrets, unsafe functions) | Every PR |
| **CodeQL** | Semantic code analysis (Python + GitHub Actions) | Every PR |
| **pip-audit** | Python dependency vulnerabilities | Every PR |
| **npm audit** | npm dependency vulnerabilities (ui/) | Every PR |
| **OSV Scanner** | Lockfile vulnerability scanning | Every PR |
| **Trivy** | Filesystem vulnerability scanning (HIGH/CRITICAL) | Every PR |
| **ClusterFuzzLite** | Fuzz testing (crash/OOM/timeout detection) | Every PR |
| **Self-scan** | agent-bom scanning its own dependencies | Every release |
| **Container rescan** | Weekly Trivy scan of Docker images (amd64 + arm64) | Weekly cron |
| **Dependency review** | License + vulnerability check on new deps | Every PR |

### What a Formal Pentest Should Cover

If engaging a third-party auditor, the recommended scope:

1. **MCP Server API** (FastAPI, port 8422): Authentication bypass, injection, IDOR
2. **Proxy message handling**: Malformed JSON-RPC, oversized messages, Unicode edge cases
3. **Policy engine regex**: ReDoS, bypass via encoding, null byte injection
4. **Database sync**: TOCTOU in file writes, symlink attacks, path traversal
5. **CLI argument handling**: Injection via `--command`, `--args` passthrough
6. **SARIF/HTML output**: XSS in generated reports (especially HTML format)

### Open Source Tools for Self-Testing

- **OWASP ZAP** — Automated scan of the FastAPI REST API endpoints
- **Nuclei** — Template-based API fuzzing
- **mitmproxy** — Test proxy behavior from the client side
- **Semgrep** — Rule-based SAST (complement to Bandit)

## Compliance Posture

### What agent-bom IS

- A **local CLI tool** that scans your infrastructure
- An **MCP server** that exposes scan tools to AI agents
- A **runtime proxy** that monitors MCP traffic
- **Apache 2.0 licensed** open source software

### What agent-bom IS NOT

- Not a SaaS product (no ATO/FedRAMP required for the tool itself)
- Not a data processor (no customer data stored externally)
- Not SOC 2 certified (no SaaS to certify)

### Compliance Framework Mapping

agent-bom **maps findings TO compliance controls** across 14 frameworks:

OWASP Top 10, OWASP LLM Top 10, OWASP MCP Top 10, OWASP Agentic Security,
EU AI Act, NIST AI RMF, NIST CSF, ISO 27001, SOC 2, CIS Benchmarks,
MITRE ATT&CK, MITRE ATLAS, PCI DSS

This means every finding includes which compliance controls it violates — enabling teams to prioritize by regulatory impact.

## Vulnerability Disclosure

Security vulnerabilities should be reported via [GitHub Security Advisories](https://github.com/msaad00/agent-bom/security/advisories/new) (private). See [SECURITY.md](../SECURITY.md) for the full policy.
