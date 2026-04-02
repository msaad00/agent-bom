# Threat Model

This document enumerates trust boundaries, threat actors, attack surfaces,
and mitigations for agent-bom. It satisfies the OpenSSF Best Practices Silver
"assurance case" criterion and complements [SECURITY.md](SECURITY.md).

---

## System overview

agent-bom operates in four modes:

1. **Scanner** — reads local config files + public APIs, produces reports
2. **Proxy** — sits between an MCP client and server, inspects STDIO traffic
3. **API server** — exposes REST/WebSocket endpoints for the dashboard
4. **MCP server** — exposes 36 tools to AI assistants (Claude, Cursor, etc.)

## Trust boundaries

```
┌─────────────────────────────────────────────────────┐
│  User workstation (trusted)                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ CLI/scan  │  │  Proxy   │  │ MCP server       │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────────────┘  │
│       │              │              │                 │
├───────┼──────────────┼──────────────┼─────────────────┤ ← TRUST BOUNDARY
│       ▼              ▼              ▼                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ OSV/NVD/ │  │ Upstream │  │ AI client        │  │
│  │ EPSS/KEV │  │ MCP srv  │  │ (Claude, Cursor) │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
│  External APIs    Untrusted     Semi-trusted         │
└─────────────────────────────────────────────────────┘
```

| Boundary | Trust level | Rationale |
|----------|------------|-----------|
| Local filesystem | Trusted | User's own config files; validated with `validate_path(restrict_to_home=True)` |
| Public vuln APIs (OSV, NVD, EPSS, KEV) | Untrusted input | Responses are parsed defensively; no code execution from API data |
| Cloud provider APIs (AWS, Azure, GCP, Snowflake) | Authenticated, semi-trusted | Read-only API calls; credentials from environment; responses parsed defensively |
| Upstream MCP servers (via proxy) | Untrusted | All traffic inspected by 7 inline proxy detectors; policy enforcement before relay |
| AI clients (via MCP server) | Semi-trusted | Tool inputs validated; no shell execution from AI-provided arguments |
| Docker daemon socket | Privileged | Only accessed with explicit `--image` flag; user must opt in |
| Kubernetes API | Privileged | Only accessed with explicit `--k8s-mcp` flag; uses kubeconfig auth |

## Threat actors

| Actor | Motivation | Capability |
|-------|-----------|------------|
| **Malicious MCP server** | Data exfiltration, credential theft, lateral movement | Can return crafted responses with hidden instructions, cloaked payloads, prompt injection |
| **Poisoned vector DB** | Cache poisoning, instruction hijacking | Can inject instructions into RAG retrieval responses |
| **Supply chain attacker** | Typosquatting, dependency confusion | Can publish malicious packages mimicking legitimate AI libraries |
| **Compromised AI skill file** | Behavioral manipulation | Can inject instructions via CLAUDE.md, .cursorrules, AGENTS.md |
| **Network attacker** | Man-in-the-middle | Can intercept unencrypted MCP traffic (mitigated by HMAC signing, JWKS verification) |
| **Insider threat** | Privilege escalation via SQL injection | Can craft SQL through CoCo/Snowflake MCP tools (mitigated by 8 SQL injection patterns) |

## Attack surfaces and mitigations

### 1. MCP proxy (STDIO relay)

| Attack | MITRE | Mitigation |
|--------|-------|-----------|
| Tool rug pull (new tools after startup) | T1036 | ToolDriftDetector — baseline comparison, HIGH alert |
| Shell injection in tool args | T1059 | ArgumentAnalyzer — 19 dangerous patterns (shell meta, path traversal, SQL injection) |
| Credential exfiltration via responses | T1552 | CredentialLeakDetector — 12 credential patterns, CRITICAL alert |
| Rate-based DoS | T1499 | RateLimitTracker — sliding window, per-tool threshold |
| Multi-step exfiltration (read→send) | T1041 | SequenceAnalyzer — 4 suspicious sequences |
| Hidden instructions in HTML/CSS | T1027 | ResponseInspector — 8 cloaking + 5 SVG + 5 invisible char + 7 injection patterns |
| Vector DB cache poisoning | T1557 | VectorDBInjectionDetector — injection patterns + full cloaking scan |
| Semantic prompt injection | T1204 | Semantic scoring — 11 weighted signals, threshold-based alerting |
| Message replay | T1078 | HMAC signing on every JSON-RPC message |
| Unauthorized tool use | T1204 | JWKS signature verification (RS256-ES512); `alg: none` rejected |
| Request flooding | T1498 | 10 MB message size limit; readline timeout (120s) |

### 2. Scanner (CLI / CI)

| Attack | MITRE | Mitigation |
|--------|-------|-----------|
| Path traversal in config paths | T1083 | `validate_path()` — restrict to home directory, resolve symlinks |
| Malicious SBOM input | T1195 | Defensive JSON parsing; no code execution from SBOM data |
| Typosquatted packages | T1195.002 | Typosquat detection against known package names |
| Poisoned skill files | T1059.006 | 17 behavioral risk patterns; Sigstore provenance verification |
| API response manipulation | T1557 | HTTPS-only for all outbound calls; TLS certificate verification |
| Credential leakage in output | T1552 | Heuristic redaction (`***REDACTED***`) for env var names |

### 3. API server

| Attack | MITRE | Mitigation |
|--------|-------|-----------|
| Unauthorized access | T1078 | API key auth (`AGENT_BOM_API_KEY`) or OIDC/JWT (`AGENT_BOM_OIDC_ISSUER`) |
| JWT algorithm confusion | T1550 | JWKS enforces RS/ES algorithms; `alg: none` explicitly rejected |
| Network exposure | T1190 | Defaults to `127.0.0.1:8422` (localhost-only) |

### 4. MCP server (tool interface)

| Attack | MITRE | Mitigation |
|--------|-------|-----------|
| Prompt injection via tool args | T1059 | Tool inputs are data, not executed; results are JSON, not instructions |
| Resource exhaustion | T1499 | Tool response truncation (5 agents, 5 vulns, 10 references per result) with total counts |

## What agent-bom does NOT protect against

- **Pre-existing compromised MCP servers** — the proxy uses trust-on-first-use; servers compromised before proxy deployment must be identified via scanning first
- **Obfuscated credentials** — redaction is regex-based and may miss non-standard patterns
- **Zero-day vulnerabilities in dependencies** — scanner coverage depends on OSV/NVD/GHSA database freshness
- **Physical access attacks** — out of scope
- **AI model inference attacks** — prompt extraction, membership inference, and model inversion are out of scope (agent-bom scans infrastructure, not model internals)

## Review cadence

This threat model is reviewed with each major release (x.0) and after any
security advisory. Last reviewed: v0.75.13 (April 2026).
