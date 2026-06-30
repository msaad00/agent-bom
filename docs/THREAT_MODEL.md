# Threat Model

This document enumerates trust boundaries, threat actors, attack surfaces,
and mitigations for agent-bom. It satisfies the OpenSSF Best Practices Silver
"assurance case" criterion and complements [SECURITY.md](../SECURITY.md).

---

## System overview

agent-bom operates in six modes:

1. **Scanner** — reads local config files + public APIs, produces reports
2. **Proxy** — sits between an MCP client and server, inspects STDIO traffic
3. **Gateway** — centralizes selected remote MCP traffic and policy decisions
4. **API server** — exposes REST/WebSocket endpoints for the dashboard
5. **MCP server** — exposes validated tools to MCP-compatible assistants
6. **Runtime control plane** — records production-index, blueprint drift,
   authorization traces, Shield actions, and tenant-scoped evidence

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
│  │ OSV/NVD/ │  │ Upstream │  │ MCP-compatible   │  │
│  │ EPSS/KEV │  │ MCP srv  │  │ client           │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
│  External APIs    Untrusted     Semi-trusted         │
└─────────────────────────────────────────────────────┘
```

| Boundary | Trust level | Rationale |
|----------|------------|-----------|
| Local filesystem | Trusted | User's own config files; validated with `validate_path(restrict_to_home=True)` |
| Public vuln APIs (OSV, NVD, GHSA, EPSS, KEV) | Untrusted input | Responses are parsed defensively; no code execution from API data |
| Threat-intel and advisory feeds | Untrusted input | Feed data is normalized, deduplicated, and attributed; external records do not become executable code |
| Cloud provider APIs (AWS, Azure, GCP, Snowflake) | Authenticated, semi-trusted | Read-only API calls; credentials from environment; responses parsed defensively |
| Upstream MCP servers (via proxy) | Untrusted | All traffic inspected by 7 inline proxy detectors; policy enforcement before relay |
| MCP-compatible clients (via MCP server) | Semi-trusted | Tool inputs validated; no shell execution from AI-provided arguments |
| Runtime proxy/gateway sessions | Semi-trusted | Only traffic routed through the proxy/gateway is enforced; direct out-of-band calls remain outside this boundary |
| API database | Customer-controlled trusted store | SQLite/Postgres stores tenant-scoped inventory, findings, graphs, audit records, runtime evidence, and policy state |
| Export sinks (OTLP, SIEM, object storage, data warehouse) | External sink | agent-bom redacts and shapes exports; downstream access control is owned by the sink |
| Docker daemon socket | Privileged | Only accessed with explicit `--image` flag; user must opt in |
| Kubernetes API | Privileged | Only accessed with explicit `--k8s-mcp` flag; uses kubeconfig auth |

## Security assumptions

- The customer controls the deployment boundary: IdP, TLS termination, API keys,
  database, network policy, object storage, and SIEM/export destinations.
- Runtime enforcement protects MCP/tool traffic that is routed through the
  proxy or gateway. Direct cloud-console actions, direct SDK calls, and bypassed
  MCP traffic are inventory signals, not enforceable events.
- Scanner accuracy depends on visible inventory and configured data sources.
  Hidden endpoints, private registries, and disconnected environments require
  explicit connector configuration or offline feed sync.
- Redaction reduces exposure in logs, traces, reports, and exports, but it is
  not a complete DLP system.
- Advisory matching depends on feed freshness, package identity quality, and
  ecosystem-native identifiers such as purl, CVE, GHSA, OSV, CWE, and optional
  CPE evidence.

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
| Unauthorized access | T1078 | Non-loopback binds require API key auth (`AGENT_BOM_API_KEY`) or OIDC/JWT (`AGENT_BOM_OIDC_ISSUER` or `AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON`) unless explicitly overridden |
| JWT algorithm confusion | T1550 | JWKS enforces RS/ES algorithms; `alg: none` explicitly rejected |
| Network exposure | T1190 | Defaults to `127.0.0.1:8422` (localhost-only); non-loopback unauthenticated binds fail closed by default |
| Cross-tenant data access | T1078 | Tenant-aware auth context, API-key tenant binding, OIDC/SAML/SCIM role mapping, and route-level authorization checks |
| Unauthorized writes | T1078 | Viewer sessions are read-only; write, key, tenant, policy, Shield, and destructive routes require elevated roles |

### 4. MCP server (tool interface)

| Attack | MITRE | Mitigation |
|--------|-------|-----------|
| Prompt injection via tool args | T1059 | Tool inputs are data, not executed; results are JSON, not instructions |
| Resource exhaustion | T1499 | Tool response truncation (5 agents, 5 vulns, 10 references per result) with total counts |

### 5. Runtime gateway and Shield

| Attack | MITRE | Mitigation |
|--------|-------|-----------|
| Unauthorized runtime action | T1078 | Gateway, firewall, and Shield write routes require authenticated admin/operator-equivalent roles |
| Blueprint drift | T1565 | Runtime production-index posture can be compared against role blueprints and surfaced as drift evidence |
| Policy bypass | T1562 | Proxy/gateway decisions produce authorization traces and audit events; bypassed traffic is out of enforcement scope |
| Emergency access abuse | T1078 | Shield break-glass and unblock actions are explicit privileged operations with audit context |

### 6. Threat-intel and advisory data

| Attack | MITRE | Mitigation |
|--------|-------|-----------|
| Poisoned advisory feed | T1195 | External feed records are parsed as data, normalized, attributed, and matched through structured identifiers |
| Stale exploitability signal | T1588 | Advisory sources expose sync/freshness metadata; downstream decisions should inspect last sync and source provenance |
| Identifier collision | T1588 | Findings retain canonical IDs and ecosystem-native package evidence instead of trusting a single free-text identifier |

## RBAC and tenant isolation

agent-bom uses a small built-in role hierarchy for the control plane:

| Role | Intended access |
|------|-----------------|
| `viewer` | Read-only dashboards, evidence, reports, graph views, and export-safe summaries |
| `analyst` | Operational write access such as scans, triage, source tests, dataset work, and non-administrative evidence workflows |
| `admin` | Tenant administration, API keys, SCIM/OIDC/SAML configuration, gateway policy writes, Shield emergency actions, and destructive operations |

Role input can come from API keys, browser sessions, trusted proxy headers,
OIDC/JWT claims, SAML attributes, and SCIM group mappings. Tenant IDs are
attached to the auth context and enforced by API routes and stores that support
tenant-scoped data.

Current limitations:

- Custom roles and ABAC policies are not yet a first-class product surface.
- Resource-owner policies are coarse compared with tenant-level isolation.
- Multi-approver workflows for emergency Shield actions are not enforced yet.
- A malicious tenant admin or compromised IdP remains outside the protection
  boundary.

## What agent-bom does NOT protect against

- **Pre-existing compromised MCP servers** — the proxy uses trust-on-first-use; servers compromised before proxy deployment must be identified via scanning first
- **Traffic that bypasses agent-bom** — direct tool calls, direct SDK calls, cloud-console changes, and CI/CD mutations that do not pass through scanner, API, proxy, gateway, or Shield surfaces are not enforceable
- **Obfuscated credentials** — redaction is pattern-based and may miss encoded, encrypted, split, runtime-only, or non-standard secret formats
- **Compromised identity systems** — stolen API keys, compromised OIDC/SAML/SCIM providers, malicious tenant admins, or broken upstream IdP policy can defeat local authorization checks
- **Zero-day vulnerabilities in dependencies** — scanner coverage depends on OSV/NVD/GHSA/KEV/EPSS and vendor advisory freshness
- **Poisoned or stale customer extensions** — custom connectors, custom policies, webhooks, MCP tools, and private feeds are evaluated as configured but remain customer-controlled code and data
- **Physical access attacks** — out of scope
- **AI model inference attacks** — prompt extraction, membership inference, and model inversion are out of scope (agent-bom scans infrastructure, not model internals)
- **Formal DLP guarantees** — redaction, reporting, and trace shaping reduce leakage risk but are not a replacement for a dedicated DLP program

## Review cadence

This threat model is reviewed with each major release (x.0) and after any
security advisory. Last reviewed: v0.90.0 (June 2026).
