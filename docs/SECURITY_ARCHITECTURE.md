# Security Architecture

This document answers the security questions enterprise teams ask before adopting agent-bom.

## Data Flow — What Leaves Your Machine?

agent-bom sends only the minimum data needed for the feature in use: package names and versions for CVE lookups and version resolution, CVE IDs for enrichment, and finding summaries only for explicitly enabled push integrations. No source code, configuration contents, or credential values leave your machine.

### External API Calls

| API | Data Sent | Data Received | When |
|-----|-----------|---------------|------|
| **OSV** (Google) | Bulk download (no query) | All vulnerability advisories | `db update --source osv` |
| **GHSA** (GitHub) | Ecosystem name, page number | Security advisories | `db update --source ghsa` |
| **NVD** (NIST) | CVE IDs | CVSS scores, CWE mappings | `--enrich` flag |
| **EPSS** (FIRST) | Bulk download (no query) | Exploit probability scores | `db update --source epss` |
| **KEV** (CISA) | Bulk download (no query) | Known-exploited CVE list | `db update --source kev` |
| **deps.dev** (Google) | Package name + version | Transitive dependencies | `--deps-dev` flag |
| **npm / PyPI / Go proxy** | Package name (+ version/latest lookup) | Package metadata / latest version | Floating version resolution |
| **PyPI** | Package name | Latest version number | Update check (1x/24h) |

### Offline Mode

```bash
# Pre-sync databases
agent-bom db update --source osv --source ghsa --source epss --source kev

# Scan with zero network calls
agent-bom agents --offline
```

In offline mode, **zero external API calls** are made. All scanning uses the pre-synced local database only.

### Cloud connect — read-only by design

Cloud scanning never moves customer data out of the account. The contract:

- **One read-only role per cloud.** The connect Terraform modules grant exactly
  one identity per provider — AWS `SecurityAudit` (optionally `ViewOnlyAccess`),
  Azure built-in `Reader` (optionally `Security Reader`), GCP `roles/viewer`
  plus `roles/iam.securityReviewer`. No write actions are granted, and CI
  enforces that the connect modules stay read-only.
- **Keyless where possible.** Collectors authenticate via workload identity
  (IRSA, Azure workload identity, GCP Workload Identity Federation) and
  short-lived federated credentials — no long-lived keys are created by default.
  Providers are detected by credential source, not by a CLI on `PATH`.
- **Metadata only leaves the collector.** Inventory emits asset metadata, CVE
  counts, CIS results, and secret *type/location* — never file contents, secret
  values, or raw block data. Audit-trail ingestion reduces CloudTrail / Activity
  Log / Cloud Audit events to `(principal, resource, action)` counts and
  last-seen timestamps; raw events never persist.
- **Agentless workload scanning stays in-account.** The AWS EBS side-scan
  (`src/agent_bom/cloud/side_scan.py`) snapshots a volume, attaches it to an
  in-account collector, reads package/filesystem metadata, and deletes the temp
  snapshot and volume in a guaranteed `try/finally`. An orphan sweep recovers
  any leftover temp resources (tagged by the scanner) after a hard crash, so a
  failed run leaves nothing behind. No volume bytes leave the account.
  Azure Managed Disk and GCP Persistent Disk adapters use the same durable
  ownership and cleanup contract through injected, already-authenticated SDK
  clients. Their provider resources and block bytes remain inside the target
  subscription/project. These adapters have fake-client contract evidence but
  no CLI/scheduler integration or credentialed live-cloud proof yet.

### Control-plane identity

The control plane never stores a customer's cloud keys. It reads a customer
account by **assuming that account's read-only connection role** (AWS
`sts:AssumeRole` with an ExternalId; Azure/GCP federated equivalents) and
receives only short-lived credentials. To make that call the control plane needs
its *own* cloud identity, and that identity is a **workload identity per target
— never a static access key**:

| Target | Control-plane identity | Keyless mechanism |
|--------|------------------------|-------------------|
| EKS | Scanner IRSA role | Projected SA token → STS `AssumeRoleWithWebIdentity` |
| Self-managed k8s on EC2 / ECS | Node instance profile / ECS task role | AWS SDK default credential chain |
| AKS | Azure workload identity | Federated pod SA token → Entra ID |
| GKE | GCP Workload Identity | KSA → impersonated read-only service account |

- **Assumes connection roles, cross-account.** The scanner identity is granted a
  least-privilege `sts:AssumeRole` policy scoped to the connection-role name
  pattern (`agent-bom-readonly*` / `abom-readonly*`), so it can assume the
  read-only role in each target account for AWS Organizations fan-out and hosted
  connect. Only `sts:AssumeRole` is granted — no other action, no broader
  resource. Provisioned by `deploy/terraform/aws/baseline`
  (`connect_role_arns`); set it to `[]` to disable cross-account assume.
- **ExternalId is the reciprocal guard.** Every connection role's trust policy
  requires a high-entropy `sts:ExternalId`, always enforced, closing the
  confused-deputy gap even though the assume permission is scoped by name
  pattern.
- **Least-privilege, both sides.** The assumed role carries only read-only
  managed policies (`SecurityAudit` / `ViewOnlyAccess` and equivalents); the
  assuming identity carries only `sts:AssumeRole`. Neither side is ever
  root/admin.
- **No static keys.** No long-lived access key is created for the control-plane
  identity in any supported path. Snowflake is the lone exception (no cloud
  workload identity): it uses key-pair auth via a Secret reference, never a
  password.
- **Local/dev path is dev-only.** Running the control plane or CLI against your
  own laptop credentials (`aws sso login`, `az login`,
  `gcloud auth application-default login`) is supported for development and
  one-off operator scans, but a personal base identity must never be wired into
  a long-running hosted control plane — use the workload identity above.

The end-to-end onboarding walk-through (read the identity ARN, create the trust
in each account or via the org StackSet, connect in the UI) is in
[`DEPLOY_PLATFORM.md` § Connect your cloud (zero keys)](DEPLOY_PLATFORM.md#connect-your-cloud-zero-keys).

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
4. Runs 7 inline proxy detectors (tool drift, prompt injection, credential/PII leak, rate-limit abuse, exfiltration sequences, response cloaking, vector DB injection)
5. Forwards allowed messages to the server
6. Logs all activity to JSONL audit file

For cross-agent correlation and the broader 8-detector protection engine, run `agent-bom runtime protect --shield` alongside the proxy workflow.

### Security Controls

- **Message size limit**: 10 MB max per JSON-RPC message (DoS mitigation)
- **Regex timeout**: 0.1s per pattern evaluation (ReDoS mitigation)
- **PII detection**: Email, SSN, credit card, phone, internal IP
- **Secrets detection**: API keys, tokens, private keys
- **Audit trail**: JSONL logging to configurable path (`AGENT_BOM_LOG`)
- **Rate limiting**: Per-tool call rate limits (configurable) and shared API request throttling when Postgres-backed enterprise mode is enabled

## Self-Assessment Coverage

### Automated Security Testing (in CI)

| Tool | What It Checks | Frequency |
|------|----------------|-----------|
| **Bandit** | Python SAST (injection, hardcoded secrets, unsafe functions) | Every PR |
| **CodeQL** | Semantic code analysis (Python + GitHub Actions) | Every PR |
| **pip-audit** | Python dependency vulnerabilities | Every PR |
| **npm audit** | npm dependency vulnerabilities (`ui/` + `sdks/typescript/`) | Every PR |
| **OSV Scanner** | Lockfile vulnerability scanning | Every PR |
| **Container scanner** | Filesystem vulnerability scanning (HIGH/CRITICAL) | Every PR |
| **ClusterFuzzLite** | Fuzz testing (crash/OOM/timeout detection) | Every PR |
| **Self-scan** | agent-bom scanning its own dependencies | Every release |
| **Container rescan** | Weekly container scan of Docker images (amd64 + arm64) | Weekly cron |
| **Dependency review** | License + vulnerability check on new deps | Every PR |
| **JS supply-chain guard** | Fails if tracked or published JS source maps appear; verifies UI and TypeScript SDK source-map policy | Every PR |

### JavaScript / npm hardening

- Daily Dependabot coverage watches both JavaScript surfaces: `ui/` and `sdks/typescript/`
- CI runs `npm audit` with `--ignore-scripts` before installing or building JavaScript dependencies
- The TypeScript SDK build is checked to ensure it does not emit `.map` files into `dist/`
- The UI explicitly disables production browser source maps

### Model / weight supply-chain posture

- `agent-bom` treats model artifacts as supply-chain inputs, not opaque blobs
- Local model scans surface risky formats, bundle manifests, adapter lineage, signature presence, and per-file security flags
- HuggingFace provenance checks surface author, card presence, digest availability, and gated/private posture
- Hash verification can compare local weights against HuggingFace Hub metadata and report verified, unverified, offline, or tampered states
- Operators can enable advisory or enforce mode for model artifact policy with `--model-policy-mode`, `--require-model-signatures`, and `--block-unsafe-model-formats`; warn mode reports unsigned or unsafe artifacts while enforce mode fails closed through the normal scan policy exit path
- AI model advisories stay separate from package CVEs: `src/agent_bom/model_advisories.py` loads the bundled or customer-provided `AGENT_BOM_AI_MODEL_ADVISORY_FEED`, matches model-card signals such as `custom_code`, and adds source-attributed `model_advisories` plus feed freshness posture to `model_supply_chain_data`.

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

## Graph guarantees

agent-bom builds a context graph from inventory and canonical advisory feeds (CISA KEV, OSV, NVD, EPSS, MITRE) to model reachability across MCP agents, servers, credentials, and tools. Static edges use the contract names: `agent -> server` (`uses`), `server -> credential` (`exposes_cred`), `server -> tool` (`provides_tool`), and `credential -> tool` (`reaches_tool`). The graph is deterministic, round-trip-clean against the source inventory, and tenant-scoped at the database layer via Postgres row-level security. It does not use ML inference, does not encode causality without runtime traces from the proxy / gateway, and does not update in real time without those runtimes in the path.

The full contract — entity and edge enums, accuracy guarantees, scaling tiers, re-baseline procedure, and known coverage gaps — is in [docs/graph/CONTRACT.md](graph/CONTRACT.md).

## Compliance Posture

### What agent-bom IS

- A **local CLI tool** that scans your infrastructure
- A **self-hosted API + UI** for operator workflows, graph, audit, remediation, and policy
- An **MCP server** that exposes scan tools to AI agents
- A **runtime proxy** that monitors MCP traffic
- A **gateway and fleet surface** for shared remote MCP policy and endpoint inventory
- **Apache 2.0 licensed** open source software

### What agent-bom IS NOT

- Not a SaaS product (no ATO/FedRAMP required for the tool itself)
- Not a data processor (no customer data stored externally)
- Not SOC 2 certified (no SaaS to certify)

### Compliance Framework Mapping

agent-bom **maps findings TO compliance controls** across curated tag-mapped frameworks and exposes AISVS as a benchmark:

OWASP LLM Top 10, OWASP MCP Top 10, OWASP Agentic Top 10,
EU AI Act, NIST AI RMF, NIST CSF, NIST 800-53 Rev 5, FedRAMP Moderate,
ISO 27001, SOC 2, CIS Controls v8, MITRE ATLAS, CMMC 2.0 Level 2, PCI DSS.
OWASP AISVS v1.0 is returned as per-check benchmark evidence.

The bundled mappings are a curated subset of each framework focused on AI/MCP/agent risk — not a complete catalog. See [docs/ARCHITECTURE.md § Coverage per framework](./ARCHITECTURE.md#coverage-per-framework) for the honest control counts per framework.

Every finding includes which compliance controls it violates — enabling teams to prioritize by regulatory impact.

## Vulnerability Disclosure

Security vulnerabilities should be reported via [GitHub Security Advisories](https://github.com/msaad00/agent-bom/security/advisories/new) (private). See [SECURITY.md](../SECURITY.md) for the full policy.

For the planned independent runtime and control-plane assessment before `v1.0`,
see [docs/PENTEST_READINESS.md](PENTEST_READINESS.md).
