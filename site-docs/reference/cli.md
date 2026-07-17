# CLI Reference

## Commands

### Get started

The narrow front door for humans: `connect` → `scan` → `graph` → `report`, plus
`up` to run the platform locally. Every command below remains available; these
verbs are additive entry points that delegate to the underlying implementations.

| Command | Description |
|---------|-------------|
| `connect` | Read-only onboard a cloud or data source (AWS, Azure, GCP, Snowflake); prints CLI, CloudShell, and Terraform grant options plus opt-in inventory env var, then reports detected credentials |
| `up` | Run the platform locally — alias of `serve`; accepts the same flags and points at `deploy/docker-compose.fullstack.yml` for the full stack |

### Scanning

| Command | Description |
|---------|-------------|
| `scan` | Discover MCP clients, extract dependencies, scan packages, and compute blast radius (alias: `agents`) |
| `quickstart` | Print local scan, sample-data, and API/UI first-run next steps |
| `manifest` | Emit the canonical Agent BOM manifest for local agent, MCP server, tool, and credential-reference posture |
| `skills` | Scan, verify, and rescan AI instruction files and skills |
| `image` | Scan a container image |
| `fs` | Scan a filesystem directory or mounted VM disk snapshot |
| `iac` | Scan Dockerfile, Kubernetes, Terraform, CloudFormation, and live Kubernetes posture |
| `sbom` | Ingest an existing CycloneDX or SPDX SBOM and scan it |
| `ingest` | Ingest operator-provided evidence (e.g. hardware/firmware attestation) into the unified graph |
| `ingest hardware` | Map a hardware/firmware attestation evidence file onto host / GPU / firmware / advisory graph nodes |
| `cloud` | Scan AWS, Azure, or GCP infrastructure posture |
| `cloud scan` | One cloud-aware scan across every configured provider (`--provider all` auto-detects; `--show-passed` lists passed CIS checks) |
| `cloud aws` / `cloud azure` / `cloud gcp` | Provider-scoped aliases — `cloud scan --provider <aws\|azure\|gcp>` |
| `cloud registry-scan` | Sweep an entire cloud container registry (ECR/ACR/GAR) — enumerate every repo+tag and scan each, read-only |
| `cloud resilience` | Show provider pagination, retry, and partial-failure tolerance evidence |
| `check` | Check one package before install or approval |
| `verify` | Verify package integrity / provenance or self-verify `agent-bom` |
| `secrets` | Scan a directory for hardcoded secrets and PII |
| `code` | Analyze source code for AI components, prompts, guardrails, and tools |
| `scanners` | List scanner driver capabilities, inputs, outputs, and failure semantics |

### Runtime

| Command | Description |
|---------|-------------|
| `proxy` | Run an MCP server through the agent-bom security proxy |
| `watch` | Watch MCP client configuration files for drift and alert on new risks |
| `audit` | View and analyze a proxy audit JSONL log |
| `audit-drain-dlq` | Replay or inspect proxy audit dead-letter queue entries |

### MCP

| Command | Description |
|---------|-------------|
| `mcp` | Discover, scan, and manage MCP agents and servers |
| `mcp inventory` | Discover MCP agents and servers without CVE scanning |
| `mcp scan` | Check a single MCP server package or npx/uvx spec |
| `mcp introspect` | Connect to live servers and list tools |
| `mcp registry` | Browse and manage the MCP server security registry |
| `mcp server` | Start agent-bom as an MCP server over stdio |
| `mcp where` | Show MCP discovery paths checked on this machine |
| `mcp validate` | Validate an MCP/client inventory file |
| `where` | Top-level shortcut for MCP discovery paths |

### Reporting

| Command | Description |
|---------|-------------|
| `graph` | Export the transitive dependency graph from a scan report |
| `graph-evidence` | Export retained graph snapshot history or a signed evidence manifest digest |
| `mesh` | Show lightweight agent/MCP topology without CVE scanning |
| `report` | History, diff, pipeline-event artifacts, local queries, analytics, dashboard, and compliance narrative workflows |
| `findings` | List normalized findings, manage the triage queue, record decisions, and export signed OpenVEX evidence |
| `findings push` | Push normalized findings or Trivy / Grype / Syft JSON to `POST /v1/findings/bulk` on the control plane |
| `findings list` | List findings from the control plane; prints lifecycle columns when bulk-ingest metadata is present |
| `attest` | Sign and verify generated SBOM output (SHA-256 digest + in-toto attestation) |

### Governance And Operations

| Command | Description |
|---------|-------------|
| `policy` | Policy templates, application, and install-guard checks |
| `firewall` | Inter-agent firewall policy validate / list / check |
| `trust` | Show data access, network, auth, and storage boundaries |
| `fleet` | Manage AI agent fleet discovery, lifecycle, and posture |
| `fleet sync` | Discover local MCP agents and push inventory to `POST /v1/fleet/sync` |
| `cost` | LLM FinOps posture — spend forecast and chargeback rollups (read-only) |
| `cost forecast` | Project LLM burn rate and budget runway (read-only FinOps) |
| `cost allocation` | Roll up LLM spend by cost-center / allocation tag (alias: `cost chargeback`) |
| `identity` | Non-human identity governance — credentials, discovery, access reviews (read-only) |
| `identity credential-expiry` | Show expiring, overdue, and rotation-due credentials (never secret values) |
| `identity discover` | Discover Okta / Entra non-human identities (gated, reference-only) |
| `identity access-review` | List or get NHI recertification campaigns and their status |
| `cloud inventory` | Estate-wide AWS / Azure / GCP asset summary (gated by `AGENT_BOM_*_INVENTORY`) |
| `serve` | Start the API server and dashboard |
| `api` | Start the REST API server |
| `schedule` | Manage recurring scan schedules |
| `remediate` | Generate a prioritized remediation plan; with explicit `--apply`, patch supported dependency manifests |
| `teardown` | Tear down the AWS/EKS reference install owned by agent-bom |

### Database And Utilities

| Command | Description |
|---------|-------------|
| `db` | Manage the local vulnerability database |
| `db freshness` | Show the structured vuln-data freshness indicator (sources, age, staleness) surfaced on every scan, API, and MCP tool |
| `db framework-status` | Show bundled framework catalog freshness |
| `doctor` | Check environment readiness for scanning |
| `self-audit` | Audit this agent-bom deployment's own security and governance posture (auth, tenant isolation, audit-log integrity, secret sealing) with honest pass/fail/warn/unknown results |
| `capabilities` | Show every gated capability, current state, and exact unlock path without printing secret values |
| `gateway` | Multi-MCP gateway commands |
| `interactive` | Start an interactive command shell for repeated CLI workflows |
| `plugins` | Inspect extension plugin registry status without loading third-party plugin code |
| `profiles` | Manage named CLI profiles for repeatable scan contexts |
| `proxy-bootstrap` | Generate managed endpoint onboarding material |
| `samples` | Create bundled sample inputs for demos and first runs |
| `sidecar-injector` | Run the TLS admission webhook for sidecar injection |
| `upgrade` | Check for and install the latest version of agent-bom |
| `completions` | Print a shell completion script |

## Command contracts

- `check` supports terminal output by default plus `--format json` for machine-readable pre-install verdicts.
- `report history` and `report diff` support `--format json` for CI and automation.
- `report pipeline-events <scan-job.json>` exports structured scan progress as JSONL for DAG/dashboard consumers.
- `report query "SELECT ..."` runs read-only SQL against the local scan analytics store.
- `remediate` is read-only by default and supports `--format json` as the machine-readable remediation contract.
- `remediate --apply` patches supported package dependency manifests only after confirmation; `--apply --open-pr` creates a draft PR instead of pushing to the default branch.
- `agents --agent-mode` emits a stable JSON envelope for assistant and automation callers. It defaults to JSON stdout and reports `ok`, `exit_code`, `data_mode`, summary counts, confidence signals, and truncation metadata.
  - By default `data_mode` is `summary`: the `data` field carries a bounded payload — counts (packages by ecosystem, findings/exposure by severity), the top 10 ranked findings and exposure paths, and a summary-level agent inventory. The full inlined per-package provenance dump (`ai_inventory`, `ai_bom_entities`, the complete `findings`/`packages` lists) is omitted so the payload fits an LLM/automation context window. For a ~877-package repo this drops the envelope from tens of MB to a few KB.
  - For the complete report, add `--agent-mode-full` (sets `data_mode: "full"` and inlines the legacy full payload), or write full JSON to disk with `agent-bom agents -o report.json --format json`. `data.full_report` records this on every summary payload.
  - `--agent-token-budget <TOKENS>` further trims either shape to an approximate JSON token budget.
- Use `agent-bom agents -f <format> -o <path>` for SARIF, HTML, SBOM, and richer environment exports.
- Use `agent-bom agents -f sarif -o -` when you need SARIF on stdout for piping.
- `where` is available both as `agent-bom where` and `agent-bom mcp where`.
- `agent-bom verify` and `agent-bom verify agent-bom` both self-verify the installed package.
- `cloud aws` / `cloud azure` / `cloud gcp` (and `cloud scan --provider <name>`) exit non-zero when an explicitly requested provider hard-fails discovery or its CIS benchmark because the provider SDK is not installed or credentials are absent/invalid. The helpful `pip install 'agent-bom[<provider>]'` / credential-setup message is still printed. A genuinely empty-but-successful scan (credentials present, no AI resources) still exits 0, and one provider failing never aborts the others — every requested provider is still attempted, the exit code only reflects that one hard-failed. `cloud scan --provider all` only scans auto-detected configured clouds, so unconfigured clouds are skipped (not failed) and the run stays at exit 0.
- `secrets` accepts `--offline` as a no-op for parity with `agents`/`scan`; secret scanning is always local and never makes network calls, so shared CI invocations that pass `--offline` work unchanged.

## Headless control-plane ingest

Use these when CI, a laptop, or an MCP client needs to push evidence into a
running control plane without opening the dashboard.

See also [docs/INGEST_PATHS.md](https://github.com/msaad00/agent-bom/blob/main/docs/INGEST_PATHS.md)
for the full SARIF / Trivy / Grype matrix and the `findings push` vs
`--external-scan` tradeoff.

```bash
# Push external scanner output (Trivy / Grype / Syft / tool-agnostic SARIF) or normalized findings JSON
agent-bom findings push ./trivy.json \
  --api-url https://agent-bom.internal.example.com \
  --api-key "$AGENT_BOM_API_KEY" \
  --source trivy

# Full local scan depth from an external report (no control plane required)
agent-bom agents --external-scan ./findings.sarif -f json -o report.json  # imports; does not execute Semgrep
agent-bom agents --external-scan ./trivy.json -f json -o report.json

# List findings back from the control plane (lifecycle columns when present)
agent-bom findings list --api-url https://agent-bom.internal.example.com --api-key "$AGENT_BOM_API_KEY"

# Discover local MCP agents and sync fleet inventory
agent-bom fleet sync \
  --push-url https://agent-bom.internal.example.com/v1/fleet/sync \
  --push-api-key "$AGENT_BOM_PUSH_API_KEY"
```

**`findings push` vs `--external-scan`:** bulk push lands rows in the control-plane
findings queue (`POST /v1/findings/bulk`) — best for fleet triage and dashboard
review. `--external-scan` imports evidence through the full local scan pipeline (blast radius, graph,
compliance, exports) and merges with discovered MCP context; use it for CI gates
and air-gap reports. Tool-agnostic SARIF from any conforming producer is
auto-detected on both paths (#3585).

**VM / registry matrix:** scan with Trivy (`trivy rootfs` or `trivy image`), then
either `--external-scan` for local depth or `findings push` for control-plane
queue. Registry sweeps: `agent-bom cloud registry-scan --provider ecr --region …`.

**Unified findings queue:** bulk-ingested findings appear in `GET /v1/findings`
and the dashboard `/findings` page. Hub-native clients can also call
`GET /v1/compliance/hub/findings`; there is no separate hub-findings browser
page — compliance shows hub posture totals only.

**Lifecycle columns:** the dashboard and `findings list` show **Status**,
**First seen**, and **Last seen** only when the API returns lifecycle metadata
(bulk-ingested / reconciled rows). Scan-only job findings omit those fields.

**Local pilot URLs:** `findings push` and `fleet sync` accept
`http://127.0.0.1:8422` loopback control-plane URLs for local Docker pilots.
Remote HTTP endpoints still require HTTPS (or
`AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS=1` for private-network pilots).

**Air-gap:** export `AGENT_BOM_SKIP_UPDATE_CHECK=1` or `AGENT_BOM_OFFLINE=1`
before invoking the CLI to suppress the background PyPI version check (it starts
before subcommand flags are parsed).

## Common flags

```bash
# Output format
agent-bom agents -f json|html|sarif|csv|cyclonedx|spdx

# Output file
agent-bom agents -o report.json
agent-bom check requests@2.33.0 -e pypi -f json -o check.json
agent-bom report diff before.json after.json -f json -o diff.json
agent-bom report pipeline-events scan-job.json -o pipeline-events.jsonl
agent-bom report query "SELECT severity, COUNT(*) AS count FROM scan_findings GROUP BY severity" --format json

# Assistant / automation envelope (bounded summary by default)
agent-bom agents --agent-mode
agent-bom agents --agent-mode --agent-mode-full      # inline the complete report
agent-bom agents --agent-mode --agent-token-budget 4000

# Compliance
agent-bom agents --compliance owasp-llm,eu-ai-act,all

# SBOM
agent-bom agents -f cyclonedx -o bom.json
agent-bom agents -f spdx -o bom.spdx.json

# Scan a public repo by URL (shallow clone, static, read-only, auto-cleaned)
agent-bom agents --repo https://github.com/org/repo

# Image scanning
agent-bom agents --image python:3.12-slim

# Policy
agent-bom agents --policy policy.json

# Enrichment
agent-bom agents --enrich    # NVD CVSS v4 + EPSS

# Prometheus
agent-bom agents --push-gateway http://pushgateway:9091

# VEX
agent-bom agents --vex vex.json
agent-bom agents --generate-vex --vex-output vex.json

# Config directory
agent-bom agents --config-dir /path/to/configs

# Self-scan (scan agent-bom's own installed dependencies)
agent-bom agents --self-scan

# Cloud — one cloud-aware scan across every configured provider (read-only)
agent-bom cloud scan                            # --provider all, auto-detects configured clouds
agent-bom cloud scan --provider aws --cis --show-passed
agent-bom cloud aws                             # alias for cloud scan --provider aws
agent-bom cloud registry-scan --provider ecr --region us-east-1   # sweep an ECR/ACR/GAR registry, read-only

# Vulnerability data freshness (same indicator surfaced on every scan, API, and MCP tool)
agent-bom db freshness
```

The `--self-scan` flag is on the `agents` subcommand (not top-level). It walks the active Python environment via `importlib.metadata.distributions()` and emits a CVE report against agent-bom's own runtime so you can audit the tool with the tool.

The `--repo <URL>` flag scans a public git repository by link without a local checkout. The repo is shallow-cloned (`git clone --depth 1 --single-branch`, no submodules, no credential prompt) into a temporary directory, scanned **statically** (its code is never executed), and the temp directory is always removed afterwards. Clones are bounded by a wall-clock timeout, a total-size cap, and a file-count cap (`AGENT_BOM_REPO_SCAN_*`). Only well-formed `http(s)` URLs are accepted; ssh/scp-style and local paths are rejected. For private repos, set `AGENT_BOM_REPO_SCAN_TOKEN` (reference-only; never logged or emitted). `--repo` is mutually exclusive with `--project/-p`. The same option is exposed on the MCP `scan` tool as `repo_url`.

## Troubleshooting

See [CLI Debug Guide](cli-debug.md) for quiet/logging behavior, stdout vs file output, discovery triage, and package verification workflows.

Use the
[Inaccurate Finding](https://github.com/msaad00/agent-bom/issues/new?template=inaccurate_finding.yml)
template for false positives, false negatives, wrong severity/advisory mapping,
or misleading remediation. Include sanitized JSON/SARIF output and public
evidence; do not post secrets, private source code, private package names, or
customer data.
The repository includes a
[sanitized inaccurate-finding report example](https://github.com/msaad00/agent-bom/blob/main/docs/INACCURATE_FINDING_REPORT.md)
with a copy-paste-safe issue body.

For the JSON contract behind `agent-bom remediate`, see [`remediate` Output
Contract](remediate-output.md).

## Environment variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `NVD_API_KEY` | Increase NVD rate limit | No |
| `SNYK_TOKEN` | Optional commercial vuln-API enrichment | No |
| `AGENT_BOM_CLICKHOUSE_URL` | Analytics storage | No |
| `AWS_PROFILE` | AWS CIS benchmark | Only for `cloud aws --cis` / `cloud scan --provider aws` |
| `SNOWFLAKE_ACCOUNT` | Snowflake CIS benchmark | Only for `agents --snowflake` CIS posture |
| `AGENT_BOM_OKTA_DISCOVERY` / `AGENT_BOM_ENTRA_DISCOVERY` | Gate `identity discover` and discovered-NHI credential expiry | Only for NHI discovery |
| `AGENT_BOM_AWS_INVENTORY` / `AGENT_BOM_AZURE_INVENTORY` / `AGENT_BOM_GCP_INVENTORY` | Gate `cloud inventory` and `cloud scan` per provider | Only for cloud connect / estate inventory |
| `AGENT_BOM_VULN_DB_MAX_AGE_HOURS` / `AGENT_BOM_VULN_DB_OFFLINE` | Staleness threshold and offline override behind the `db freshness` indicator | No |
| `AGENT_BOM_API_URL` / `AGENT_BOM_API_KEY` / `AGENT_BOM_API_TOKEN` | Control-plane base URL and credentials for `findings push` and MCP bulk ingest | Only for headless push |
| `AGENT_BOM_PUSH_URL` / `AGENT_BOM_PUSH_API_KEY` | Fleet sync destination (`/v1/fleet/sync`) and bearer token | Only for `fleet sync` |
| `AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS` | Allow HTTP / loopback outbound URLs for local fleet sync pilots | Only when pushing to local HTTP endpoints |
| `AGENT_BOM_SKIP_UPDATE_CHECK` / `AGENT_BOM_OFFLINE` | Suppress background PyPI version check on CLI startup | Air-gap / offline installs |
| `AGENT_BOM_REGISTRY_MAX_IMAGES` / `AGENT_BOM_REGISTRY_MAX_TAGS_PER_REPO` | Cap the `cloud registry-scan` work list | Only for registry sweeps |
