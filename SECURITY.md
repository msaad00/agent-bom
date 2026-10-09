# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](https://github.com/msaad00/agent-bom/security/advisories/new).

For procurement-facing support boundaries, patch cadence, escalation paths, and
release-note security language, see
[docs/ENTERPRISE_SUPPORT_MODEL.md](docs/ENTERPRISE_SUPPORT_MODEL.md).

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

The open-source project supports the latest released tag. Older release lines
are not maintained as long-term support branches unless a separate commercial
or customer-specific agreement exists.

## Trust model and permissions

agent-bom is **read-only by default**. A scan reads configuration, manifests,
images, and cloud inventory, and changes nothing it scans. A small set of
capabilities goes further. Each one is off until an operator turns it on, is
scoped to the narrowest target that does the job, and leaves a record.

### Default: read-only scanning

- **Reads:** agent and MCP client configs, lock files and manifests, SBOMs,
  container images (`--image`), Kubernetes pod specs (`--k8s`), IaC sources,
  and cloud provider APIs when credentials are configured. Run
  `agent-bom agents --dry-run` to preview the access plan. The full path list
  and every outbound lookup are in [docs/PERMISSIONS.md](docs/PERMISSIONS.md).
- **Does not launch or call MCP servers.** Discovery parses server definitions
  only. Launching a server for live introspection is opt-in (`--introspect`, below).
- **Does not read or store credential values.** Env var values in MCP configs are
  redacted at parse time; reports carry credential *names* only.
- **Does not change external state.** Cloud inventory uses read-only roles. The
  reference AWS policy is
  [`scripts/provision/aws_readonly_policy.json`](scripts/provision/aws_readonly_policy.json)
  (List/Get/Describe-class actions only). Local writes go only to paths you pass
  (`--output`, `--save` history).

### Capabilities that go beyond read-only

| Capability | What it changes, and why | How it is enabled | Scope and authorization | Credentials (least privilege) | Record |
|---|---|---|---|---|---|
| **Disk side-scan** (AWS EBS, Azure Managed Disk, GCP Persistent Disk) | Creates a tagged snapshot and a temporary disk, attaches it to an in-account collector, mounts it `ro,nosuid,nodev,noexec`, then deletes the disk and snapshot. Needed to read a workload's filesystem SBOM without an agent. Only package, CVE, and secret type/location metadata leave the collector. | `AGENT_BOM_SIDESCAN=1` (off by default). The scheduler also needs `AGENT_BOM_SIDESCAN_SCHEDULER` (off). | One target volume per run. The CLI, `POST /v1/cloud/side-scan` (admin-only, tenant-scoped), and the MCP `cloud_side_scan` tool all return `disabled` without the flag. If unmount fails, resources are kept and their IDs reported rather than force-deleted; a sweep removes tagged orphan snapshots. | A separate lifecycle role, never the scanner role: `deploy/terraform/connect-aws-sidescan`, `deploy/terraform/connect-azure-sidescan`, `deploy/terraform/connect-gcp-sidescan`. The AWS role can delete only snapshots and volumes carrying the side-scan tag. | Durable lifecycle record with resource IDs and cleanup status (`GET /v1/cloud/side-scan/{execution_id}`) |
| **Live MCP introspection** | Starts configured stdio MCP servers as local subprocesses, or connects to SSE/HTTP servers, to compare their real tool list with the config. Calls `initialize` and the `*/list` methods only, never `tools/call`. | `--introspect` on a scan, or `agent-bom mcp introspect`. The MCP-server tool also requires `allow_command_execution` (off). | Servers flagged by security checks are never launched. Each connection has a timeout and every subprocess is stopped on exit. Env values passed to servers are already redacted. | None beyond the server's own config | Introspection report in scan output |
| **Runtime proxy and gateway** | Sits in the MCP call path. Can block tool calls a policy denies and, with `--detect-credentials`, redact leaked credentials from responses. Needed for enforcement, not just detection. | `agent-bom proxy -- <server>` or `agent-bom gateway serve`. Blocking requires a policy (`--policy`, `--block-undeclared`); `--log-only` is advisory. | The proxy runs stdio servers in a hardened container by default (`--isolate`). The firewall fails closed when the gateway and local policy are both unavailable. `gateway serve` refuses non-loopback binds without client auth unless explicitly overridden. Policy edits through the API are admin-only. | Gateway bearer token or control-plane token you issue | Hash-chained JSONL audit log (`--log`) of relayed and blocked calls |
| **Fleet containment** | Quarantines an agent and publishes an `enforce`-mode gateway deny policy bound to that agent ID, so its relayed calls are refused. | `POST /v1/fleet/{agent_id}/quarantine` (or the UI). Reversed by moving the agent out of the quarantined state (`PUT /v1/fleet/{agent_id}/state`), which disables the deny policy. | Admin-only (`policy_write`), tenant-scoped, one agent per call. Takes effect only where traffic goes through the gateway. | Control-plane session or API key | `fleet.quarantine` audit event |
| **Proxy rollout** | Rewrites supported JSON MCP client configs so each stdio server runs through the proxy. | `agent-bom runtime configure` and `agent-bom proxy-bootstrap` preview only; `--apply` writes. | Discovered client configs on the current machine. Each file is replaced atomically and keeps its file mode. | None | Changed files listed in output |
| **Dependency remediation** | Edits dependency manifests to fixed versions and, optionally, opens a draft PR. | `agent-bom remediate --apply` (asks for confirmation unless `-y`); `--open-pr` adds a branch, commit, push, and draft PR. | Refuses dirty worktrees and writes outside the git root. Keeps `.agent-bom-backup` copies unless `--no-backup`. Re-validates manifests before any PR unless `--skip-verify`. | Your existing `gh` login; nothing new is stored | Remediation audit JSONL |
| **Ticket filing** | Creates issues in a connected ITSM project for findings. | A stored ticketing connection, then the UI, `POST /v1/ticketing/tickets`, or the CLI. | Tenant-scoped; analyst or admin role. Idempotent per finding. | A token limited to the target project, encrypted at rest | `ticketing.create` audit event and a finding-to-ticket link |
| **Outbound destinations** (push, scheduled exports, SIEM, webhooks, Slack, compliance platforms, AI enrichment) | Sends sanitized findings or events to a destination you configure. | Off until a flag, URL, token, or destination is set. See [docs/PERMISSIONS.md](docs/PERMISSIONS.md#explicit-push-export-and-integration-destinations). | Tenant-scoped. Export destinations need analyst or admin; webhooks need admin, are SSRF-validated at registration, and are delivered only by an operator-run worker. | Destination-specific, write-only to that destination | Audit events for destination and webhook changes |
| **Control-plane state** | `agent-bom api` writes scans, findings, graph, connections, and audit records to its own SQLite or Postgres store. | Running the control plane. | Every request resolves a tenant; cross-tenant reads and writes are rejected. See [docs/TRUST.md](docs/TRUST.md). | Database credentials you provision | Append-only, HMAC-signed audit log |
| **Demo modes** | `--demo` scans a bundled sample; `api --demo-estate` seeds synthetic data. | Explicit flags. | Demo estate runs in its own state directory and is labeled as demo data in the UI. No external writes. | None | n/a |

To keep a deployment strictly read-only: leave `AGENT_BOM_SIDESCAN` unset, do
not pass `--introspect`, `--apply`, or `--open-pr`, do not run the proxy or
gateway, and configure no outbound destination or ticketing connection.
`agent-bom trust --format json` prints the boundary contract the running build
reports.

### Secure defaults

- `agent-bom api` binds `127.0.0.1:8422`. With no API key, OIDC, SAML, SCIM, or
  trusted-proxy auth configured, requests fail closed with `401`. On loopback
  the CLI mints a local dev key that the bundled UI uses. Anonymous access needs
  an explicit `--allow-insecure-no-auth`.
- Connector secrets (cloud connection external IDs, ticketing, export
  destination, endpoint connector, and model-provider keys) are Fernet-encrypted
  at rest with `AGENT_BOM_CONNECTIONS_KEY`, resolved from env, AWS Secrets
  Manager, KMS envelope, or Vault (`AGENT_BOM_CONNECTIONS_KEY_PROVIDER`). With no
  key, those routes refuse to store a secret (`503`) instead of falling back to
  plaintext. Exception: a local loopback or explicit no-auth first run seeds a
  key file under the state directory (`~/.agent-bom/connections.key`); set
  `AGENT_BOM_NO_AUTO_CONNECTIONS_KEY=1` to disable that.
- **Caveat:** webhook signing secrets are stored as-is in the control-plane
  database because delivery needs them to sign payloads. They are not encrypted
  by `AGENT_BOM_CONNECTIONS_KEY` and are never returned after creation. Protect
  the database (disk encryption, restricted access) accordingly.
- Set `AGENT_BOM_AUDIT_HMAC_KEY` in production. Production or multi-replica
  control planes fail closed without it unless
  `AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC=1` is set.

### Credential handling
- agent-bom does not store cloud credentials. They come from the provider's
  default chain (profile, workload identity, application default credentials).
- Credential names and env var keys appear in output as `***REDACTED***`.
- Redaction is heuristic (regex patterns) and may miss obfuscated or non-standard key names.

### Known limitations
- **Credential redaction is heuristic.** Non-standard or obfuscated key names may not be flagged.
- **External scanner dependency.** Container image scanning can rely on external binaries; their CVEs apply to those tools.
- **Network dependency.** OSV/NVD/EPSS enrichment requires outbound HTTPS; air-gapped environments see reduced coverage.
- **Runtime proxy enforcement.** The proxy uses a trust-on-first-use model; pre-existing compromised servers must be identified by scanning before the proxy is deployed.

### API security (when running `agent-bom api`)
- Defaults to localhost-only binding (`127.0.0.1:8422`)
- `/docs`, `/redoc`, and `/openapi.json` support local onboarding. Production Compose and Helm profiles set `AGENT_BOM_DISABLE_DOCS=1` to disable those handlers.
- API key auth via `AGENT_BOM_API_KEY` env var; OIDC/JWT via `AGENT_BOM_OIDC_ISSUER`
- WebSocket endpoints use the same configured auth posture as HTTP routes. Handshake attempts are limited per transport peer before credential verification or the browser first-message wait; clustered deployments use the required shared PostgreSQL limiter and reject connections if that limiter is unavailable.
- Wildcard CORS is restricted to loopback development. Non-loopback listeners require explicit trusted origins. Direct ASGI imports using wildcard `AGENT_BOM_CORS_ORIGINS` must explicitly set `AGENT_BOM_API_HOST` to the loopback address used by the ASGI server; unknown listeners are rejected. The CLI passes its selected listener address directly.
- Listener diagnostics use the launcher's configured bind address, then `AGENT_BOM_API_HOST`. Direct ASGI imports with neither report an unknown listener scope in `/v1/auth/policy` and startup diagnostics. Set `AGENT_BOM_API_HOST` to the actual ASGI bind address; it is deployment metadata, not a network probe. Unknown scope does not enable anonymous access or change an explicit development/demo override.
- JWKS public key caching (1h TTL); RS256/RS384/RS512/ES256/ES384/ES512 supported; `alg: none` rejected
- Dashboard HTML uses a route-specific CSP. The packaged FastAPI-served UI allows `script-src 'self' 'unsafe-inline'` for the Next.js runtime bootstrap; API JSON routes keep the stricter `default-src 'self'` policy.
- `ui/vercel.json` is generated from the same CSP module as the standalone UI server (`ui/lib/security-headers.mjs`), so the two policies cannot drift and neither permits `eval`-style execution. Only the local development server relaxes `script-src`, for the Next.js dev runtime. That config exists for static UI previews and is not a supported control-plane deployment path: self-hosted control planes serve the dashboard from the Python API or the standalone UI container.

## Security Testing

- **Static analysis**: ruff + mypy on every PR (required CI checks)
- **Dependency scanning**: Dependabot weekly (Python + npm)
- **Container image scanning**: pinned scanner action in CI pipeline
- **Pre-commit hooks**: ruff, ruff-format, detect-private-key, check-yaml, end-of-file-fixer
- **Third-party penetration testing**: not completed yet; required before `v1.0` runtime-enforcement GA. Scope and exit criteria are documented in [docs/PENTEST_READINESS.md](docs/PENTEST_READINESS.md)

## Third-Party Pentest Plan

The independent assessment planned before `v1.0` is expected to cover:

- runtime proxy enforcement and audit integrity
- multi-MCP gateway auth, policy evaluation, and upstream relay behavior
- control-plane tenant isolation across API and dashboard surfaces
- reference EKS / Helm deployment hardening

The tracked scope, environment expectations, and `v1.0` release criteria live
in [docs/PENTEST_READINESS.md](docs/PENTEST_READINESS.md).

## Release verification and dependency controls

The public verification path is documented:

- [docs/RELEASE_VERIFICATION.md](docs/RELEASE_VERIFICATION.md) — Sigstore bundle verification, SLSA provenance inspection, and self-SBOM review
- [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) — dependency bounds, lockfiles, extras audit coverage, fuzz targets, and release trust controls

## Vulnerability Disclosure Timeline

1. Reporter submits via GitHub Security Advisories
2. Maintainer acknowledges within 48 hours
3. Issue triaged, CVSS severity assigned within 5 business days
4. Fix developed on private branch; CVE ID requested if warranted
5. Coordinated disclosure: patch released, advisory published simultaneously
6. Reporter credited in release notes (unless anonymity requested)

## Coordinated Disclosure Embargo

agent-bom follows a **90-day coordinated disclosure** model aligned with industry practice (CERT/CC, Project Zero):

- **Default embargo: 90 days** from the date the maintainer acknowledges the report
- **Critical (CVSS ≥ 9.0)**: 30-day target with possible 14-day extension if a patch is in active review
- **High (CVSS 7.0–8.9)**: 60-day target
- **Medium / Low (CVSS < 7.0)**: 90-day target
- **Extension requests** are considered case-by-case; the reporter is consulted before any extension
- **Early disclosure** is permitted if the vulnerability is being actively exploited in the wild, or if the reporter and maintainer mutually agree
- **Public CVE / GHSA publication** happens at the same moment as the patched release; the reporter is credited unless anonymity is requested
- **Private pre-disclosure** to downstream packagers (PyPI security, Docker Hub, distros) may occur up to 7 days before public disclosure when the maintainer has reasonable grounds to believe coordinated patching reduces aggregate risk

If the maintainer becomes unresponsive past the embargo deadline without prior coordination, reporters may publish at their own discretion 14 days after a documented final outreach attempt.
