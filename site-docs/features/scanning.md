# Scanning & Discovery

## Auto-discovery

agent-bom discovers MCP clients and their configured servers by reading config files from 20 supported clients:

| Client | Config path |
|--------|------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude/settings.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code Copilot | `~/Library/Application Support/Code/User/mcp.json` |
| Windsurf | `~/.windsurf/mcp.json` |
| Cline | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/...` |
| Roo Code | `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/...` |
| Codex CLI | `~/.codex/config.toml` |
| Gemini CLI | `~/.gemini/settings.json` |
| Goose | `~/.config/goose/config.yaml` |
| Cortex Code | `~/.snowflake/cortex/mcp.json` |
| Continue | `~/.continue/config.json` |
| Zed | `~/.config/zed/settings.json` |
| Amazon Q | VS Code globalStorage |
| JetBrains AI | `~/Library/Application Support/JetBrains/*/mcp.json` |
| Junie | `~/.junie/mcp/mcp.json` |
| OpenClaw | `~/.openclaw/openclaw.json` |
| Project-level | `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json` |

Linux paths use `~/.config/` equivalents.

## Vulnerability sources

| Source | Data |
|--------|------|
| [OSV](https://osv.dev) | Primary CVE database — covers PyPI, npm, Go, Maven, etc. |
| [NVD](https://nvd.nist.gov) | CVSS base scores (v3.1, then v3.0, then v2) |
| [EPSS](https://www.first.org/epss/) | Exploit probability scores (0.0–1.0) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities catalog |
| [GitHub Advisories](https://github.com/advisories) | Supplemental advisory data |
| Commercial vuln API | Optional enrichment when a vendor API token is configured |

### Severity basis

Online (OSV API) and `--offline` (local DB) scans derive severity from an
advisory with one precedence, so `--fail-on-severity` gates do not depend on
mode:

1. CVSS base score from the OSV `severity` array — v3.x, then v4.0, then v2.
2. Otherwise a CVSS score or vector in the advisory's vendor blocks
   (`database_specific`, `severity_vectors`, `affected[]`), v3.x before v4.0.
3. A CVSS score sets the severity band (`severity_source: cvss`); the reported
   `cvss_vector` is the one that produced the score, so its prefix
   (`CVSS:3.1/`, `CVSS:4.0/`) names the basis.
4. Otherwise the advisory's own label (`severity_source: osv_database`, …).
5. Otherwise a conservative namespace fallback (for example GHSA → medium,
   `severity_source: ghsa_heuristic`).

Local databases synced before this precedence keep their stored scores until the
next `agent-bom db update`.

### Declared version ranges

A range is never reported as a version. Without a lockfile, a `package.json`
spec such as `^4.0.0`, `5.0.0 || ^7.0.0`, or `*` (and the same in transitive
registry metadata, `npx pkg@^1`, install commands, PyPI specifiers, and
Terraform provider constraints) keeps the raw spec in `declared_version`, is
marked `floating_reference`, and is resolved online to the version a fresh
install selects — the `latest` dist-tag when it satisfies the range, else the
highest satisfying release. When nothing satisfies it, the registry is
unreachable, or the scan is `--offline`, the version stays `unknown`, has no
purl, and no advisory is matched against the range's lower bound. Git, URL,
file, alias, and workspace specs are never resolved to a registry version.

### Reproducible matching evidence

The committed, mutation-tested range benchmark currently covers 207 comparable
OSV advisories, 19,161 affected-version checks, and 576 fixed-version checks
with zero false negatives and zero false positives. The benchmark removes the
explicit affected-version list before exercising range logic, uses advisory
fixed releases as its defensible negative set, and fails under a deliberately
reintroduced multi-window bug. See the
[machine-readable result](https://github.com/msaad00/agent-bom/blob/main/docs/CVE_MATCHING_ACCURACY.json) and
[`scripts/cve_matching_accuracy.py`](https://github.com/msaad00/agent-bom/blob/main/scripts/cve_matching_accuracy.py).
This is a reproducible range-matcher baseline, not a universal scanner-accuracy
claim.

## Credential exposure detection

Config files are parsed for server definitions. Environment variable **values** are automatically redacted — only key names are reported. Patterns detected:

- AWS keys (`AKIA...`)
- GitHub tokens (`ghp_`, `gho_`, `ghs_`)
- OpenAI / Anthropic API keys
- JWTs, bearer tokens
- Connection strings with embedded passwords
- Private keys (PEM headers)

## Container image scanning

```bash
agent-bom image python:3.12-slim
```

Uses agent-bom's native image scanning pipeline to enumerate OS and language packages within container images.
The native parser reads Debian dpkg, Alpine apk, modern SQLite RPM databases,
and legacy RPM BerkeleyDB/NDB databases without requiring a scanner binary.
Malformed legacy RPM databases fail the scan instead of producing a clean
zero-package result.

The default OS result remains precision-first and reports distro-confirmed
advisories. To include unfixed, pending, no-DSA, and end-of-life distro
advisories for an exhaustive review, run:

```bash
AGENT_BOM_INCLUDE_UNFIXED=1 agent-bom image python:3.12-slim
```

The artifact is the same findings report with lower-confidence unfixed distro
rows included; review their match-confidence tier before using them as a CI
block. Language-package coverage is unaffected by this switch.

## IaC and cloud posture

When a CloudFormation template contains unreadable or malformed containers,
the scan keeps findings from valid resources and emits a coverage warning for
checks it could not evaluate. Inspect `coverage_warnings` and `scan_run.outcome`
in the JSON report before treating a scan as complete. This static check does
not resolve CloudFormation references or establish deployed cloud posture.

Use `agent-bom iac` as the pre-cloud gate for Terraform, CloudFormation,
Kubernetes, Helm-rendered manifests, and Dockerfiles. Use `agent-bom
cis-benchmark` as the runtime posture check for deployed cloud state. The
combined workflow catches proposed misconfiguration before apply and drift
after deployment.

See [Cloud Posture and IaC Gates](cloud-posture.md) for the recommended lane
split and CI example.
