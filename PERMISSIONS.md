# Permissions & Trust Contract

agent-bom is a **read-only security scanner**. This document is an explicit,
auditable contract of what the tool accesses — and what it never touches.

---

## What We Read

agent-bom reads only what you explicitly ask it to scan:

| Target | How specified | What is read |
|--------|--------------|--------------|
| Agent configs | auto-discovery or `--project` | Config JSON/YAML files (e.g. `claude_desktop_config.json`) |
| Inventory | `--inventory` | Your inventory JSON file |
| Lock files | inferred from project | `package-lock.json`, `requirements.txt`, `Cargo.lock`, etc. |
| Docker images | `--image` | Image filesystem layers (via Grype/Syft subprocess) |
| Kubernetes | `--k8s` | Pod specs via `kubectl get pods -o json` (read-only) |
| Terraform | `--tf-dir` | `.tf` source files (no state files, no `.tfvars`) |
| GitHub Actions | `--gha` | `.github/workflows/*.yml` files |
| SBOM files | `--sbom` | CycloneDX/SPDX JSON you provide |

**Auto-discovery** reads these standard config paths (no other paths):
- `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
- `~/.config/claude/claude_desktop_config.json` (Linux)
- `~/.cursor/mcp.json`
- `~/.codeium/windsurf/mcp_config.json`
- `.claude/settings.json` in project root

Use `--dry-run` to preview exactly which paths would be read before any scan runs.

---

## What We Never Do

- **Never write** to any config file, lock file, or project file
- **Never execute** MCP servers or agent processes
- **Never store** credential values — only env var _names_ appear in reports as `***REDACTED***`
- **Never transmit** your file contents, project structure, or inventory to external services
- **Never cache** any personal data to disk (scan history is opt-in via `--save`)
- **Never require** authentication tokens or API keys (NVD key is optional for rate limits only)

---

## External API Calls

agent-bom queries these **public APIs only** — no user data is included in requests:

| Service | URL | What we send | What we receive |
|---------|-----|-------------|----------------|
| OSV.dev | `https://api.osv.dev/v1/querybatch` | Package names + versions | CVE IDs |
| NVD/NIST | `https://services.nvd.nist.gov/rest/json/cves/2.0` | CVE IDs | CVSS scores, CWE IDs |
| FIRST EPSS | `https://api.first.org/data/v1/epss` | CVE IDs | Exploit probability |
| CISA KEV | `https://www.cisa.gov/.../known_exploited_vulnerabilities.json` | _(none — full download)_ | KEV catalog |

All external calls: **no authentication**, **no user data**, **no tracking**.

---

## Credential Handling

Environment variables in MCP server configs are **never read for their values**.
Only the _key names_ (e.g. `OPENAI_API_KEY`, `DATABASE_URL`) are inspected to
determine whether credentials are present. Values are always shown as `***REDACTED***`.

---

## Verifying Our Claims

This is an open-source tool — you can verify every claim above:

| Verification | How |
|---|---|
| Read source code | `src/agent_bom/` — all scanning logic is in plain Python |
| Check network calls | `src/agent_bom/enrichment.py` — all external API calls |
| Audit credential handling | `src/agent_bom/models.py` — `MCPServer.credential_names` |
| Run in isolation | `--no-scan` skips all network calls; `--dry-run` reads nothing |
| Signed releases | Releases v0.7.0+ are signed via [Sigstore/cosign](https://www.sigstore.dev/) — `.bundle` files attached to each GitHub Release |
| OpenSSF Scorecard | [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/msaad00/agent-bom/badge)](https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom) |

---

## Least Privilege — API Server

When running `agent-bom api`, the HTTP server adds these headers to every response:

```
X-Agent-Bom-Read-Only: true
X-Agent-Bom-No-Credential-Storage: true
```

The API server itself runs entirely in-process. No outbound connections are made
unless a scan job explicitly requests enrichment (`"enrich": true` in the request body).

---

## Reporting a Security Issue

See [SECURITY.md](SECURITY.md) for responsible disclosure via GitHub Security Advisories.
