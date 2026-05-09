# Agentic Workflow Matrix

Use this page to choose the first integration path for an AI-agent workflow.
Each path should produce a concrete artifact before it moves into a control
plane or runtime enforcement rollout.

| Surface | Start with | Trust boundary | Evidence artifact | Move up to |
|---|---|---|---|---|
| Local CLI | `agent-bom agents --demo --offline`, then `agent-bom agents -p .` | Reads local agent and MCP configuration from the developer machine. No control-plane credentials required. | Terminal findings, JSON, SARIF, SBOM, HTML, graph export. | Scheduled scan, Docker, GitHub Action. |
| Claude, Cursor, Windsurf, VS Code, Cortex, Codex CLI | `agent-bom mcp server` | Exposes read-only security tools to the assistant. The assistant does not need direct scanner credentials beyond the local process boundary. | MCP tool output, inventory, blast-radius answers, compliance checks. | Shared MCP configuration, skills, fleet sync. |
| GitHub Actions | `uses: msaad00/agent-bom@v0.86.3` with SARIF upload enabled | Runs in CI with repository-scoped token permissions. Fork PR behavior depends on GitHub security policy. | `agent-bom-results.sarif`, pull-request summary, code-scanning alert category. | Branch protection, required code scanning, artifact retention. |
| Skills and instruction files | `agent-bom skills scan .` | Reads repo-local instructions such as `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, and `skills/*.md`. | Skill trust findings, referenced package and MCP inventory, credential-env names. | Signed skills, provenance verification, registry publishing. |
| Cloud and AI infrastructure | `agent-bom agents --preset enterprise` plus provider-specific flags only where credentials are approved. | Uses read-only provider APIs or local inventory files. Keep provider secrets in the operator boundary, not in repo docs. | Cloud, warehouse, GPU, model, dataset, and runtime package evidence. | Fleet sync, compliance exports, graph-backed findings. |
| Runtime proxy | `agent-bom proxy --no-isolate --log audit.jsonl --block-undeclared -- ...` | Wraps selected local MCP traffic. Policy can block before an upstream tool receives the call. Container containment requires a stdio MCP path plus a configured sandbox image or an existing container command. | Tier-A audit JSONL, policy decisions, runtime alerts, metrics, and sandbox posture when isolation is enabled. | Sidecar proxy, gateway policy pull, SIEM export. |
| Shared gateway | `agent-bom gateway serve --from-control-plane ...` | Centralizes auth, tenancy, routing, and policy for remote MCP upstreams. | Gateway health, policy evaluation, relay metrics, audit relay. | Helm/EKS gateway, tenant policies, autoscaling. |
| Shield SDK | `from agent_bom.shield import Shield` | Enforces allow/block decisions in-process where the application already sees tool calls. | Redacted alerts and application-local decisions. | Shared policy model, proxy/gateway parity, runtime monitoring. |

## Copy-Paste Workflows

### Local Developer Scan

```bash
agent-bom agents --demo --offline
agent-bom agents -p . -f html -o agent-bom-report.html
agent-bom agents -p . -f sarif -o agent-bom-results.sarif
```

Produces local review artifacts without requiring a hosted service. Use this
when the buyer or contributor needs to see the first finding path quickly.

### CI Security Review

```yaml
- uses: msaad00/agent-bom@v0.86.3
  with:
    scan-type: agents
    severity-threshold: high
    format: sarif
    upload-sarif: true
    pr-comment: true
```

Produces SARIF and pull-request evidence. If Code Scanning is empty, check the
SARIF troubleshooting guide before changing scanner behavior.

### Hosted Gateway Or Proxy Review

```bash
# Audit/policy only for a selected stdio MCP server.
agent-bom proxy --no-isolate --log audit.jsonl --block-undeclared -- npx @modelcontextprotocol/server-filesystem /workspace

# Add process containment by running the stdio MCP inside a pinned sandbox image.
agent-bom proxy \
  --sandbox-image ghcr.io/your-org/mcp-runtime:node20@sha256:<64-hex-digest> \
  --sandbox-image-pin-policy enforce \
  --sandbox-mount "$PWD:/workspace:ro" \
  --log audit.jsonl \
  --block-undeclared \
  -- npx @modelcontextprotocol/server-filesystem /workspace

agent-bom gateway serve \
  --from-control-plane https://agent-bom.example.com \
  --control-plane-token "$AGENT_BOM_CONTROL_PLANE_TOKEN" \
  --bearer-token "$AGENT_BOM_GATEWAY_BEARER_TOKEN"
```

Produces runtime audit and policy evidence for selected traffic. This is not a
claim that all MCP traffic is governed; it proves the selected proxy or gateway
path. Gateway policy governs remote MCP traffic; it does not containerize the
upstream server.

## Guardrails

- Do not present roadmap integrations as shipped product.
- Prefer read-only scan commands for first contact with a new environment.
- Keep provider, gateway, and CI tokens in the operator boundary.
- Record the command, artifact path, trust boundary, and next step in PRs and
  demos.
- Runtime causality requires proxy, gateway, trace, or Shield evidence. Static
  scans show reachability and exposure, not live tool-call causality.
