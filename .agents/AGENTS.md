# Agent Guidelines for agent-bom

This is the root operating guide for agent contributors working in this repo.
Keep it concise and route deep implementation details to the owning docs,
tests, or package directories.

`agent-bom` is an open security scanner and self-hosted control plane for
AI-era infrastructure. The product must prove value across local scans, CI
evidence, fleet inventory, graph-backed findings, MCP/runtime enforcement, and
customer-controlled deployments.

## Operating Contract

Every material change should satisfy four lenses:

| Lens | Question | Evidence expected |
|---|---|---|
| Product manager | Is the first run obvious, useful, and honest? | Clear command, visible artifact, no inflated claims, next step documented |
| Sales engineer | Can this be proven live in a buyer environment? | CLI/Docker/API/Helm/runtime smoke evidence or a specific reason it was not run |
| Account executive | Is the buyer/problem/value clear? | Framing tied to AI/MCP supply-chain risk, self-hosted adoption, and governance evidence |
| Software/security engineer | Is it safe, accurate, scalable, and operable? | Tests, strict validation, auth/tenant/audit behavior, failure mode, and rollback notes |

Do not present roadmap work as shipped product. If a claim is user-visible, tie
it to code, tests, screenshots, docs, or live command output.

## Project Structure

```text
agent-bom/
├─ src/agent_bom/              # Python package: CLI, scanners, API, MCP, runtime, graph
├─ ui/                         # Next.js dashboard
├─ deploy/helm/agent-bom/      # Kubernetes and Helm control-plane/runtime chart
├─ integrations/               # MCP registries, OpenClaw/Cortex/Docker integration assets
├─ docs/                       # repo docs, security evidence, architecture, skills
├─ site-docs/                  # published documentation site
├─ tests/                      # Python regression and contract tests
├─ sdks/typescript/            # TypeScript SDK surface
└─ .github/workflows/          # CI, release, dependency, and security automation
```

High-signal entry points:

- CLI scan path: `src/agent_bom/cli/agents/__init__.py`
- scanner driver metadata: `src/agent_bom/scanner_drivers.py`
- API app and routes: `src/agent_bom/api/server.py`, `src/agent_bom/api/routes/`
- graph persistence/API: `src/agent_bom/db/graph_store.py`, `src/agent_bom/api/routes/graph.py`
- MCP tools/server: `src/agent_bom/mcp_server.py`, `src/agent_bom/mcp_tools/`
- runtime proxy/gateway: `src/agent_bom/proxy_server.py`, `src/agent_bom/gateway_server.py`
- dashboard: `ui/app/`, `ui/components/`, `ui/lib/`
- deployment chart: `deploy/helm/agent-bom/templates/`

## Product Lanes

Use this framing when editing public docs, UI copy, release notes, demos, or
examples:

1. **Scan locally** — CLI, Docker, and GitHub Action produce findings, SARIF,
   SBOMs, HTML reports, and graph exports.
2. **Send evidence to a control plane** — fleet sync, REST API, Helm/EKS, and
   the browser UI centralize inventory, graph state, compliance, audit, and
   governance.
3. **Enforce runtime behavior** — MCP server mode, proxy/gateway, and Shield
   SDK turn the same model into assistant and tool-call controls.

These lanes are one product and one evidence model. They do not weaken the
self-hosted story: production control planes run in the customer's own cloud,
VPC, Kubernetes cluster, database, identity, and audit boundary.

## Integration Bar

Integrations are distribution surfaces, not footnotes. For integration work,
document the first command, credential boundary, artifact, and next step.

Important integration families:

- MCP/coding agents: Claude, Cursor, Windsurf, VS Code, Cortex Code, OpenAI
  Codex CLI, and other MCP clients.
- Skills/registries: OpenClaw skills, Cortex Code skill, MCP Registry,
  Smithery, Glama, Docker MCP registry.
- Developer workflow: CLI, Docker, GitHub Action, SARIF, SBOM, pre-install
  `check`, PR comments, and CI gates.
- Cloud and AI infra: AWS, Azure, GCP, Snowflake, Databricks, CoreWeave,
  Nebius, Hugging Face, OpenAI, W&B, MLflow, Ollama.
- Runtime and app frameworks: MCP proxy/gateway, Shield SDK, Anthropic/OpenAI
  SDK patterns, LangChain, CrewAI.
- Governance and observability: Postgres/Supabase, ClickHouse, Snowflake paths,
  OTEL, SIEM/export hooks, compliance bundles.

## Core Commands

```bash
uv run pytest -q
uv run ruff check src tests
uv run mypy src/agent_bom
uv run agent-bom agents --demo --offline

cd ui
npm run verify:toolchain
npm run typecheck
npm test -- --run
npm run build
```

Run narrower checks when the change is narrow, but list exactly what you ran in
the PR body.

Minimum verification matrix:

| Change scope | Minimum verification |
|---|---|
| CLI/scanner behavior | targeted `tests/test_cli*` or scanner tests plus one real `agent-bom agents` smoke |
| API routes/models | targeted API tests plus schema/codegen check when contracts change |
| graph persistence/API/UI | graph API tests plus a live or fixture graph with non-empty nodes and edges |
| runtime proxy/gateway | targeted runtime tests plus a live JSON-RPC smoke when feasible |
| Helm/deploy | `helm template` for affected profiles plus YAML lint where available |
| UI | `npm run verify:toolchain`, typecheck, tests; browser/screenshot review for visible changes |
| docs/positioning only | stale-command search and `git diff --check`; do not claim untested capabilities |
| dependency/toolchain | package-specific install, lockfile/toolchain verification, and affected tests |

## Repo Rules

- Keep changes scoped. Do not mix dependency bumps, product docs, UI changes,
  and scanner behavior unless one is required by the other.
- Preserve signed commits and avoid synthetic GitHub update-branch churn; use
  local rebase plus `--force-with-lease` when a PR branch must be refreshed.
- Do not edit generated artifacts unless the owning generation command is run
  and documented.
- For bug fixes, add or update a regression test that fails without the fix.
- For user-visible dashboard or graph changes, verify readability in light and
  dark themes and avoid dense unreadable canvases as the first view.
- For auth, tenant, audit, firewall, gateway, and proxy changes, document
  fail-open/fail-closed behavior explicitly.
- For docs, avoid vague capability lists. Prefer "first command -> artifact ->
  next step."

## Release Readiness

Before a release readiness claim, check:

- latest `main` CI state and open release-blocker issues
- PyPI/install smoke or local wheel smoke, depending on release stage
- Docker/Helm smoke for the advertised deployment path
- API `/health` and `/docs` behavior under the intended auth mode
- MCP tool listing and strict-argument behavior
- graph/finding links with real scan data, not only synthetic fixtures
- runtime proxy/gateway smoke when runtime is part of the release narrative
- README, Docker Hub README, docs site, version surfaces, and changelog alignment

If a check cannot be run, say so directly and keep the claim narrower.
