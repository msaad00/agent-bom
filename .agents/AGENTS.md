# Agent Guidelines for agent-bom

This is the root operating guide for **any agent or coding assistant** working
in this repo — Claude, Codex, Cursor, Continue, Aider, Windsurf, or human
contributors using one. Follows the [agents.md](https://agents.md) convention.

Keep it concise and route deep implementation details to the owning docs,
tests, or package directories.

`agent-bom` is an open security scanner and self-hosted control plane for
AI-era infrastructure. The product must prove value across local scans, CI
evidence, fleet inventory, graph-backed findings, MCP/runtime enforcement, and
customer-controlled deployments.

**Product vision:** plug-n-play for humans and agents — easy, accurate,
efficient, scalable, secure, up-to-date. Inventory → findings → compliance →
graphs (environments, lineage, identity, scans, MCP, agents).

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

## On task start, ALWAYS

- `git fetch origin main` before any audit and compare against the relevant
  base branch. Rebase, merge, or pull only when the current worktree is meant
  to move.
- Read recent commits (`git log --oneline -15`) and open PRs (`gh pr list`).
- Check `pyproject.toml` version vs the latest tag vs PyPI before claiming
  release state.
- For end-user audits, install fresh from PyPI in a clean venv. Do not trust
  the working tree.

## Never

- `Co-Authored-By:` an LLM (Claude, Codex, Copilot, GPT, Gemini, etc.) in
  commits.
- Tool-credit prefixes in PR titles, commits, or CHANGELOG entries
  (`[claude]`, `[codex]`, `[copilot]`, `[cursor]`, etc.) — they ship into
  GitHub release notes.
- Clutter marketing, positioning, release notes, PR titles, or benchmark claims
  with comparisons to other products — describe our own capabilities and users'
  needs. Integration code and supported-upstream docs may name a third-party
  service when the exact name is required for users to configure it.
- Release with broken imports, red tests, or unreleased `[Unreleased]`
  CHANGELOG entries left after tagging.
- Claim a file, feature, or behavior exists without reading the code that
  proves it.
- Open more than 4 PRs simultaneously in the same queue — open sequentially
  as each merges.
- Re-tag an existing version. Bump and tag forward only.
- `git push --force` to `main`, `--no-verify`, `--no-gpg-sign`, or amend
  published commits without an explicit user request.

## Always

- Verify before claiming. "Looks good" without running or reading the code is
  not allowed.
- Full-stack alignment on every material change: deps → data model → DB →
  API → middleware → outputs (JSON / SARIF / CycloneDX / SPDX / Markdown /
  HTML) → CLI → UI → tests → docs → CI guards → Helm / Docker.
- Canonicalize platform invariants server-side; don't raise on ad-hoc input
  where Pydantic validators can normalize.
- Non-trivial features ship as a 4-PR series: foundation → mechanical →
  surface → lock-in.
- When Phase N supersedes a Phase N-1 component, remove the old one in the
  same PR.
- Auth-by-default. New endpoints reject anonymous traffic unless the contract
  explicitly allows it.

## Engineering bar (six lenses, every change)

1. **Correctness** — tests pass; semantics match docs.
2. **Performance** — measured, not asserted; published benchmarks are real.
3. **Security** — auth-by-default, redaction-aware, audit-chain-signed where
   applicable.
4. **Observability** — healthz / correlation_id / OCSF-shaped logs / metric
   labels.
5. **Persistence** — backends abstracted (SQLite default, Postgres ready,
   ClickHouse planned); RLS where multi-tenant.
6. **Enterprise readiness** — Helm + values examples + EKS + Docker + Render /
   Fly + airgap path.

## PR / commit style

- Factual and impersonal. No chat-style prose ("you flagged X", "as we
  discussed").
- Title: `feat(area): ...`, `fix(area): ...`, `docs(area): ...`,
  `chore(deps): ...`, `refactor(area): ...`.
- Body: Summary (1-3 bullets) → Verification (commands run) → Notes (if any).
- Pin every claim to evidence (test name, command, screenshot, doc path).

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
- Never surface a raw exception string to an HTTP response body or a log line on
  API / cloud / runtime paths — raw exceptions carry secrets, ARNs, paths, and
  connection strings. Route response text through
  `agent_bom.security.sanitize_error(exc)` (use `generic=True` on
  auth/secret/encryption/session/broker paths) and log text through
  `sanitize_text(...)`. The `scripts/check_exception_sanitization.py` guard
  (pre-commit + CI) fails on new `detail=str(exc)` / `detail=f"...{exc}"` bodies
  and raw-exception log f-strings; use `# exc-safe: <reason>` only for a vetted
  exception.
- Before opening or updating a PR that touches `src/agent_bom/api/` routes or
  models (and after any change that regenerates a checked-in artifact), run
  `make preflight` — it runs the same drift gates as CI's **Version Alignment**
  job (OpenAPI `docs/openapi/`, v1 schemas `docs/schemas/v1/`, product-surface
  contract, release consistency, env-var reference, SDK `patterns.json`). Use
  `make preflight-fix` to regenerate the artifacts, then review and commit them.
  Skipping this is the most common cause of an approved PR going red on a stale
  generated file — regenerate locally instead of round-tripping through CI.
- Run the tests for the code you touched **before** pushing (`pytest` on the
  affected `tests/test_*.py` files; test order is randomized by pytest-randomly,
  so a green local run on your files is the fastest signal). Push a PR branch
  **once and let CI finish** — CI uses `cancel-in-progress` on non-`main`
  branches, so stacking rapid commits (formatter, merge-main, review-dismissals)
  cancels the in-flight run and the canceled jobs surface as red "failing"
  checks. When a check's annotation reads "The operation was canceled," that is a
  supersede/cancel, not a test failure: re-run the job (`gh run rerun --failed`)
  and leave the branch untouched until it completes — do not debug it as a code
  bug.
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
