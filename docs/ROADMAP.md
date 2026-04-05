# Roadmap

This roadmap reflects the current post-`v0.75.15` direction for `agent-bom`.
It is organized around product phases, not a loose feature wish list.

For the full backlog, see [open issues](https://github.com/msaad00/agent-bom/issues).

---

## Where the product stands now

`agent-bom` is already a serious OSS product:

- released on PyPI and Docker
- usable as a CLI, GitHub Action, API service, dashboard, and MCP server
- strong on MCP-aware blast radius, runtime proxying, skills scanning, and report output
- increasingly hardened for real deployments instead of only local demos

The next step is not random feature sprawl. It is tightening enterprise hardening and scanner depth while preserving the MCP and AI-native advantage.

---

## Phase 1: Security Preventives

Goal: make dependency, image, and supply-chain regressions visible early and actionable by default.

### In progress

| Item | Status |
|------|--------|
| Daily dependency update checks | Active |
| Daily self-scan issue automation | Active |
| Daily container rescan issue automation | Active |
| Security issue taxonomy for dependency, base-image, and drift regressions | Active |

### Next

| Item | Issue | Status |
|------|-------|--------|
| Supply-chain regression fixtures for compromised package release / typosquat / lockfile drift | New lane | Planned |
| Stronger release gates for suspicious source or provenance mismatch | New lane | Planned |
| Operator-visible vulnerability freshness and risk summaries in CLI/API/reporting | New lane | Planned |

---

## Phase 2: Enterprise Hardening

Goal: make the product secure and explainable by default in real deployments.

### In progress

| Item | Issue | Status |
|------|-------|--------|
| Helm security defaults: security context, probes, NetworkPolicy wiring | [#1214](https://github.com/msaad00/agent-bom/pull/1214) | Landed |
| Tenant isolation enforcement on fleet and schedule routes | [#1222](https://github.com/msaad00/agent-bom/pull/1222) | Landed |
| Postgres tenant session plumbing + first DB-level RLS slice | New lane | In progress |

### Next

| Item | Status |
|------|--------|
| Harden tenant isolation beyond soft app-layer filtering | Planned |
| Turn DB/schema/API/UI/report consistency into a standing release gate | Planned |
| Define an "enterprise pilot ready" bar for auth, tenancy, reporting, and observability | Planned |

---

## Phase 3: Scanner Depth

Goal: deepen package and lockfile coverage without losing the MCP-aware and runtime-aware differentiators.

### Priorities

| Item | Issue | Status |
|------|-------|--------|
| Lockfile-depth scanning to complement MCP/config-driven discovery | New lane | Planned |
| Broader package and ecosystem coverage where traditional SCA tools are stronger today | Existing backlog | Planned |
| Better regression coverage for supply-chain incidents and poisoned dependencies | New lane | Planned |

---

## Phase 4: MCP, Runtime, and Skills to 9/10

Goal: keep the most differentiated surfaces ahead of the market.

### MCP and runtime

| Item | Status |
|------|--------|
| Richer request tracing and operator observability | In progress |
| Clearer tool schema/versioning and deprecation rules | Planned |
| Stronger remote operator docs and governance depth | Planned |
| Remote MCP introspection beyond config-file discovery | Planned |

### Skills and instruction analysis

| Item | Status |
|------|--------|
| Move from regex-first detection toward AST-aware or control-flow-aware analysis where it materially improves signal | In progress |
| Add explicit schema/versioned output for skills results | Done |
| Expand trust, provenance, and rescan workflows | Planned |

---

## Phase 5: Contributor and Product Scale

Goal: preserve OSS momentum while making the product easier to extend and adopt.

| Item | Status |
|------|--------|
| Cleaner contributor path for scanners, outputs, and integrations | Planned |
| Dependabot batching and update-noise reduction | In progress |
| Additional CI templates and integration surfaces beyond GitHub-first flows | Planned |
| Commercial support / hosted control-plane path definition | Planned |

---

## Completed recently

| Item | Version / PR |
|------|---------------|
| `v0.75.15` release across PyPI, Docker, and GitHub Release | `v0.75.15` |
| GitHub Action hardening: safe argv, pip cache, summaries, cleaner contracts | `#1203`, `#1209` |
| MCP hardening: remote auth, sync-tool governance, caller rate limiting, metrics, tracing | `#1204`, `#1210`, `#1211` |
| Docker hardening: Snowpark proxy/CA support, runtime image from source | `#1205`, `#1208` |
| Daily preventive security automation | `#1213` |

---

This roadmap should evolve with shipped work and real product priorities, not become a dumping ground for unsequenced ideas.
