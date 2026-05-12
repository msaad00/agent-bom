# Visual language for agent-bom docs

Three media, used deliberately. agent-bom is one product with multiple
surfaces; images should show the surface being discussed without implying a
separate product or unshipped capability. Picking the right medium keeps the README
readable, mobile-friendly, and easy to keep in sync with code.

For product screenshots, the source of truth is the packaged Next.js
dashboard. Snowflake Streamlit views may still exist for Snowflake-native
deployments, but they are not the primary product visuals for README or docs.

## SVG — for hero visuals + dense product imagery

Use when:
- the diagram is the *story* of the section (blast-radius, scan pipeline, engine internals, compliance mapping)
- you need typographic control, color hierarchy, or dense info per pixel
- it does not change every PR

Files live in `docs/images/`, always shipped as `*-light.svg` + `*-dark.svg`
with `<picture>`+`prefers-color-scheme` switching. Hand-tuned, no auto-layout.

Current SVG inventory:

| File | What it shows | Where it lives in the README |
|---|---|---|
| `logo-{light,dark}.svg` | Brand mark | hero |
| `blast-radius-{light,dark}.svg` | CVE, package, MCP server, agent, credentials, and tools in one blast-radius path | hero, under tagline |
| `scan-pipeline-{light,dark}.svg` | 5-stage pipeline (discover → scan → analyze → report → enforce) | "How a scan moves" |
| `engine-internals-{light,dark}.svg` | Inside the scanner | available for deeper architecture docs; not currently embedded in the README |
| `compliance-{light,dark}.svg` | Finding → control → evidence packet | Compliance section |
| `demo-latest.gif` | Terminal demo (1.04MB after compression) | "Try the demo" |

Current PNG inventory:

| File | What it shows | Where it lives in the README |
|---|---|---|
| `dashboard-live.png` | Packaged Next.js dashboard risk overview | Product views |
| `dashboard-paths-live.png` | Packaged Next.js attack paths and exposure view | Product views |
| `mesh-live.png` | Focused agent mesh graph across agents, MCP servers, packages, tools, credentials, and findings | Product views |
| `security-graph-live.png` | Fix-first attack-path queue with export controls and remediation handoff | Product views |
| `lineage-graph-live.png` | Root-centered lineage investigation with bounded paths and reachability summary | Product views |
| `dependency-map-live.png` | Supply chain dependency map with scan pipeline counts and package risk distribution | Product views |
| `remediation-live.png` | Fix-first remediation surface | Product views |

Public README, Docker Hub, and marketplace screenshots should not duplicate the
same graph in dark and light themes. Use one focused, readable product capture
for graph proof; keep theme-specific screenshots in release QA notes only when a
theme regression is being verified.

## Mermaid — for code-true flows that evolve

Use when:
- the diagram mirrors a piece of code or config that changes (helm templates, middleware stack, deployment topology)
- editing it as text in a PR is more honest than re-rendering an SVG
- the layout is naturally **linear or single-radial** (no crossing edges)

Rules to avoid spaghetti:
1. Pick one direction (`LR` or `TB`), don't mix
2. Maximum one level of `subgraph` nesting; flatten the rest into siblings
3. Maximum 4–6 nodes per inner cluster — overflow goes into a paragraph below the diagram, not into the diagram
4. Edges should radiate from a single hub OR flow linearly — never form a mesh
5. Drop modifier nodes (logos, decorations) — Mermaid is structure, not decoration

Current Mermaid surface:
- `## Deploy in your own AWS / EKS` — 3-tier hub-and-spoke (endpoints → control plane → workloads + state + observability)
- `### How a request flows through the control plane` — linear left-to-right pipeline of middleware classes

## ASCII / monospace — for terminal output only

Use when the block is literally a terminal artifact (CLI output, code snippet,
config file). Do not use ASCII for architecture diagrams — every drift makes
it harder to read.

Current ASCII surface:
- The CVE blast-radius tree at the top of the README — it is what
  `agent-bom agents --offline` actually prints
- All `bash` / `yaml` / `json` code blocks — those are commands, not diagrams

## When in doubt

If the diagram is going to be referenced by an enterprise buyer's procurement
deck, ship SVG. If it's going to drift faster than the next release, ship
Mermaid. If a junior engineer would type it into a terminal, ship ASCII inside
a fenced code block.
