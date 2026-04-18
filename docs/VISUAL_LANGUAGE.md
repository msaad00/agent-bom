# Visual language for agent-bom docs

Three media, used deliberately. Picking the right one keeps the README
readable, mobile-friendly, and easy to keep in sync with code.

## SVG — for hero visuals + dense product imagery

Use when:
- the diagram is the *story* of the section (blast-radius, scan pipeline, engine internals, compliance mapping, topology)
- you need typographic control, color hierarchy, or dense info per pixel
- it does not change every PR

Files live in `docs/images/`, always shipped as `*-light.svg` + `*-dark.svg`
with `<picture>`+`prefers-color-scheme` switching. Hand-tuned, no auto-layout.

Current SVG inventory:

| File | What it shows | Where it lives in the README |
|---|---|---|
| `logo-{light,dark}.svg` | Brand mark | hero |
| `blast-radius-{light,dark}.svg` | Package → CVE → MCP → agent → credentials → tools | hero, under tagline |
| `scan-pipeline-{light,dark}.svg` | 5-stage pipeline (discover → scan → analyze → report → enforce) | "How a scan moves" |
| `engine-internals-{light,dark}.svg` | Inside the scanner | "How a scan moves" |
| `topology-{light,dark}.svg` | Focused graph view (start scoped, expand) | "How a scan moves" |
| `compliance-{light,dark}.svg` | Finding → control → evidence packet | Compliance section |
| `dashboard-live.png` `mesh-live.png` `remediation-live.png` | Live UI screenshots | Product views |
| `demo-latest.gif` | Terminal demo (1.04MB after compression) | "Try the demo" |

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
