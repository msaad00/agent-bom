# Refreshing product screenshots

The four PNGs the README and architecture docs link to are checked in at
`docs/images/`:

| File | Route | What it shows |
|---|---|---|
| `dashboard-live.png` | `/` | Operator overview — agent / MCP / finding cards |
| `dashboard-paths-live.png` | `/security-graph` | Attack-path / blast-radius graph |
| `mesh-live.png` | `/mesh` | Agent mesh topology |
| `remediation-live.png` | `/findings` | Findings table with remediation actions |

These regenerate from a single Playwright job. Run it whenever the dashboard
visual surface changes — minimum once per minor release so the visible
version footer matches the tag.

## One-shot capture

The `/` Risk overview and `/findings` table render from in-memory state and
capture cleanly with the recipe below. The `/mesh` and `/security-graph`
routes render from **persisted graph storage** — they show skeleton/empty
surfaces in memory-only mode and need a Postgres-backed deployment with a
real scan persisted to render the topology and attack-path canvases.

```bash
# 1. Boot API with no-auth so the dashboard reads without a session token.
#    For mesh + security-graph captures, point AGENT_BOM_POSTGRES_URL at
#    a populated database first — otherwise those two routes capture
#    empty.
agent-bom api --port 8422 --allow-insecure-no-auth &

# 2. Push a real scan against the agent-bom repo so the dashboard has
#    rich blast-radius / attack-path data instead of demo-only stubs.
curl -X POST -H "Content-Type: application/json" \
  http://127.0.0.1:8422/v1/scan \
  -d '{"agent_projects":["'$PWD'"]}'

# 3. From ui/, run the screenshot job.  Playwright auto-boots the
#    Next.js dev server on :3001 (see ui/playwright.config.ts).
cd ui
NEXT_PUBLIC_API_URL=http://127.0.0.1:8422 npm run screenshots

# 4. Eyeball each PNG in docs/images/ before committing — `/mesh` and
#    `/security-graph` will show skeletons unless persisted graph
#    storage is configured.
git diff --stat docs/images/
```

## What lives in the script

`ui/e2e/screenshots.spec.ts` — one test per route, viewport pinned to
1440×900 so the captured image matches the README hero crop, network-idle
+ 800 ms settle so React Flow / charts finish mounting before the snap.

## When to add a new screenshot

Adding a new screenshot is a docs-facing surface change. Update **all** of:

1. `ui/e2e/screenshots.spec.ts` — add the new entry to `SHOTS`.
2. The README / docs page that references `docs/images/<new-name>.png`.
3. This file's table.

Tip: keep the route list short. Every new screenshot is another piece of
visual debt that drifts on the next UI refresh.

## CI guard

The screenshot job is intentionally **not** wired to CI — capturing meaningful
dashboards needs a populated API, and a mocked-out empty-state shot is worse
than the current PNG. Treat screenshot refresh as a release-checklist item
rather than a green/red gate.
