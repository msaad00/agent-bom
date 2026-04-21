# agent-bom dashboard

This is the Next.js dashboard for `agent-bom`.

## Recommended local run

If you want the same product surface users get from the CLI, run:

```bash
pip install 'agent-bom[ui]'
agent-bom serve
```

That starts the API on `http://localhost:8422` and serves the bundled dashboard.

## UI development

Run the dashboard and API separately when working on frontend changes:

```bash
agent-bom api
npm run dev
```

The UI reads `NEXT_PUBLIC_API_URL`.

- in development, the Next server uses it for local rewrites
- in containers, the runtime entrypoint writes it into `public/runtime-config.js`
  so the same image can be pointed at a different API endpoint at startup

If it is unset, the dev server proxies `/v1/*`, `/health`, and `/ws/*` to `http://localhost:8422`.

For same-origin ingress in Kubernetes or other reverse-proxy setups, set:

```bash
NEXT_PUBLIC_API_URL=
```

That keeps browser requests relative (`/v1/...`) so the ingress can route API
paths to the backend service without rebuilding the UI image.

## Browser auth model

The dashboard supports two browser auth modes:

- Recommended: same-origin reverse-proxy OIDC/session auth. The proxy keeps the browser session and injects trusted `X-Agent-Bom-Role` plus `X-Agent-Bom-Tenant-ID` headers to the API. Enable `AGENT_BOM_TRUST_PROXY_AUTH=1` on the backend for this mode.
- Fallback: a short-lived API key entered into the dashboard and stored in `sessionStorage` for the current browser tab/session only.

All browser fetches use `credentials: "include"` so proxy-managed sessions work without custom patches.

## Frontend quality gates

The UI now ships with two extra release guards:

- `npm run bundle:check` verifies the checked-in client bundle budget against the built `.next/` output.
- `npm run test:e2e` runs the packaged browser path (`scan -> result -> export`) with Playwright.

For local E2E runs, build first:

```bash
npm run build
npm run test:e2e
```

If you see `Failed to fetch`:

1. Make sure `agent-bom api` is running.
2. Check the browser console for CORS or network errors.
3. Confirm `NEXT_PUBLIC_API_URL` points at the backend you expect.

## Offline demo path

Use the built-in demo to exercise the dashboard without scanning a real project:

```bash
agent-bom agents --demo --offline -f json -o report.json
```

Then import `report.json` from the dashboard home page.
