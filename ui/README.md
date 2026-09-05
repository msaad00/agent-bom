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

The Next.js server reads `AGENT_BOM_API_URL` at runtime, with
`NEXT_PUBLIC_API_URL` retained as a legacy fallback. Browser API calls stay
same-origin. Changing the server destination does not require rebuilding.

If neither variable is set, the server proxies `/v1/*`, `/health`, `/version`,
and `/ws/*` to `http://localhost:8422`.

For same-origin ingress in Kubernetes or other reverse-proxy setups, set:

```bash
NEXT_PUBLIC_API_URL=
```

That keeps browser requests relative (`/v1/...`) so the ingress can route API
paths to the backend service without rebuilding the UI image.

## Browser auth model

The dashboard supports two browser auth modes:

- Recommended: same-origin reverse-proxy OIDC/session auth. The proxy keeps the browser session and injects trusted `X-Agent-Bom-Role` plus `X-Agent-Bom-Tenant-ID` headers to the API. Enable `AGENT_BOM_TRUST_PROXY_AUTH=1` on the backend for this mode.
- Local-only fallback: a short-lived API key entered into the dashboard. The UI exchanges it for a same-origin `httpOnly` browser session cookie and never stores or forwards the raw key from browser storage.

All browser fetches and EventSource streams use same-origin URLs plus `credentials: "include"` so proxy-managed sessions work without custom patches and runtime config cannot redirect browser credentials to a different origin.

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
3. Confirm `AGENT_BOM_API_URL` points at the backend reachable from the UI server.

## Offline demo path

Use the built-in demo to exercise the dashboard without scanning a real project:

```bash
agent-bom agents --demo --offline -f json -o report.json
```

Then import `report.json` from the dashboard home page.


### Runtime API destination

Run `AGENT_BOM_API_URL=http://api:8422 node server.js` inside the standalone
bundle, or set that variable on the UI container. The server forwards `/v1`,
`/health`, `/version`, and `/ws` to that origin at runtime. The same built image
can target a different API without rebuilding. Use an HTTP(S) origin without
credentials, paths, query parameters, or fragments. Invalid configuration returns
503; an unreachable backend fails the request rather than returning API success.

`AGENT_BOM_API_URL` takes precedence over the legacy `NEXT_PUBLIC_API_URL` runtime
setting. With neither set, the server uses `http://localhost:8422`. Browser API
requests and credentials remain same-origin. Use `npm run dev` and `npm run build`
to generate the server Proxy entry; `NEXT_EXPORT=1 npm run build` excludes it
for Python-served static assets.
