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

The UI reads `NEXT_PUBLIC_API_URL`. If it is unset, the dev server proxies `/v1/*`, `/health`, and `/ws/*` to `http://localhost:8422`.

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
