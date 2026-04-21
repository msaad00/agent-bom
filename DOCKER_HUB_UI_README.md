# agent-bom-ui

**Standalone browser UI for the self-hosted `agent-bom` control plane.**

`agentbom/agent-bom-ui` is the separate Next.js UI container used when you run
the browser dashboard independently from the API.

It is **not** the scanner or control-plane backend by itself.

Use it with:

- `agentbom/agent-bom` for the API, scan jobs, gateway, proxy-related
  entrypoints, and other non-browser control-plane services
- your own ingress / SSO / Postgres setup when deploying the split UI + API
  control-plane shape

## Quick Start

```bash
docker run --rm -p 3000:3000 \
  -e NEXT_PUBLIC_API_URL=http://localhost:8422 \
  agentbom/agent-bom-ui:latest
```

Then run the API separately:

```bash
docker run --rm -p 8422:8422 agentbom/agent-bom:latest api
```

## Product Split

- `agentbom/agent-bom` = scanner, API, jobs, runtime/gateway entrypoints
- `agentbom/agent-bom-ui` = standalone browser UI only

## Links

- GitHub: https://github.com/msaad00/agent-bom
- Docs: https://msaad00.github.io/agent-bom/
- Helm chart: `oci://ghcr.io/msaad00/charts/agent-bom`
