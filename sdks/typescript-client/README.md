# @agent-bom/client

Typed TypeScript client for the self-hosted `agent-bom` control plane.

This package is the API-client lane. It is separate from `@agent-bom/runtime`,
which stays focused on local MCP runtime detectors.

## Install

```bash
npm install @agent-bom/client
```

## Use

```ts
import { AgentBomClient } from "@agent-bom/client";

const client = new AgentBomClient({
  baseUrl: "https://agent-bom.example.com",
  apiKey: process.env.AGENT_BOM_API_KEY,
  tenantId: "default",
});

const health = await client.health();
const paths = await client.exposurePaths({ limit: 5, minRisk: 70 });
const decision = await client.shouldIDeploy({
  candidate: "flask@2.0.0",
  blockRisk: 80,
});
const ingest = await client.ingestFindings({
  source: "agent-runtime",
  findings: [{ id: "finding-1", severity: "high" }],
});

console.log(health.status, paths.paths.length, decision.decision, ingest.ingested);
```

## Boundary

This package wraps stable HTTP control-plane calls for JavaScript and
TypeScript consumers. It does not run local scanners itself, and it does not
embed secrets. Operators still own the control-plane URL, API key or bearer
token, tenant ID, network boundary, and retention policy.
