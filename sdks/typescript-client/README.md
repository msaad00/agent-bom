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
const manifest = await client.agentManifest();
const runtime = await client.runtimeProductionIndex();
const findings = await client.listFindings({ severity: "high" });
const paths = await client.exposurePaths({ limit: 5, minRisk: 70 });
const decision = await client.shouldIDeploy({
  candidate: "flask@2.0.0",
  blockRisk: 80,
});
const ingest = await client.ingestFindings({
  source: "agent-runtime",
  findings: [{ id: "finding-1", severity: "high" }],
});
const dataset = await client.registerDatasetVersion({
  datasetId: "hf-corpus",
  versionId: "2026-05-17",
  source: "ci",
});
const versions = await client.datasetVersions("hf-corpus");
const version = await client.datasetVersion("hf-corpus", "2026-05-17");
const advisory = await client.intelLookup("CVE-2026-0001");
const intel = await client.intelMatch({ ecosystem: "npm", name: "demo", version: "1.0.0" });
const sources = await client.intelSources();

console.log(
  health.status,
  manifest.schema_version,
  runtime.schema_version,
  findings.count,
  paths.paths.length,
  decision.decision,
  ingest.ingested,
  dataset.dataset.version_id,
  versions.count,
  version.dataset.version_id,
  advisory.schema_version,
  intel.schema_version,
  sources.schema_version,
);
```

## Boundary

This package wraps stable HTTP control-plane calls for JavaScript and
TypeScript consumers. It does not run local scanners itself, and it does not
embed secrets. Operators still own the control-plane URL, API key or bearer
token, tenant ID, network boundary, and retention policy.
