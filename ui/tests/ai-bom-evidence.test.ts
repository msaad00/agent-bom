import { describe, expect, it } from "vitest";

import {
  aiBomScopeLabel,
  countActiveEvidenceSources,
  deriveAiBomEvidenceSources,
  summarizeAiBomEntities,
} from "@/lib/ai-bom-evidence";
import type { AgentBomManifestResponse } from "@/lib/api";

const manifestFixture: AgentBomManifestResponse = {
  schema_version: "agent-bom.manifest/v1",
  generated_at: "2026-07-10T03:57:48Z",
  source: "control-plane",
  tenant_id: "default",
  summary: {
    agents: 0,
    mcp_servers: 9,
    tools: 42,
    credential_refs: 3,
    runtime_observed_servers: 2,
    gateway_registered_servers: 1,
  },
  visibility: {
    owners: 1,
    unowned_agents: 0,
    shadow_runtime_servers: 0,
    untracked_runtime_servers: 0,
    servers_with_warnings: 1,
    risky_credential_refs: 0,
    risk_signals: {
      unowned_agent_ids: [],
      shadow_runtime_server_ids: [],
      untracked_runtime_server_ids: [],
      risky_credential_refs: [],
    },
  },
  blueprint_drift: {
    status: "aligned",
    mode: "observation_only",
    fail_behavior: "report_only",
    signal_count: 0,
    signals: [],
  },
  agents: [],
  mcp_servers: [],
  graph: {
    nodes: [
      { id: "server:github", entity_type: "server", label: "github", attributes: {} },
      { id: "pkg:form-data", entity_type: "package", label: "form-data@4.0.0", attributes: {} },
      { id: "model:gpt-4", entity_type: "model", label: "gpt-4", attributes: {} },
    ],
    edges: [],
    stats: { nodes: 3, edges: 0, relationships: [] },
  },
  boundaries: {
    stores_credential_values: false,
    stores_raw_prompts: false,
    credential_value_policy: "names_only",
  },
};

describe("ai-bom-evidence", () => {
  it("builds a deployment-aware scope label instead of a vague local/default chip", () => {
    expect(
      aiBomScopeLabel(
        {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          total: 0,
          kev: 0,
          compound_issues: 0,
          deployment_mode: "local",
        },
        manifestFixture,
      ),
    ).toBe("Local · tenant default · control plane");
  });

  it("rolls up AI estate entities from the manifest graph", () => {
    expect(summarizeAiBomEntities(manifestFixture)).toEqual({
      agents: 0,
      mcpServers: 9,
      models: 1,
      packages: 1,
      credentials: 3,
      cloudAssets: 0,
      findings: 0,
    });
  });

  it("marks connected evidence sources from deployment posture", () => {
    const sources = deriveAiBomEvidenceSources(
      {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        total: 1,
        kev: 0,
        compound_issues: 0,
        deployment_mode: "hybrid",
        has_local_scan: true,
        has_fleet_ingest: true,
        has_proxy: true,
        scan_sources: ["aws", "agent_discovery"],
      },
      manifestFixture,
    );

    expect(countActiveEvidenceSources(sources)).toBeGreaterThanOrEqual(4);
    expect(sources.find((source) => source.id === "cloud")?.active).toBe(true);
    expect(sources.find((source) => source.id === "control-plane")?.active).toBe(true);
  });
});
