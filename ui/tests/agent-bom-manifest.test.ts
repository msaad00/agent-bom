import { describe, expect, it } from "vitest";

import {
  DEFAULT_MANIFEST_FILTERS,
  classifyFreshness,
  deriveManifestRows,
  filterManifestRows,
  manifestFilterOptions,
  type ManifestFilters,
} from "@/lib/agent-bom-manifest";
import type { AgentBomManifestResponse } from "@/lib/api";

const manifest: AgentBomManifestResponse = {
  schema_version: "agent-bom.manifest/v1",
  generated_at: "2026-05-19T12:00:00Z",
  source: "control-plane",
  tenant_id: "tenant-a",
  summary: {
    agents: 2,
    mcp_servers: 3,
    tools: 4,
    credential_refs: 2,
    runtime_observed_servers: 2,
    gateway_registered_servers: 1,
  },
  visibility: {
    owners: 1,
    unowned_agents: 1,
    shadow_runtime_servers: 1,
    untracked_runtime_servers: 1,
    servers_with_warnings: 1,
    risky_credential_refs: 1,
    risk_signals: {
      unowned_agent_ids: ["agent-2"],
      shadow_runtime_server_ids: ["srv-2"],
      untracked_runtime_server_ids: ["srv-2"],
      risky_credential_refs: ["ROOT_TOKEN"],
    },
  },
  blueprint_drift: {
    status: "needs_review",
    mode: "observation_only",
    fail_behavior: "report_only",
    signal_count: 1,
    signals: [{ kind: "untracked_runtime_server", entity_id: "srv-2", severity: "warning", message: "shadow" }],
  },
  agents: [
    { id: "agent-1", name: "claude-desktop", owner: "platform", environment: "prod" },
    { id: "agent-2", name: "cursor", environment: "dev" },
  ],
  mcp_servers: [
    {
      id: "srv-1",
      name: "filesystem",
      agent_name: "claude-desktop",
      transport: "stdio",
      auth_mode: "env",
      credential_refs: [{ name: "API_KEY", kind: "env" }],
      tools: [{ name: "read_file" }],
      discovery: { sources: ["local"] },
      security: { warnings: [] },
      observed: {
        runtime_observed: true,
        gateway_registered: true,
        configured_locally: true,
        fleet_present: true,
        last_seen: "2026-05-19T11:00:00Z",
      },
    },
    {
      id: "srv-2",
      name: "cloud-admin",
      agent_name: "cursor",
      transport: "stdio",
      auth_mode: "env",
      credential_refs: [{ name: "ROOT_TOKEN", kind: "env" }],
      tool_count: 3,
      discovery: { sources: ["runtime"] },
      security: { warnings: ["privileged credential"] },
      observed: {
        runtime_observed: true,
        gateway_registered: false,
        configured_locally: false,
        fleet_present: false,
        last_seen: "2026-05-10T11:00:00Z",
      },
    },
    {
      id: "srv-3",
      name: "docs",
      agent_name: "claude-desktop",
      transport: "http",
      auth_mode: "none",
      credential_refs: [],
      tools: [],
      discovery: { sources: ["fleet"] },
      security: { warnings: [] },
      observed: {},
    },
  ],
  graph: {
    nodes: [],
    edges: [],
    stats: { nodes: 0, edges: 0, relationships: [] },
  },
  boundaries: {
    stores_credential_values: false,
    stores_raw_prompts: false,
    credential_value_policy: "names_only",
  },
};

describe("Agent BOM manifest row filters", () => {
  const now = new Date("2026-05-19T12:00:00Z");

  it("derives cockpit rows with risk, source, runtime, and freshness classifications", () => {
    const rows = deriveManifestRows(manifest, now);

    expect(rows).toHaveLength(3);
    expect(rows.map((row) => [row.name, row.source, row.runtimeState, row.reviewStatus, row.freshness])).toEqual([
      ["filesystem", "local", "gateway bound", "not assessed", "seen_24h"],
      ["cloud-admin", "runtime", "shadow runtime", "review needed", "stale"],
      ["docs", "fleet", "inventory only", "not assessed", "unknown"],
    ]);
  });

  it("filters by explicit dimensions instead of only free text", () => {
    const rows = deriveManifestRows(manifest, now);
    const filters: ManifestFilters = {
      ...DEFAULT_MANIFEST_FILTERS,
      owner: "unowned",
      runtime: "shadow runtime",
      freshness: "stale",
      review: "review needed",
    };

    expect(filterManifestRows(rows, filters).map((row) => row.name)).toEqual(["cloud-admin"]);
  });

  it("filters source options and query text", () => {
    const rows = deriveManifestRows(manifest, now);

    expect(manifestFilterOptions(rows)).toEqual({
      owners: ["platform", "unowned"],
      sources: ["fleet", "local", "runtime"],
    });
    expect(filterManifestRows(rows, { ...DEFAULT_MANIFEST_FILTERS, source: "fleet" }).map((row) => row.name)).toEqual([
      "docs",
    ]);
    expect(filterManifestRows(rows, { ...DEFAULT_MANIFEST_FILTERS, query: "claude http" }).map((row) => row.name)).toEqual([
      "docs",
    ]);
  });

  it("classifies missing and malformed last-seen timestamps as unknown", () => {
    expect(classifyFreshness("", now)).toBe("unknown");
    expect(classifyFreshness("not-a-date", now)).toBe("unknown");
  });
});

it("does not infer severity from credential names or missing assessment", () => {
 const rows=deriveManifestRows({...manifest,mcp_servers:[{id:"read-only",credential_refs:[{name:"READ_ONLY_API_TOKEN"}],observed:{configured_locally:true},security:{warnings:[]}}]});
 expect(rows[0]?.reviewStatus).toBe("not assessed");
 expect(rows[0]?.reviewIndicators).toContain("1 credential reference");
 expect(rows[0]?.toolCount).toBeNull();
 });
 it("preserves explicit security block evidence as a review indicator", () => {
 const rows=deriveManifestRows({...manifest,mcp_servers:[{id:"blocked",security:{blocked:true},observed:{}}]});
 expect(rows[0]?.reviewStatus).toBe("review needed");
 expect(rows[0]?.reviewIndicators).toContain("Security block reported");
 });

it("does not assign ambiguous client names to another environment", () => {
 const agents=[{id:"prod",name:"assistant",owner:"prod-team",environment:"prod"},{id:"dev",name:"assistant",owner:"dev-team",environment:"dev"}];
 for (const ordered of [agents,[...agents].reverse()]) {
  const row=deriveManifestRows({...manifest,agents:ordered,mcp_servers:[{id:"s",agent_name:"assistant"}]})[0];
  expect(row?.environment).toBe("unknown");
  expect(row?.owner).toBe("unknown");
  const unmatched=deriveManifestRows({...manifest,agents:ordered,mcp_servers:[{id:"s",agent_name:"prod"}]})[0];
  expect(unmatched?.environment).toBe("unknown");
 }
});

it("prefers explicit server membership and leaves shared ownership unresolved", () => {
  const agents = [
    { id: "prod", name: "assistant", owner: "prod-team", environment: "prod", mcp_server_ids: ["s"] },
    { id: "dev", name: "assistant", owner: "dev-team", environment: "dev" },
  ];
  expect(deriveManifestRows({ ...manifest, agents, mcp_servers: [{ id: "s", agent_name: "dev" }] })[0]?.environment).toBe("prod");
  const shared = agents.map((agent) => ({ ...agent, mcp_server_ids: ["s"] }));
  expect(deriveManifestRows({ ...manifest, agents: shared, mcp_servers: [{ id: "s", agent_name: "prod" }] })[0]?.environment).toBe("unknown");
});

it("does not interpret an observation client name as another agent ID", () => {
  const agents = [
    { id: "assistant", name: "different-client", owner: "prod-team", environment: "prod" },
    { id: "dev-client", name: "assistant", owner: "dev-team", environment: "dev" },
  ];
  for (const ordered of [agents, [...agents].reverse()]) {
    const row = deriveManifestRows({ ...manifest, agents: ordered, mcp_servers: [{ id: "s", agent_name: "assistant" }] })[0];
    expect(row?.owner).toBe("dev-team");
    expect(row?.environment).toBe("dev");
  }
});

it("does not resolve a missing client name using its display placeholder", () => {
  const agents = [{ id: "prod", name: "local discovery", owner: "prod-team", environment: "prod" }];
  const row = deriveManifestRows({ ...manifest, agents, mcp_servers: [{ id: "s" }] })[0];
  expect(row?.agentName).toBe("local discovery");
  expect(row?.owner).toBe("unknown");
  expect(row?.environment).toBe("unknown");
});

it("keeps every reported shared-server agent visible without assigning one owner", () => {
  const shared: AgentBomManifestResponse = {
    ...manifest,
    agents: [{ id: "alpha-id", name: "alpha", owner: "team-a", environment: "prod" }, { id: "beta-id", name: "beta", owner: "team-b", environment: "dev" }],
    mcp_servers: [{ id: "shared", name: "shared-server", agent_name: "", agent_names: ["alpha", "beta"], observation_ids: ["a", "b"] }],
  };
  const rows = deriveManifestRows(shared);
  expect(rows).toHaveLength(1);
  expect(rows[0]?.agentName).toBe("alpha, beta");
  expect(rows[0]?.owner).toBe("unknown");
  expect(rows[0]?.environment).toBe("unknown");
  expect(filterManifestRows(rows, { ...DEFAULT_MANIFEST_FILTERS, query: "beta" })).toHaveLength(1);
});

it("does not recover an observation-scoped conflict through an agent display name", () => {
  const row = deriveManifestRows({ ...manifest,
    agents: [{ id: "agent", name: "assistant", owner: "prod-team", environment: "prod", mcp_server_ids: ["shared"] }],
    mcp_servers: [{ id: "observation:conflict", server_stable_id: "shared", identity_basis: "observation", agent_names: ["assistant"] }],
  })[0];
  expect(row?.agentName).toBe("assistant");
  expect(row?.owner).toBe("unknown");
  expect(row?.environment).toBe("unknown");
});
