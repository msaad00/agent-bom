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
    expect(rows.map((row) => [row.name, row.source, row.runtimeState, row.riskLevel, row.freshness])).toEqual([
      ["filesystem", "local", "gateway bound", "high", "seen_24h"],
      ["cloud-admin", "runtime", "shadow runtime", "high", "stale"],
      ["docs", "fleet", "inventory only", "low", "unknown"],
    ]);
  });

  it("filters by explicit dimensions instead of only free text", () => {
    const rows = deriveManifestRows(manifest, now);
    const filters: ManifestFilters = {
      ...DEFAULT_MANIFEST_FILTERS,
      owner: "unowned",
      runtime: "shadow runtime",
      freshness: "stale",
      risk: "high",
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
