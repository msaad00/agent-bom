import { describe, expect, it } from "vitest";

import type { Agent } from "@/lib/api";
import {
  agentRiskScore,
  buildTopologyGraph,
  filterTopologyAgents,
  limitTopologyAgents,
  serverHasCredentials,
  topologyAgentDisplayName,
  topologySummary,
} from "@/lib/agent-topology-graph";

function agent(name: string, servers: Agent["mcp_servers"] = []): Agent {
  return {
    name,
    agent_type: "custom",
    mcp_servers: servers,
  };
}

describe("agent-topology-graph", () => {
  it("humanizes agent display names", () => {
    expect(topologyAgentDisplayName(agent("data-pipeline"))).toBe("Data Pipeline");
    expect(
      topologyAgentDisplayName({
        ...agent("cursor"),
        enrollment_name: "Prod Cursor",
      }),
    ).toBe("Prod Cursor");
  });

  it("scores credential and vulnerability edges higher", () => {
    const risky = agent("cursor", [
      {
        name: "shell-runner",
        packages: [{ name: "pyyaml", version: "5.3", ecosystem: "pypi", vulnerabilities: [{ id: "CVE-1", severity: "critical" }] }],
        env: { AWS_ACCESS_KEY_ID: "***" },
      },
    ]);
    const safe = agent("idle", [{ name: "filesystem", packages: [] }]);
    expect(agentRiskScore(risky)).toBeGreaterThan(agentRiskScore(safe));
  });

  it("filters attention signals at every mesh size", () => {
    const agents = [
      agent("a1", [{ name: "s1", packages: [{ name: "pyyaml", version: "5.3", ecosystem: "pypi", vulnerabilities: [{ id: "CVE-1", severity: "critical" }] }] }]),
      agent("a2", [{ name: "s2", packages: [] }]),
      agent("a3", [{ name: "s3", packages: [] }]),
      agent("a4", [{ name: "s4", packages: [] }]),
      agent("a5", [{ name: "s5", packages: [] }]),
      agent("a6", [{ name: "s6", packages: [] }]),
      agent("a7", [{ name: "s7", packages: [] }]),
      agent("a8", [{ name: "s8", packages: [] }]),
      agent("a9", [{ name: "s9", packages: [] }]),
    ];
    const selected = filterTopologyAgents(agents, "attention");
    expect(selected.length).toBeLessThan(agents.length);
    expect(selected.some((entry) => entry.name === "a1")).toBe(true);
  });

  it("builds shared service nodes once", () => {
    const sharedServer = {
      name: "github",
      command: "npx github",
      transport: "stdio",
      packages: [],
    };
    const graph = buildTopologyGraph([
      agent("cursor", [sharedServer]),
      agent("codex-cli", [sharedServer]),
    ]);
    const serverNodes = graph.nodes.filter((node) => node.id.startsWith("srv-"));
    expect(serverNodes).toHaveLength(1);
    expect(serverNodes[0]?.data?.agentCount).toBe(2);
  });

  it("keeps inventory edges readable (not near-invisible)", () => {
    const graph = buildTopologyGraph([
      agent("cursor", [{ name: "filesystem", packages: [] }]),
    ]);
    const inventory = graph.edges[0];
    expect(inventory?.style?.opacity).toBeGreaterThanOrEqual(0.65);
    expect(Number(inventory?.style?.strokeWidth ?? 0)).toBeGreaterThanOrEqual(1.4);
  });

  it("summarizes unique services and shared blast radius", () => {
    const summary = topologySummary([
      agent("cursor", [{ name: "github", packages: [], env: { TOKEN: "x" } }]),
      agent("codex-cli", [{ name: "github", packages: [] }]),
      agent("orphan"),
    ]);
    expect(summary.uniqueServices).toBe(1);
    expect(summary.sharedServers).toBe(1);
    expect(summary.unlinkedAgents).toBe(1);
    expect(summary.credentialedServers).toBe(1);
  });
});


describe("bounded topology scope", () => {
 it("does not classify ordinary configuration environment variables as credentials", () => {
  expect(serverHasCredentials({ name: "docs", packages: [], env: { LOG_LEVEL: "debug", REGION: "local" } })).toBe(false);
  expect(serverHasCredentials({ name: "api", packages: [], env: { API_TOKEN: "[redacted]" } })).toBe(true);
 });
 it("counts grouped services consistently instead of counting repeated memberships", () => {
  const shared: NonNullable<Agent["mcp_servers"]>[number] = { name: "shared", credential_env_vars: ["API_TOKEN"], packages: [{name:"pkg",version:"1",ecosystem:"npm", vulnerabilities:[{id:"CVE-1",severity:"high"}]}] };
  const summary = topologySummary([agent("one", [shared]), agent("two", [shared])]);
  expect(summary.uniqueServices).toBe(1);
  expect(summary.credentialedServers).toBe(1);
  expect(summary.vulnerableServers).toBe(1);
 });
 it("caps a single oversized agent's services without inventing disconnected agents", () => {
  const result = limitTopologyAgents([agent("large", Array.from({length:300},(_,i)=>({name:`service-${i}`,packages:[]})))]);
  expect(result).toHaveLength(1);
  expect(result[0]?.mcp_servers).toHaveLength(220);
  expect(buildTopologyGraph(result).edges).toHaveLength(220);
 });
 it("retains full inventory separately from attention, including disconnected agents", () => {
  const rows = [agent("one", [{name:"ordinary",packages:[]}]), agent("unlinked")];
  expect(filterTopologyAgents(rows,"attention")).toEqual([]);
  expect(filterTopologyAgents(rows,"all")).toEqual(rows);
  expect(filterTopologyAgents(rows,"unlinked")).toEqual([rows[1]]);
 });
});
