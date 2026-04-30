import { describe, expect, it } from "vitest";

import type { ScanResult } from "@/lib/api";
import { buildMeshGraph, getMeshAgentKey } from "@/lib/mesh-graph";

const baseResult: ScanResult = {
  agents: [
    {
      name: "claude-desktop",
      agent_type: "desktop",
      mcp_servers: [
        {
          name: "filesystem",
          packages: [
            {
              name: "server-filesystem",
              version: "1.0.0",
              ecosystem: "npm",
              vulnerabilities: [{ id: "CVE-2026-0001", severity: "critical" }],
            },
          ],
          tools: [{ name: "read_file", description: "Read a file" }],
        },
      ],
    },
    {
      name: "cursor",
      agent_type: "desktop",
      mcp_servers: [
        {
          name: "filesystem",
          packages: [
            {
              name: "server-filesystem",
              version: "1.0.0",
              ecosystem: "npm",
              vulnerabilities: [{ id: "CVE-2026-0001", severity: "critical" }],
            },
          ],
          tools: [{ name: "read_file", description: "Read a file" }],
        },
      ],
    },
    {
      name: "zed",
      agent_type: "desktop",
      mcp_servers: [
        {
          name: "notes",
          packages: [
            {
              name: "notes-server",
              version: "1.0.0",
              ecosystem: "npm",
              vulnerabilities: [],
            },
          ],
          tools: [{ name: "list_notes", description: "List notes" }],
        },
      ],
    },
  ],
  blast_radius: [
    {
      vulnerability_id: "CVE-2026-0001",
      severity: "critical",
      package: "server-filesystem",
      affected_agents: ["claude-desktop", "cursor"],
      affected_servers: ["filesystem"],
      exposed_credentials: [],
      exposed_tools: ["read_file"],
      reachable_tools: ["read_file"],
      blast_score: 9,
    },
  ],
};

describe("buildMeshGraph", () => {
  it("keeps shared topology visible when vulnerable-only mode is enabled", () => {
    const { nodes, edges, stats } = buildMeshGraph(
      baseResult,
      { packages: true, vulnerabilities: true, credentials: true, tools: true },
      "high",
      { vulnerableOnly: true },
    );

    expect(stats.totalAgents).toBe(2);
    expect(nodes.filter((node) => node.id === "agent:cursor")).toHaveLength(1);
    expect(nodes.some((node) => node.id === "agent:claude-desktop")).toBe(true);
    expect(nodes.some((node) => node.id === "agent:cursor")).toBe(true);
    expect(nodes.some((node) => node.id === "agent:zed")).toBe(false);
    expect(edges.some((edge) => edge.id === "agent:claude-desktop->server:filesystem")).toBe(true);
    expect(edges.some((edge) => edge.id === "agent:cursor->server:filesystem")).toBe(true);
  });

  it("respects selected agent scope without dropping the shared server edge", () => {
    const { nodes, edges } = buildMeshGraph(
      baseResult,
      { packages: true, vulnerabilities: true, credentials: true, tools: true },
      "high",
      { vulnerableOnly: true, selectedAgents: ["cursor"] },
    );

    expect(nodes.some((node) => node.id === "agent:cursor")).toBe(true);
    expect(nodes.some((node) => node.id === "server:filesystem")).toBe(true);
    expect(edges.some((edge) => edge.id === "agent:cursor->server:filesystem")).toBe(true);
  });

  it("keeps same-named agents separate across fleet endpoints", () => {
    const fleetResult: ScanResult = {
      agents: [
        {
          name: "claude-desktop",
          agent_type: "desktop",
          source_id: "device-a",
          enrollment_name: "alice-mac",
          mcp_servers: [
            {
              name: "filesystem",
              packages: [
                {
                  name: "server-filesystem",
                  version: "1.0.0",
                  ecosystem: "npm",
                  vulnerabilities: [{ id: "CVE-2026-0001", severity: "critical" }],
                },
              ],
              tools: [],
            },
          ],
        },
        {
          name: "claude-desktop",
          agent_type: "desktop",
          source_id: "device-b",
          enrollment_name: "bob-mac",
          mcp_servers: [
            {
              name: "filesystem",
              packages: [
                {
                  name: "server-filesystem",
                  version: "1.0.0",
                  ecosystem: "npm",
                  vulnerabilities: [{ id: "CVE-2026-0001", severity: "critical" }],
                },
              ],
              tools: [],
            },
          ],
        },
      ],
      blast_radius: [],
    };

    const { nodes, edges } = buildMeshGraph(fleetResult, undefined, "high");

    expect(getMeshAgentKey(fleetResult.agents[0]!)).toBe("claude-desktop@device-a");
    expect(nodes.some((node) => node.id === "agent:claude-desktop@device-a")).toBe(true);
    expect(nodes.some((node) => node.id === "agent:claude-desktop@device-b")).toBe(true);
    expect(nodes.filter((node) => node.data.label === "claude-desktop · alice-mac")).toHaveLength(1);
    expect(edges.some((edge) => edge.id === "agent:claude-desktop@device-a->server:filesystem")).toBe(true);
    expect(edges.some((edge) => edge.id === "agent:claude-desktop@device-b->server:filesystem")).toBe(true);
  });
});
