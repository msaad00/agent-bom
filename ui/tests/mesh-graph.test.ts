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
    expect(stats.topExposurePath?.vulnerabilityId).toBe("CVE-2026-0001");
    expect(stats.topExposurePath?.findings).toEqual(["CVE-2026-0001"]);
    expect(stats.topExposurePath?.dependencyContext).toMatchObject({
      packageName: "server-filesystem",
      packageVersion: "1.0.0",
      ecosystem: "npm",
      serverName: "filesystem",
    });
    expect(stats.topExposurePath?.nodeIds).toEqual(
      expect.arrayContaining([
        "agent:claude-desktop",
        "agent:cursor",
        "server:filesystem::",
        "pkg:server:filesystem:::npm:server-filesystem@1.0.0",
        "vuln:server-filesystem:CVE-2026-0001",
      ]),
    );
    expect(stats.topExposurePath?.reachableTools).toEqual(["read_file"]);
    expect(nodes.filter((node) => node.id === "agent:cursor")).toHaveLength(1);
    expect(nodes.some((node) => node.id === "agent:claude-desktop")).toBe(true);
    expect(nodes.some((node) => node.id === "agent:cursor")).toBe(true);
    expect(nodes.some((node) => node.id === "agent:zed")).toBe(false);
    expect(edges.some((edge) => edge.id === "agent:claude-desktop->server:filesystem::")).toBe(true);
    expect(edges.some((edge) => edge.id === "agent:cursor->server:filesystem::")).toBe(true);
  });

  it("ranks the mesh command path by blast score, severity, and blast radius evidence", () => {
    const result: ScanResult = {
      agents: [
        {
          name: "analyst-agent",
          agent_type: "desktop",
          mcp_servers: [
            {
              name: "database",
              packages: [
                {
                  name: "pillow",
                  version: "9.0.0",
                  ecosystem: "pypi",
                  vulnerabilities: [{ id: "CVE-2022-22817", severity: "high", fixed_version: "9.0.1" }],
                },
                {
                  name: "werkzeug",
                  version: "2.2.2",
                  ecosystem: "pypi",
                  vulnerabilities: [{ id: "CVE-2023-25577", severity: "critical", fixed_version: "2.2.3" }],
                },
              ],
              tools: [
                { name: "read_file", description: "Read a file" },
                { name: "execute_sql", description: "Run SQL" },
              ],
              env: {
                DATABASE_URL: "redacted",
              },
            },
          ],
        },
      ],
      blast_radius: [
        {
          vulnerability_id: "CVE-2022-22817",
          severity: "high",
          package: "pillow",
          affected_agents: ["analyst-agent"],
          affected_servers: ["database"],
          exposed_credentials: [],
          reachable_tools: ["read_file"],
          blast_score: 45,
        },
        {
          vulnerability_id: "CVE-2023-25577",
          severity: "critical",
          package: "werkzeug",
          affected_agents: ["analyst-agent"],
          affected_servers: ["database"],
          exposed_credentials: ["DATABASE_URL"],
          reachable_tools: ["execute_sql"],
          blast_score: 96,
          impact_category: "code-execution",
          attack_vector_summary: "Agent can reach database server package and SQL tool.",
        },
      ],
    };

    const { stats } = buildMeshGraph(
      result,
      { packages: true, vulnerabilities: true, credentials: true, tools: true },
      "high",
      { vulnerableOnly: true, maxVulnerabilitiesPerPackage: 1 },
    );

    expect(stats.topExposurePath?.vulnerabilityId).toBe("CVE-2023-25577");
    expect(stats.topExposurePath?.riskScore).toBe(96);
    expect(stats.topExposurePath?.fixedVersion).toBe("2.2.3");
    expect(stats.topExposurePath?.fix).toEqual({
      label: "Upgrade werkzeug",
      version: "2.2.3",
    });
    expect(stats.topExposurePath?.relationships.map((edge) => edge.relationship)).toEqual(
      expect.arrayContaining(["uses", "depends_on", "vulnerable_to", "provides_tool", "exposes_cred"]),
    );
    expect(stats.topExposurePath?.impactCategory).toBe("code-execution");
    expect(stats.topExposurePath?.nodeIds).toEqual(
      expect.arrayContaining([
        "agent:analyst-agent",
        "server:database::",
        "pkg:server:database:::pypi:werkzeug@2.2.2",
        "vuln:werkzeug:CVE-2023-25577",
      ]),
    );
  });

  it("respects selected agent scope without dropping the shared server edge", () => {
    const { nodes, edges } = buildMeshGraph(
      baseResult,
      { packages: true, vulnerabilities: true, credentials: true, tools: true },
      "high",
      { vulnerableOnly: true, selectedAgents: ["cursor"] },
    );

    expect(nodes.some((node) => node.id === "agent:cursor")).toBe(true);
    expect(nodes.some((node) => node.id === "server:filesystem::")).toBe(true);
    expect(edges.some((edge) => edge.id === "agent:cursor->server:filesystem::")).toBe(true);
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
    expect(edges.some((edge) => edge.id === "agent:claude-desktop@device-a->server:filesystem::")).toBe(true);
    expect(edges.some((edge) => edge.id === "agent:claude-desktop@device-b->server:filesystem::")).toBe(true);
  });

  it("does not merge same-named servers with different command identity", () => {
    const result: ScanResult = {
      agents: [
        {
          name: "claude-desktop",
          agent_type: "desktop",
          mcp_servers: [
            {
              name: "filesystem",
              command: "npx @modelcontextprotocol/server-filesystem /tmp/a",
              packages: [],
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
              command: "npx @modelcontextprotocol/server-filesystem /tmp/b",
              packages: [],
              tools: [{ name: "read_file", description: "Read a file" }],
            },
          ],
        },
      ],
      blast_radius: [],
    };

    const { nodes } = buildMeshGraph(result, { packages: true, vulnerabilities: true, credentials: true, tools: true }, "all");

    const serverNodes = nodes.filter((node) => node.data.nodeType === "server" || node.data.nodeType === "sharedServer");
    expect(serverNodes).toHaveLength(2);
    expect(serverNodes.every((node) => node.data.nodeType === "server")).toBe(true);
  });

  it("keeps package versions as distinct visible package nodes", () => {
    const result: ScanResult = {
      agents: [
        {
          name: "claude-desktop",
          agent_type: "desktop",
          mcp_servers: [
            {
              name: "filesystem",
              packages: [
                { name: "server-filesystem", ecosystem: "npm", version: "1.0.0", vulnerabilities: [] },
                { name: "server-filesystem", ecosystem: "npm", version: "2.0.0", vulnerabilities: [] },
              ],
              tools: [],
            },
          ],
        },
      ],
      blast_radius: [],
    };

    const { nodes } = buildMeshGraph(result, { packages: true, vulnerabilities: true, credentials: true, tools: true }, "all");

    const packageLabels = nodes
      .filter((node) => node.data.nodeType === "package")
      .map((node) => node.data.label)
      .sort();
    expect(packageLabels).toEqual(["server-filesystem@1.0.0", "server-filesystem@2.0.0"]);
  });

  it("caps dense findings and reports omitted nodes for readable defaults", () => {
    const result: ScanResult = {
      agents: [
        {
          name: "cursor",
          agent_type: "desktop",
          mcp_servers: [
            {
              name: "dense-server",
              env: {
                OPENAI_API_KEY: "",
                ANTHROPIC_API_KEY: "",
                AWS_SECRET_ACCESS_KEY: "",
                GITHUB_TOKEN: "",
                DATABASE_PASSWORD: "",
              },
              packages: Array.from({ length: 6 }, (_, packageIndex) => ({
                name: `pkg-${packageIndex}`,
                version: "1.0.0",
                ecosystem: "npm",
                vulnerabilities: Array.from({ length: 4 }, (_, vulnIndex) => ({
                  id: `CVE-2026-${packageIndex}${vulnIndex}`,
                  severity: vulnIndex === 0 ? "critical" : "high",
                })),
              })),
              tools: Array.from({ length: 6 }, (_, index) => ({
                name: `tool_${index}`,
                description: `Tool ${index}`,
              })),
            },
          ],
        },
      ],
      blast_radius: [],
    };

    const { nodes, stats } = buildMeshGraph(
      result,
      { packages: true, vulnerabilities: true, credentials: true, tools: true },
      "high",
      { vulnerableOnly: true },
    );

    expect(nodes.filter((node) => node.data.nodeType === "package")).toHaveLength(4);
    expect(nodes.filter((node) => node.data.nodeType === "vulnerability")).toHaveLength(8);
    expect(nodes.filter((node) => node.data.nodeType === "tool")).toHaveLength(3);
    expect(nodes.filter((node) => node.data.nodeType === "credential")).toHaveLength(4);
    expect(stats.omittedPackages).toBe(2);
    expect(stats.omittedVulnerabilities).toBe(8);
    expect(stats.omittedTools).toBe(3);
    expect(stats.omittedCredentials).toBe(1);
    expect(
      nodes
        .filter((node) => node.data.nodeType === "credential")
        .every((node) => String(node.data.serverName).includes("env-var reference")),
    ).toBe(true);
  });
});
