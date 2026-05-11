import { describe, expect, it } from "vitest";
import type { Agent, BlastRadius, ScanResult } from "@/lib/api";
import { blastPriority, buildBlastRadiusSummary, buildDerivedBlastRadius, buildEpssVsCvss, buildPipelineStats, effectiveBlastRadius } from "@/lib/insights-risk";

const agents = [
  {
    name: "desktop-agent",
    mcp_servers: [
      {
        name: "filesystem",
        packages: [
          {
            name: "pillow",
            version: "9.0.0",
            ecosystem: "pypi",
            vulnerabilities: [
              {
                id: "CVE-2022-0001",
                severity: "critical",
                cvss_score: 9.8,
                epss_score: 0.42,
                fixed_version: "9.0.1",
              },
            ],
          },
        ],
      },
    ],
  },
] as unknown as Agent[];

describe("insights risk helpers", () => {
  it("derives blast-radius rows from vulnerable packages when graph analysis is absent", () => {
    const derived = buildDerivedBlastRadius(agents);

    expect(derived).toHaveLength(1);
    expect(derived[0]).toMatchObject({
      vulnerability_id: "CVE-2022-0001",
      severity: "critical",
      package: "pillow",
      affected_agents: ["desktop-agent"],
      affected_servers: ["filesystem"],
    });
    expect(derived[0]!.blast_score).toBeGreaterThan(90);
  });

  it("uses derived rows for pipeline stats when scan blast radius is empty", () => {
    const result = {
      agents,
      blast_radius: [],
    } as unknown as ScanResult;

    expect(effectiveBlastRadius(result)).toHaveLength(1);
    expect(buildPipelineStats(result)).toMatchObject({
      agents: 1,
      servers: 1,
      packages: 1,
      vulnerabilities: 1,
      critical: 1,
    });
  });

  it("uses risk_score before blast_score so nonzero risk does not render as an empty chart", () => {
    const blast = {
      vulnerability_id: "CVE-2022-0002",
      severity: "high",
      affected_agents: ["desktop-agent"],
      exposed_credentials: [],
      reachable_tools: [],
      risk_score: 8.5,
      blast_score: 0,
    } as BlastRadius;

    expect(blastPriority(blast)).toBe(85);
    expect(buildEpssVsCvss([{ ...blast, cvss_score: 8.1, epss_score: 0.2 }])[0]!.blast).toBe(85);
  });

  it("groups blast radius summary by package so charts do not repeat one package per CVE", () => {
    const rows = [
      {
        vulnerability_id: "CVE-2022-0001",
        package: "pillow",
        severity: "critical",
        affected_agents: ["desktop-agent"],
        affected_servers: ["filesystem"],
        exposed_credentials: [],
        reachable_tools: [],
        risk_score: 10,
        blast_score: 100,
      },
      {
        vulnerability_id: "CVE-2023-0002",
        package: "pillow",
        severity: "high",
        affected_agents: ["desktop-agent"],
        affected_servers: ["filesystem"],
        exposed_credentials: [],
        reachable_tools: [],
        risk_score: 8,
        blast_score: 80,
      },
    ] as BlastRadius[];

    expect(buildBlastRadiusSummary(rows)).toEqual([
      expect.objectContaining({
        name: "pillow",
        severity: "critical",
        vulnerability_count: 2,
        agent_count: 1,
        server_count: 1,
        score: 100,
      }),
    ]);
  });
});
