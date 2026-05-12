import { describe, expect, it } from "vitest";

import { compareExposurePaths, pathDisplayTitle, pathFixLabel, type ExposurePath } from "@/lib/exposure-path";

function path(overrides: Partial<ExposurePath>): ExposurePath {
  return {
    id: "path-1",
    label: "Agent -> package -> CVE",
    riskScore: 8,
    severity: "high",
    source: { id: "agent-1", label: "analyst-agent", role: "agent" },
    target: { id: "cve-1", label: "CVE-2026-0001", role: "finding" },
    hops: [
      { id: "agent-1", label: "analyst-agent", role: "agent" },
      { id: "pkg-1", label: "werkzeug@2.2.2", role: "package" },
      { id: "cve-1", label: "CVE-2026-0001", role: "finding" },
    ],
    relationships: [],
    nodeIds: ["agent-1", "pkg-1", "cve-1"],
    edgeIds: [],
    findings: ["CVE-2026-0001"],
    affectedAgents: ["analyst-agent"],
    affectedServers: ["database"],
    reachableTools: ["execute_sql"],
    exposedCredentials: [],
    dependencyContext: {
      packageName: "werkzeug",
      packageVersion: "2.2.2",
      ecosystem: "pypi",
      serverName: "database",
    },
    ...overrides,
  };
}

describe("ExposurePath", () => {
  it("renders a security-first display title from shared path fields", () => {
    expect(pathDisplayTitle(path({}))).toBe("analyst-agent -> werkzeug@2.2.2 -> CVE-2026-0001");
  });

  it("prefers fix versions for compact remediation labels", () => {
    expect(pathFixLabel(path({ fix: { label: "Upgrade werkzeug", version: "2.2.3" } }))).toBe("2.2.3");
    expect(pathFixLabel(path({ fix: { label: "Rotate credential" } }))).toBe("Rotate credential");
  });

  it("ranks by risk, then severity, then KEV, then affected agents", () => {
    const criticalKev = path({ id: "critical-kev", riskScore: 9, severity: "critical", evidence: { isKev: true } });
    const highWide = path({
      id: "high-wide",
      riskScore: 9,
      severity: "high",
      affectedAgents: ["analyst-agent", "cursor"],
    });
    const medium = path({ id: "medium", riskScore: 7, severity: "medium" });

    expect([medium, highWide, criticalKev].sort(compareExposurePaths).map((item) => item.id)).toEqual([
      "critical-kev",
      "high-wide",
      "medium",
    ]);
  });
});
