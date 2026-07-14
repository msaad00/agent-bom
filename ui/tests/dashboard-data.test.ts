import { describe, expect, it } from "vitest";

import { buildExposurePathView } from "@/lib/dashboard-data";
import type { BlastRadius } from "@/lib/api";

function makeBlast(overrides: Partial<BlastRadius> = {}): BlastRadius {
  return {
    vulnerability_id: "CVE-2026-0002",
    severity: "Critical",
    package: "flask",
    affected_agents: ["Claude Desktop"],
    affected_servers: ["mcp-fs"],
    exposed_credentials: ["GITHUB_TOKEN"],
    reachable_tools: ["read_file"],
    blast_score: 82,
    risk_score: 9.1,
    ...overrides,
  };
}

describe("buildExposurePathView", () => {
  it("threads the finding's scanId into the exec→graph drill href (#3966)", () => {
    const view = buildExposurePathView(makeBlast(), "scan-abc123");
    // The drill must target the finding's own scan, not the latest snapshot.
    expect(view.href).toBe(
      "/security-graph?scan=scan-abc123&cve=CVE-2026-0002&package=flask&agent=Claude+Desktop",
    );
  });

  it("omits the scan param only when no scanId is known", () => {
    const view = buildExposurePathView(makeBlast(), undefined);
    expect(view.href).toBe(
      "/security-graph?cve=CVE-2026-0002&package=flask&agent=Claude+Desktop",
    );
    expect(view.href).not.toContain("scan=");
  });

  it("builds the node chain and key, appending an index when provided", () => {
    const view = buildExposurePathView(makeBlast(), "scan-1", 3);
    expect(view.key).toBe("CVE-2026-0002:flask:3");
    expect(view.riskScore).toBe(9.1);
    expect(view.nodes).toEqual([
      { type: "cve", label: "CVE-2026-0002", severity: "critical" },
      { type: "package", label: "flask" },
      { type: "server", label: "mcp-fs" },
      { type: "agent", label: "Claude Desktop" },
      { type: "credential", label: "GITHUB_TOKEN" },
    ]);
  });

  it("uses an index-less key for a single row", () => {
    const view = buildExposurePathView(makeBlast({ package: undefined }), "scan-1");
    expect(view.key).toBe("CVE-2026-0002:unknown");
    // Package hop dropped when absent; scan still threaded.
    expect(view.href).toBe(
      "/security-graph?scan=scan-1&cve=CVE-2026-0002&agent=Claude+Desktop",
    );
  });
});
