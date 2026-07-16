import { describe, expect, it } from "vitest";

import {
  buildExposurePathView,
  buildExecExposurePaths,
  buildTopRiskExposurePath,
} from "@/lib/dashboard-data";
import type { BlastRadius, OverviewTopRisk } from "@/lib/api";

function makeTopRisk(overrides: Partial<OverviewTopRisk> = {}): OverviewTopRisk {
  return {
    vulnerability_id: "CVE-2026-9001",
    package: "requests",
    severity: "critical",
    risk_score: 9.4,
    is_kev: false,
    cvss_score: 9.8,
    epss_score: 0.7,
    affected_agents: ["Ingest Bot"],
    ...overrides,
  };
}

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

describe("buildTopRiskExposurePath", () => {
  it("maps an OverviewTopRisk into a CVE→package→agent chain (#4063)", () => {
    const view = buildTopRiskExposurePath(makeTopRisk(), 0);
    expect(view.riskScore).toBe(9.4);
    expect(view.key).toBe("CVE-2026-9001:requests:0");
    expect(view.nodes).toEqual([
      { type: "cve", label: "CVE-2026-9001", severity: "critical" },
      { type: "package", label: "requests" },
      { type: "agent", label: "Ingest Bot" },
    ]);
  });

  it("drills a CVE-shaped risk to the finding rows for that CVE", () => {
    const view = buildTopRiskExposurePath(makeTopRisk());
    // Must land on real finding rows — not an empty security-graph snapshot for a
    // bulk estate that has no scan (#4063 / avoids the #4059 self-contradiction).
    expect(view.href).toBe("/findings?cve=CVE-2026-9001");
  });

  it("drills a non-CVE id by severity so the target is never empty", () => {
    const view = buildTopRiskExposurePath(
      makeTopRisk({ vulnerability_id: "GHSA-xxxx-yyyy-zzzz", severity: "high" }),
    );
    // A non-CVE id filtered as ?cve= would return 0 rows; fall back to the
    // severity band the finding provably belongs to.
    expect(view.href).toBe("/findings?severity=high");
  });

  it("omits absent package/agent hops and keys without an index", () => {
    const view = buildTopRiskExposurePath(
      makeTopRisk({ package: null, affected_agents: [] }),
    );
    expect(view.key).toBe("CVE-2026-9001:unknown");
    expect(view.nodes).toEqual([
      { type: "cve", label: "CVE-2026-9001", severity: "critical" },
    ]);
  });
});

describe("buildExecExposurePaths", () => {
  it("populates the strip from overview.top_risks for a bulk estate with no scans (#4063)", () => {
    const paths = buildExecExposurePaths(
      [],
      [
        makeTopRisk({ vulnerability_id: "CVE-2026-1000", risk_score: 6.0 }),
        makeTopRisk({ vulnerability_id: "CVE-2026-2000", risk_score: 9.9 }),
      ],
    );
    // Worst-first, and each carries a working finding-row drill (not an empty
    // security-graph snapshot the scan-less estate has no data for).
    expect(paths.map((p) => p.nodes[0]!.label)).toEqual(["CVE-2026-2000", "CVE-2026-1000"]);
    expect(paths[0]!.href).toBe("/findings?cve=CVE-2026-2000");
  });

  it("keeps the scan-derived path (rich hops + scan→graph drill) for a scan estate", () => {
    const paths = buildExecExposurePaths(
      [{ ...makeBlast(), scanId: "scan-xyz" }],
      // The same CVE appears in top_risks (server folds the scan in) — must NOT
      // double-count, and the richer scan row (with scanId graph drill) wins.
      [makeTopRisk({ vulnerability_id: "CVE-2026-0002" })],
    );
    expect(paths).toHaveLength(1);
    expect(paths[0]!.href).toBe(
      "/security-graph?scan=scan-xyz&cve=CVE-2026-0002&package=flask&agent=Claude+Desktop",
    );
  });

  it("merges hub-only risks alongside scan blasts, deduped and ranked", () => {
    const paths = buildExecExposurePaths(
      [{ ...makeBlast({ vulnerability_id: "CVE-2026-0002", risk_score: 5.0 }), scanId: "s1" }],
      [
        makeTopRisk({ vulnerability_id: "CVE-2026-0002", risk_score: 9.9 }), // dup of scan
        makeTopRisk({ vulnerability_id: "CVE-2026-7777", risk_score: 8.0 }), // hub-only
      ],
    );
    const labels = paths.map((p) => p.nodes[0]!.label);
    expect(labels).toContain("CVE-2026-0002");
    expect(labels).toContain("CVE-2026-7777");
    // Deduped: the scan CVE appears exactly once (scan row wins, hub dup dropped).
    expect(labels.filter((l) => l === "CVE-2026-0002")).toHaveLength(1);
    // Hub-only risk drills to real finding rows.
    const hub = paths.find((p) => p.nodes[0]!.label === "CVE-2026-7777");
    expect(hub!.href).toBe("/findings?cve=CVE-2026-7777");
  });

  it("returns an empty strip when there are genuinely no risks", () => {
    expect(buildExecExposurePaths([], [])).toEqual([]);
    expect(buildExecExposurePaths([], null)).toEqual([]);
  });
});
