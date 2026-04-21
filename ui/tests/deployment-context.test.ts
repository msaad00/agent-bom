import { describe, expect, it } from "vitest";

import {
  deploymentModeLabel,
  getDeploymentSurfaceState,
  hasDeploymentSignals,
  isDeploymentSurfaceAvailable,
  isNavLinkVisible,
} from "@/lib/deployment-context";
import type { PostureCountsResponse } from "@/lib/api";

function makeCounts(overrides: Partial<PostureCountsResponse> = {}): PostureCountsResponse {
  return {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
    kev: 0,
    compound_issues: 0,
    deployment_mode: "local",
    has_mcp_context: false,
    has_agent_context: false,
    has_local_scan: false,
    has_fleet_ingest: false,
    has_cluster_scan: false,
    has_ci_cd_scan: false,
    has_mesh: false,
    has_gateway: false,
    has_proxy: false,
    has_traces: false,
    has_registry: false,
    scan_sources: [],
    scan_count: 0,
    ...overrides,
  };
}

describe("deployment-context helpers", () => {
  it("formats deployment mode labels", () => {
    expect(deploymentModeLabel("local")).toBe("Local");
    expect(deploymentModeLabel("fleet")).toBe("Fleet");
    expect(deploymentModeLabel("cluster")).toBe("Cluster");
    expect(deploymentModeLabel("hybrid")).toBe("Hybrid");
  });

  it("detects when deployment signals exist", () => {
    expect(hasDeploymentSignals(makeCounts())).toBe(false);
    expect(hasDeploymentSignals(makeCounts({ has_fleet_ingest: true }))).toBe(true);
  });

  it("gates local-only surfaces away from fleet-only deployments", () => {
    const counts = makeCounts({
      deployment_mode: "fleet",
      has_fleet_ingest: true,
      scan_count: 1,
    });
    expect(isDeploymentSurfaceAvailable("agents", counts)).toBe(false);
    expect(isNavLinkVisible("/agents", counts)).toBe(false);
    expect(isNavLinkVisible("/fleet", counts)).toBe(true);
  });

  it("keeps runtime surfaces visible for hybrid deployments", () => {
    const counts = makeCounts({
      deployment_mode: "hybrid",
      has_local_scan: true,
      has_fleet_ingest: true,
      has_cluster_scan: true,
      has_gateway: true,
      has_proxy: true,
      has_traces: true,
      scan_count: 3,
    });
    expect(isNavLinkVisible("/gateway", counts)).toBe(true);
    expect(isNavLinkVisible("/proxy", counts)).toBe(true);
    expect(isNavLinkVisible("/audit", counts)).toBe(true);
  });

  it("builds deployment-aware state copy", () => {
    const state = getDeploymentSurfaceState(
      "agents",
      makeCounts({ deployment_mode: "cluster" }),
      "No local agent evidence found",
    );
    expect(state.title).toContain("Agents");
    expect(state.summary).toContain("Cluster");
    expect(state.detail).toBe("No local agent evidence found");
    expect(state.capabilities.length).toBeGreaterThan(0);
  });
});
