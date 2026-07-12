import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { OverviewCommandCenter } from "@/components/overview-command-center";
import { api } from "@/lib/api";

const BASE_PROPS = {
  postureGrade: "B",
  postureScore: 82,
  postureSummary: "Strong baseline with room to improve cloud coverage.",
  critical: 2,
  high: 5,
  medium: 3,
  low: 1,
  agents: 8,
  cves: 12,
  scans: 4,
  kev: 1,
  credentials: 0,
  tools: 6,
  packages: 42,
  latestScan: "Jul 8, 1:30 AM",
  mode: "Local",
  summaryReady: true,
  counts: {
    critical: 2,
    high: 5,
    medium: 3,
    low: 1,
    total: 11,
    kev: 1,
    compound_issues: 0,
    deployment_mode: "local" as const,
    has_local_scan: true,
    scan_count: 4,
    scan_sources: ["local", "agents"],
    services: {
      local_agents: { state: "live" as const, count: 8 },
      cloud_accounts: { state: "locked" as const, count: 0 },
    },
  },
  overview: {
    schema_version: "overview.v1",
    tenant_id: "default",
    posture: { grade: "B", score: 82, summary: "Strong baseline" },
    headline: {
      critical: 2,
      high: 5,
      critical_high: 7,
      kev: 1,
      credential_exposed: 0,
      scans: 4,
      latest_scan_at: "2026-07-08T05:30:00Z",
    },
    domains: {
      cloud: {
        label: "Cloud",
        href: "/connections",
        metric: 0,
        metric_label: "accounts",
        status: "idle" as const,
        detail: {},
      },
      vuln: {
        label: "Vuln / SCA",
        href: "/findings?issue=vulnerability",
        metric: 0,
        metric_label: "open CVEs",
        status: "idle" as const,
        detail: {},
      },
      code: {
        label: "Code / repo",
        href: "/scan",
        metric: 0,
        metric_label: "repo scans",
        status: "idle" as const,
        detail: {},
      },
      runtime: {
        label: "Runtime",
        href: "/runtime",
        metric: 0,
        metric_label: "sessions",
        status: "idle" as const,
        detail: {},
      },
      cost: {
        label: "Cost",
        href: "/cost",
        metric: 0,
        metric_label: "spend",
        status: "idle" as const,
        detail: {},
      },
      identity: {
        label: "Identity",
        href: "/identity",
        metric: 0,
        metric_label: "identities",
        status: "idle" as const,
        detail: {},
      },
      ops: {
        label: "Ops",
        href: "/drift",
        metric: 0,
        metric_label: "incidents",
        status: "idle" as const,
        detail: {},
      },
    },
    top_risks: [],
  },
  scanCount: 4,
  latestScanLabel: "Jul 8",
};

describe("OverviewCommandCenter", () => {
  it("renders posture hero, findings breakdown, and environment tabs", async () => {
    vi.spyOn(api, "listCloudConnections").mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "default",
      count: 0,
      connections: [],
    });

    render(<OverviewCommandCenter {...BASE_PROPS} />);

    expect(screen.getByTestId("overview-command-center")).toBeInTheDocument();
    expect(screen.getByText("Findings breakdown")).toBeInTheDocument();
    expect(screen.getByText("Scan coverage")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /View compliance/i })).toHaveAttribute("href", "/compliance");
    expect(screen.getByRole("link", { name: "Deployment" })).toHaveAttribute("href", "/help");
    expect(screen.getByRole("link", { name: "Cloud accounts" })).toHaveAttribute("href", "/connections");
  });

  it("switches to inventory and services tabs", async () => {
    vi.spyOn(api, "listCloudConnections").mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "default",
      count: 0,
      connections: [],
    });
    const user = userEvent.setup();

    render(<OverviewCommandCenter {...BASE_PROPS} />);

    await user.click(screen.getByRole("button", { name: /Inventory/i }));
    expect(screen.getByText("Packages")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Services/i }));
    await waitFor(() => {
      expect(screen.getByText("Local agents")).toBeInTheDocument();
    });
  });
});
