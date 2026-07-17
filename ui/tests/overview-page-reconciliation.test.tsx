import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Dashboard from "@/app/page";

const { apiMock, deploymentCounts } = vi.hoisted(() => ({
  apiMock: {
    getPosture: vi.fn(),
    getOverview: vi.fn(),
    getCompliance: vi.fn(),
    listJobs: vi.fn(),
    listAgents: vi.fn(),
    getScan: vi.fn(),
    updateScoreConfig: vi.fn(),
  },
  deploymentCounts: {
    critical: 7,
    high: 11,
    medium: 13,
    low: 17,
    unrated: 19,
    total: 67,
    kev: 5,
    compound_issues: 2,
    scan_count: 12,
    services: {},
  },
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock };
});

vi.mock("@/hooks/use-deployment-context", () => ({
  useDeploymentContext: () => ({ counts: deploymentCounts, loading: false, error: null }),
}));

vi.mock("@/lib/use-capture-mode", () => ({ useCaptureMode: () => false }));
vi.mock("@/components/activity-feed", () => ({ ActivityFeed: () => <div>Activity fixture</div> }));

function overviewFixture() {
  const domain = (label: string, metric: number, metricLabel: string, href: string) => ({
    label,
    href,
    metric,
    metric_label: metricLabel,
    status: "ok" as const,
    detail: {},
  });
  return {
    schema_version: "overview.v1",
    tenant_id: "tenant-ui",
    posture: { grade: "D", score: 49, summary: "Canonical posture", breakdown: [], display_format: "percent" as const },
    headline: {
      critical: 7,
      high: 11,
      critical_high: 18,
      kev: 5,
      credential_exposed: 3,
      scans: 12,
      latest_scan_at: "2026-07-17T12:00:00Z",
      hub_findings: 67,
    },
    domains: {
      cloud: domain("Cloud posture", 2, "accounts", "/connections"),
      vuln: domain("Vuln / SCA", 23, "open CVEs", "/findings?scope=all&issue=vulnerability"),
      code: domain("Code / repo", 1, "repo scans", "/scan"),
      runtime: domain("Runtime", 1, "surface", "/runtime"),
      cost: domain("LLM Cost", 0, "USD", "/cost"),
      identity: domain("NHI / Identity", 4, "identities", "/identity"),
      ops: domain("Ops", 12, "completed scans", "/jobs"),
    },
    coverage: [],
    top_risks: [],
  };
}

function staleScan(jobId: string) {
  return {
    job_id: jobId,
    status: "done",
    created_at: "2026-07-17T10:00:00Z",
    request: {},
    progress: [],
    result: {
      agents: [],
      blast_radius: [
        {
          vulnerability_id: `${jobId}-stale`,
          severity: "critical",
          affected_agents: [],
          exposed_credentials: [],
          reachable_tools: [],
          risk_score: 9,
        },
      ],
    },
  };
}

describe("Overview canonical finding counts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.getPosture.mockResolvedValue({ grade: "D", score: 49 });
    apiMock.getOverview.mockResolvedValue(overviewFixture());
    apiMock.getCompliance.mockRejectedValue(new Error("not configured"));
    apiMock.listAgents.mockResolvedValue({ count: 4, agents: [] });
    apiMock.updateScoreConfig.mockResolvedValue({});
    apiMock.listJobs.mockResolvedValue({
      jobs: Array.from({ length: 12 }, (_, index) => ({
        job_id: `scan-${index}`,
        status: "done",
        created_at: `2026-07-17T${String(23 - index).padStart(2, "0")}:00:00Z`,
        request: {},
      })),
    });
    apiMock.getScan.mockImplementation(async (jobId: string) => staleScan(jobId));
  });

  it("uses canonical posture/overview counts instead of recomputing the latest ten scans", async () => {
    render(<Dashboard />);

    await waitFor(() => expect(apiMock.getScan).toHaveBeenCalledTimes(10));
    const critical = await screen.findByRole("link", { name: /^Critical 7/i });
    const high = screen.getByRole("link", { name: /^High 11/i });
    expect(critical).toHaveTextContent("7");
    expect(high).toHaveTextContent("11");
    expect(screen.getByText("Current findings · configured window")).toBeInTheDocument();
    expect(critical).toHaveAttribute("href", "/findings?scope=all&severity=critical");
  });
});
