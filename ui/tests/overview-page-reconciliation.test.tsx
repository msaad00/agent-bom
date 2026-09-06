import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import Dashboard from "@/app/page";
import type { OverviewResponse } from "@/lib/api";

const { apiMock, deploymentCounts } = vi.hoisted(() => ({
  apiMock: {
    getPosture: vi.fn(),
    getOverview: vi.fn(),
    getTrends: vi.fn(),
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

function overviewFixture(): OverviewResponse {
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
    Object.assign(deploymentCounts, { critical: 7, high: 11, medium: 13, low: 17, unrated: 19, total: 67, kev: 5 });
    apiMock.getPosture.mockResolvedValue({ grade: "D", score: 49 });
    apiMock.getOverview.mockResolvedValue(overviewFixture());
    apiMock.getTrends.mockResolvedValue({ tenant_id: "tenant-ui", count: 0, points: [] });
    apiMock.getCompliance.mockRejectedValue(new Error("not configured"));
    apiMock.listAgents.mockResolvedValue({ count: 4, agents: [] });
    apiMock.updateScoreConfig.mockResolvedValue({});
    apiMock.listJobs.mockResolvedValue({
      jobs: Array.from({ length: 12 }, (_, index) => ({
        job_id: `scan-${index}-abcdefgh`,
        status: "done",
        created_at: `2026-07-17T${String(23 - index).padStart(2, "0")}:00:00Z`,
        request: index === 0 ? { repo_url: "https://github.com/acme/payments" } : {},
      })),
    });
    apiMock.getScan.mockImplementation(async (jobId: string) => staleScan(jobId));
  });

  afterEach(() => vi.useRealTimers());

  it("restores recent-scan metadata from bounded hydrated details after a cold API start", async () => {
    apiMock.listJobs.mockResolvedValue({ jobs: [{ job_id: "cold-sbom", status: "done", created_at: "2026-09-06T22:26:37Z" }] });
    apiMock.getScan.mockResolvedValue({
      job_id: "cold-sbom", status: "done", created_at: "2026-09-06T22:26:37Z",
      request: { sbom: "<path:reference.cdx.json>" }, progress: [],
      result: { agents: [], blast_radius: [], summary: { total_vulnerabilities: 22, critical_findings: 4 } },
    });
    render(<Dashboard />);
    const row = await screen.findByRole("link", { name: /SBOM scan.*22 vulns/i });
    expect(row).toHaveTextContent("4 CRIT");
    expect(row).not.toHaveTextContent("Metrics unavailable");
    expect(row).not.toHaveTextContent("agents");
    expect(apiMock.getScan).toHaveBeenCalledTimes(1);
    expect(apiMock.getScan).toHaveBeenCalledWith("cold-sbom");
    expect(apiMock.listJobs).toHaveBeenCalledTimes(1);
  });

  it("does not invent an agents source when recent-scan details are unavailable", async () => {
    apiMock.listJobs.mockResolvedValue({ jobs: [{ job_id: "unknown-scan", status: "done", created_at: "2026-09-06T22:26:37Z" }] });
    apiMock.getScan.mockRejectedValue(new Error("unavailable"));
    render(<Dashboard />);
    const row = await screen.findByRole("link", { name: /Completed scan.*Metrics unavailable/i });
    expect(row).not.toHaveTextContent("agents");
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

  it("passes the canonical scan floor into the score explanation", async () => {
    const overview = overviewFixture();
    apiMock.getOverview.mockResolvedValue({ ...overview, posture: {
      ...overview.posture, score: 37, grade: "F", floored: true, penalty_total: 60.7,
      breakdown: [{ driver: "high", label: "High findings", count: 103, weight: 2, contribution: 206 }],
    } });
    render(<Dashboard />);
    const explanation = await screen.findByRole("button", { name: /What influences this score/ });
    fireEvent.click(explanation);
    expect(screen.getByText("Total weighted pressure: 206.0")).toBeVisible();
    expect(screen.getByText(/worse recorded scan posture/)).toBeVisible();
    expect(screen.getByText("37%")).toBeVisible();
    expect(screen.queryByText(/60.7/)).not.toBeInTheDocument();
  });

  it("labels recent scans by their target and retains the exact job id", async () => {
    render(<Dashboard />);

    const scanLink = await screen.findByRole("link", { name: /Repository scan/i });
    expect(scanLink).toHaveAttribute("href", "/scan?id=scan-0-abcdefgh");
    expect(scanLink).toHaveAttribute("title", "Scan scan-0-abcdefgh");
  });


  it("keeps overview counts stable when deployment counts update independently", async () => {
    apiMock.getOverview.mockResolvedValue({ ...overviewFixture(), finding_counts: { ...deploymentCounts, critical: 3, kev: 2 } });
    const view = render(<Dashboard />);
    await screen.findByRole("link", { name: /^Critical 3/i });
    deploymentCounts.critical = 0;
    deploymentCounts.kev = 0;
    view.rerender(<Dashboard />);
    expect(screen.getByRole("link", { name: /^Critical 3/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /KEV 2/i })).toBeInTheDocument();
  });

  it("refreshes score, counts and risks together without overlapping requests", async () => {
    vi.useFakeTimers();
    const initial = { ...overviewFixture(), finding_counts: { ...deploymentCounts, critical: 3 }, top_risks: [{
      vulnerability_id: "CVE-2025-1234", package: "canonical-package", severity: "critical", risk_score: 9,
      is_kev: true, cvss_score: 9, epss_score: null, affected_agents: [],
    }] };
    apiMock.getOverview.mockResolvedValueOnce(initial);
    let resolveRefresh!: (value: typeof initial) => void;
    apiMock.getOverview.mockImplementationOnce(() => new Promise((resolve) => { resolveRefresh = resolve; }));
    const view = render(<Dashboard />);
    await act(async () => {});
    expect(screen.getByRole("link", { name: /^Critical 3/i })).toBeInTheDocument();
    expect(screen.getAllByText(/CVE-2025-1234/).length).toBeGreaterThan(0);
    const initialCalls = apiMock.getOverview.mock.calls.length;
    await act(async () => { vi.advanceTimersByTime(60_000); });
    expect(screen.getByText("Refreshing overview…")).toHaveAttribute("role", "status");
    await act(async () => { vi.advanceTimersByTime(120_000); });
    expect(apiMock.getOverview).toHaveBeenCalledTimes(initialCalls + 1);
    await act(async () => resolveRefresh({
      ...initial,
      posture: { ...initial.posture, grade: "A", score: 100 },
      headline: { ...initial.headline, scans: 0, latest_scan_at: null },
      finding_counts: { ...initial.finding_counts, critical: 0, high: 0, medium: 0, low: 0, unrated: 0, total: 0, kev: 0 },
      top_risks: [],
    }));
    expect(screen.getByRole("link", { name: /^Critical 0/i })).toBeInTheDocument();
    expect(screen.getByText("100%")).toBeVisible();
    expect(screen.getByText("Run a scan to establish freshness.")).toBeVisible();
    expect(screen.queryByText(/scan-0-abcdefgh-stale/)).not.toBeInTheDocument();
    expect(screen.queryByText(/CVE-2025-1234/)).not.toBeInTheDocument();
    view.unmount();
    await act(async () => { vi.advanceTimersByTime(120_000); });
    expect(apiMock.getOverview).toHaveBeenCalledTimes(initialCalls + 1);
  });

  it("updates nonzero counts, KEV and score from the next overview snapshot", async () => {
    vi.useFakeTimers();
    const initial = { ...overviewFixture(), finding_counts: { ...deploymentCounts } };
    apiMock.getOverview.mockResolvedValueOnce(initial).mockResolvedValueOnce({
      ...initial,
      posture: { ...initial.posture, score: 75, grade: "C" },
      finding_counts: { critical: 2, high: 3, medium: 4, low: 1, unrated: 0, total: 10, kev: 1 },
    });
    render(<Dashboard />);
    await act(async () => {});
    expect(screen.getByRole("link", { name: /^Critical 7/i })).toBeInTheDocument();
    await act(async () => { vi.advanceTimersByTime(60_000); });
    expect(screen.getByRole("link", { name: /^Critical 2/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /^High 3/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /KEV 1/i })).toBeInTheDocument();
    expect(screen.getByText("75%")).toBeVisible();
  });

  it("does not substitute an older posture score when the current score is null", async () => {
    const snapshot = overviewFixture();
    apiMock.getOverview.mockResolvedValue({ ...snapshot, finding_counts: { ...deploymentCounts },
      posture: { ...snapshot.posture, score: null },
    });
    render(<Dashboard />);
    await screen.findByRole("link", { name: /^Critical 7/i });
    expect(screen.queryByText("49%")).not.toBeInTheDocument();
  });

  it("retains the last coherent snapshot and discloses an unavailable refresh", async () => {
    vi.useFakeTimers();
    apiMock.getOverview.mockResolvedValueOnce({ ...overviewFixture(), finding_counts: { ...deploymentCounts, critical: 3 } })
      .mockRejectedValueOnce(new Error("private upstream details"));
    render(<Dashboard />);
    await act(async () => {});
    await act(async () => { vi.advanceTimersByTime(60_000); });
    expect(screen.getByText("Overview refresh unavailable. Showing the last loaded snapshot.")).toHaveAttribute("role", "status");
    expect(screen.getByRole("link", { name: /^Critical 3/i })).toBeInTheDocument();
    expect(screen.queryByText("private upstream details")).not.toBeInTheDocument();
  });
});
