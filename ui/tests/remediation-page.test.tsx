import { render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import RemediationPage from "@/app/remediation/page";

const { apiMock, navigationState } = vi.hoisted(() => ({
  apiMock: {
    listJobs: vi.fn(),
    getRemediation: vi.fn(),
    listTickets: vi.fn(),
    listRiskCampaigns: vi.fn(),
    listRiskCampaignVerificationQueue: vi.fn(),
    listTicketingConnections: vi.fn(),
  },
  navigationState: { query: "" },
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(navigationState.query),
}));

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: ReactNode }) => <a href={href}>{children}</a>,
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: apiMock,
  };
});

function remediationItem(pkg: string, severity: string) {
  return {
    package: pkg,
    current_version: "1.0.0",
    fixed_version: "1.0.1",
    severity,
    vulnerabilities: [`CVE-2026-${pkg}`],
    is_kev: false,
    impact_score: 7.2,
    affected_agents: ["agent-a"],
    exposed_credentials: [],
    owasp_tags: ["LLM01"],
    atlas_tags: [],
    reachable_tools: [],
    risk_narrative: "",
    command: "",
    verify_command: "",
  };
}

describe("RemediationPage", () => {
  beforeEach(() => {
    navigationState.query = "";
    vi.clearAllMocks();
    apiMock.listJobs.mockResolvedValue({
      jobs: [{ job_id: "job-1", status: "done", created_at: "2026-08-12T00:00:00Z" }],
    });
    apiMock.listTickets.mockResolvedValue({ tickets: [] });
    // Command center is rendered above the plan; keep it in an honest empty
    // state so the test isolates the package-plan density caption.
    apiMock.listRiskCampaigns.mockResolvedValue({
      schema_version: "risk-campaigns.v1",
      tenant_id: "tenant-a",
      count: 0,
      finding_window_days: 90,
      finding_limit: 1000,
      truncated: false,
      total_findings: 0,
      total_approximate: false,
      membership_complete: true,
      campaigns: [],
    });
    apiMock.listRiskCampaignVerificationQueue.mockResolvedValue({
      schema_version: "risk-campaign-verification-queue.v1",
      tenant_id: "tenant-a",
      entries: [],
      count: 0,
      has_more: false,
      next_cursor: null,
      limit: 25,
    });
    apiMock.listTicketingConnections.mockResolvedValue({
      schema_version: "ticketing.connections.v1",
      tenant_id: "tenant-a",
      count: 0,
      connections: [],
    });
  });

  it("surfaces a top-of-page page-position caption for the package plan", async () => {
    const items = Array.from({ length: 30 }, (_, i) => remediationItem(`pkg${i}`, i < 5 ? "critical" : "high"));
    apiMock.getRemediation.mockResolvedValue(items);

    render(<RemediationPage />);

    // 30 matching, 25 on the first page, 25 per page.
    await waitFor(() => {
      expect(screen.getByText(/30 matching packages/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/25 on this page/i)).toBeInTheDocument();
    expect(screen.getByText(/25 per page/i)).toBeInTheDocument();
  });

  it("singularizes the caption for a single matching package", async () => {
    apiMock.getRemediation.mockResolvedValue([remediationItem("openssl", "critical")]);

    render(<RemediationPage />);

    await waitFor(() => {
      expect(screen.getByText(/1 matching package(?!s)/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/1 on this page/i)).toBeInTheDocument();
  });
});
