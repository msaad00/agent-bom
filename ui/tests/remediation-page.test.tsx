import { render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import RemediationPage from "@/app/remediation/page";

const { apiMock, navigationState } = vi.hoisted(() => ({
  apiMock: {
    listJobs: vi.fn(),
    getRemediation: vi.fn(),
    getCorrelationRemediation: vi.fn(),
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
    // Keep the collapsed campaign workflow in an honest empty state so the
    // test isolates the package-plan density caption.
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

  it("loads remediation for an explicit scan handoff instead of the latest job", async () => {
    navigationState.query = "scan=scan-from-results&q=CVE-2026-openssl";
    apiMock.getRemediation.mockResolvedValue([
      remediationItem("openssl", "critical"),
      remediationItem("requests", "high"),
    ]);

    render(<RemediationPage />);

    await waitFor(() => expect(apiMock.getRemediation).toHaveBeenCalledWith("scan-from-results"));
    expect(apiMock.listJobs).not.toHaveBeenCalled();
    expect(screen.getByText("openssl", { exact: true })).toBeInTheDocument();
    expect(screen.queryByText("requests", { exact: true })).not.toBeInTheDocument();
  });

  it("preserves an exact correlation path decision and returns to its snapshot", async () => {
    const pathIdentity = "service:a::data:b::service:a->package:pillow->vulnerability:cve->data:b";
    navigationState.query = new URLSearchParams({
      correlation: "corr-1",
      scan: "corr-1",
      cve: "CVE-2023-4863",
      path: pathIdentity,
    }).toString();
    apiMock.getCorrelationRemediation.mockResolvedValue({
      schema_version: "agent-bom.graph-correlation-remediation/v1",
      correlation_id: "corr-1",
      snapshot_id: "corr-1",
      correlation_manifest_sha256: `sha256:${"a".repeat(64)}`,
      count: 1,
      remediation_decisions: [
        {
          decision_id: "remediation:abc",
          schema_version: "agent-bom.graph-correlation-remediation/v1",
          status: "recommended",
          correlation_id: "corr-1",
          snapshot_id: "corr-1",
          correlation_manifest_sha256: `sha256:${"a".repeat(64)}`,
          finding: { finding_id: "finding-1", advisory_id: "CVE-2023-4863", severity: "high", is_kev: true },
          package: { node_id: "package:pillow", name: "pillow", ecosystem: "pypi", purl: "pkg:pypi/pillow@9.0.0", current_version: "9.0.0" },
          container: { node_id: "container:image", image_digest: `sha256:${"b".repeat(64)}` },
          path: { path_id: "path:abc", identity: pathIdentity, source: "service:a", target: "data:b", hops: ["service:a", "package:pillow", "vulnerability:cve", "data:b"], relationships: ["uses", "vulnerable_to", "has_permission"], risk_score: 58 },
          ownership: { owner: null, status: "unassigned" },
          sla: { due_at: "2023-10-04T00:00:00+00:00", status: "overdue", policy: "cisa_kev_or_severity" },
          recommendation: { action: "upgrade", fixed_version: "10.0.1", summary: "Upgrade Pillow and rebuild the digest-pinned image.", command: "pip install 'pillow>=10.0.1'", applied: false, requires_human_review: true },
          verification: { command: "agent-bom scan . --offline", expected: "The advisory and predecessor path are absent.", status: "not_run" },
          reverification: { rescan_status: "not_run", recorrelation_status: "not_run", predecessor_snapshot_id: "corr-1" },
          evidence_scope: { name: "reference_evidence_lab", infrastructure: "modeled_local", customer_evidence: false, live_cloud: false },
        },
      ],
    });

    render(<RemediationPage />);

    await waitFor(() => expect(apiMock.getCorrelationRemediation).toHaveBeenCalledWith("corr-1"));
    expect(apiMock.getRemediation).not.toHaveBeenCalled();
    expect(screen.getByText("Correlation remediation decision")).toBeInTheDocument();
    expect(screen.getByText("Unassigned")).toBeInTheDocument();
    expect(screen.getByText("Re-scan not run · Re-correlation not run")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Return to exact attack path" })).toHaveAttribute(
      "href",
      expect.stringContaining("scan=corr-1"),
    );
    expect(screen.getByRole("link", { name: "Return to exact attack path" })).toHaveAttribute(
      "href",
      expect.stringContaining(`path=${encodeURIComponent(pathIdentity)}`),
    );
  });

  it("singularizes the caption for a single matching package", async () => {
    apiMock.getRemediation.mockResolvedValue([remediationItem("openssl", "critical")]);

    render(<RemediationPage />);

    await waitFor(() => {
      expect(screen.getByText(/1 matching package(?!s)/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/1 on this page/i)).toBeInTheDocument();
  });

  it("leads with fixable packages and collapses campaign workflow detail", async () => {
    apiMock.getRemediation.mockResolvedValue([remediationItem("openssl", "critical")]);

    render(<RemediationPage />);

    const plan = await screen.findByRole("heading", { name: "Package remediation plan" });
    const workflow = screen.getByText("Campaign workflow and verification", { exact: true });
    const disclosure = workflow.closest("details");

    expect(disclosure).not.toHaveAttribute("open");
    expect(plan.compareDocumentPosition(workflow) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
});
