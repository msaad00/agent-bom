import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ScanResultView } from "@/components/scan-result";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getScanStatus: vi.fn(),
    getScan: vi.fn(),
    downloadScanGraph: vi.fn(),
  },
}));

vi.mock("next/link", () => ({
  default: ({
    href,
    children,
    className,
  }: {
    href: string;
    children: React.ReactNode;
    className?: string;
  }) => (
    <a href={href} className={className}>
      {children}
    </a>
  ),
}));

vi.mock("@/lib/use-scan-stream", () => ({
  useScanStream: () => ({
    messages: [],
    pipelineSteps: new Map(),
    streaming: false,
  }),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: apiMock,
  };
});

describe("ScanResultView cloud evidence", () => {
  beforeEach(() => {
    Object.values(apiMock).forEach((mockFn) => mockFn.mockReset());
    apiMock.getScanStatus.mockResolvedValue({
      job_id: "scan-cloud-1",
      status: "done",
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:05:00Z",
      request: {},
    });
    apiMock.getScan.mockResolvedValue({
      job_id: "scan-cloud-1",
      status: "done",
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:05:00Z",
      request: {},
      progress: [],
      result: {
        agents: [],
        blast_radius: [],
        cloud_inventory: {
          provider: "aws",
          resource_count: 42,
          identity_count: 7,
        },
        cis_benchmark: {
          benchmark: "CIS AWS",
          benchmark_version: "1.5",
          passed: 30,
          failed: 10,
          total: 40,
          pass_rate: 0.75,
        },
      },
    });
  });

  it("renders persisted cloud inventory and CIS evidence even without attack-path findings", async () => {
    render(<ScanResultView id="scan-cloud-1" />);

    await waitFor(() => expect(apiMock.getScan).toHaveBeenCalledWith("scan-cloud-1"));

    expect(screen.getByText("Cloud evidence")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Cloud evidence" })).toHaveClass(
      "bg-[color:var(--surface)]",
      "dark:bg-cyan-950/20",
    );
    expect(screen.getByText("AWS")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("AWS CIS")).toBeInTheDocument();
    expect(screen.getByText("30/40 passed · 75%")).toBeInTheDocument();
    expect(
      screen.getByText(/Cloud inventory and posture evidence was persisted/i),
    ).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Continue from this scan" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Findings/i })).toHaveAttribute("href", "/findings?scan=scan-cloud-1");
    expect(screen.getByRole("link", { name: /Investigation/i })).toHaveAttribute(
      "href",
      "/security-graph?scan=scan-cloud-1&investigate=1&lens=attack-path",
    );
    expect(screen.getByText("Open graph evidence; no attack path is asserted")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Remediation/i })).toHaveAttribute("href", "/remediation?scan=scan-cloud-1");
  });

  it("hands a completed automatic correlation to its exact output snapshot", async () => {
    apiMock.getScan.mockResolvedValue({
      job_id: "scan-cloud-1",
      status: "done",
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:05:00Z",
      request: {},
      progress: [],
      result: {
        agents: [],
        blast_radius: [],
        auto_correlation: {
          schema_version: "agent-bom.auto-correlation/v1",
          status: "complete",
          reason: "completed",
          correlation_id: "corr-output",
          output_scan_id: "corr-output",
          input_scan_ids: ["scan-repo", "scan-image"],
          max_age_hours: 168,
          allow_stale: false,
        },
      },
    });

    render(<ScanResultView id="scan-cloud-1" />);

    const investigation = await screen.findByRole("link", { name: /Correlated investigation/i });
    expect(investigation).toHaveAttribute(
      "href",
      "/security-graph?scan=corr-output&correlation=1&investigate=1&lens=attack-path",
    );
    expect(screen.getByText("2 source snapshots automatically correlated")).toBeInTheDocument();
  });

  it("keeps the source graph available and explains a skipped automatic correlation", async () => {
    apiMock.getScan.mockResolvedValue({
      job_id: "scan-cloud-1",
      status: "done",
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:05:00Z",
      request: {},
      progress: [],
      result: {
        agents: [],
        blast_radius: [],
        auto_correlation: {
          schema_version: "agent-bom.auto-correlation/v1",
          status: "skipped",
          reason: "empty_input_snapshot",
          correlation_id: "corr-output",
          input_scan_ids: ["scan-repo"],
          max_age_hours: 168,
          allow_stale: false,
        },
      },
    });

    render(<ScanResultView id="scan-cloud-1" />);

    const investigation = await screen.findByRole("link", { name: /^Investigation/i });
    expect(investigation).toHaveAttribute(
      "href",
      "/security-graph?scan=scan-cloud-1&investigate=1&lens=attack-path",
    );
    expect(
      screen.getByText("Automatic correlation skipped: empty input snapshot"),
    ).toBeInTheDocument();
  });

  it("filters and paginates dense blast-radius evidence instead of rendering every path", async () => {
    apiMock.getScan.mockResolvedValue({
      job_id: "scan-cloud-1",
      status: "done",
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:05:00Z",
      request: {},
      progress: [],
      result: {
        agents: [],
        blast_radius: Array.from({ length: 13 }, (_, index) => ({
          vulnerability_id: `CVE-2026-${String(index).padStart(4, "0")}`,
          package: `pkg-${index}`,
          severity: index % 2 === 0 ? "critical" : "high",
          blast_score: index,
          affected_agents: [],
          exposed_credentials: [],
          reachable_tools: [],
        })),
      },
    });

    const user = userEvent.setup();
    render(<ScanResultView id="scan-cloud-1" />);

    expect(await screen.findByText("Page 1 of 2 (13 paths)")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Blast Radius \(13\)/i })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
    expect(screen.getByText("CVE-2026-0012")).toBeInTheDocument();
    expect(screen.queryByText("CVE-2026-0000")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("CVE-2026-0000")).toBeInTheDocument();

    await user.selectOptions(
      screen.getByRole("combobox", { name: "Filter blast-radius paths by severity" }),
      "critical",
    );
    expect(screen.getByText("Page 1 of 1 (7 paths)")).toBeInTheDocument();
    expect(screen.queryByText("CVE-2026-0011")).not.toBeInTheDocument();
  });

  it("sums per-account counts for an organization fan-out inventory list", async () => {
    apiMock.getScan.mockResolvedValue({
      job_id: "scan-cloud-1",
      status: "done",
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:05:00Z",
      request: {},
      progress: [],
      result: {
        agents: [],
        blast_radius: [],
        cloud_inventory: [
          { provider: "aws", account_id: "111111111111", resource_count: 30, identity_count: 4 },
          { provider: "aws", account_id: "222222222222", resource_count: 12, identity_count: 3 },
        ],
      },
    });

    render(<ScanResultView id="scan-cloud-1" />);

    await waitFor(() => expect(apiMock.getScan).toHaveBeenCalledWith("scan-cloud-1"));

    // Resources is the estate total, not the member-account count (2).
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
  });
});
