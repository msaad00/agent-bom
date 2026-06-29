import { render, screen, waitFor } from "@testing-library/react";
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
    expect(screen.getByText("AWS")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("AWS CIS")).toBeInTheDocument();
    expect(screen.getByText("30/40 passed · 75%")).toBeInTheDocument();
    expect(
      screen.getByText(/Cloud inventory and posture evidence was persisted/i),
    ).toBeInTheDocument();
  });
});
