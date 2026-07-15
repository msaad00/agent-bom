import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ReportsPanel } from "@/components/integrations/reports-panel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    createReportJob: vi.fn(),
    getReportJob: vi.fn(),
    downloadReportArtifact: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({ api: apiMock, formatDate: (s: string) => s }));

const PENDING = {
  job_id: "job-abcdef12",
  tenant_id: "t",
  status: "pending",
  format: "ndjson",
  sort: "effective_reach",
  severity: null,
  created_at: "2026-07-14T00:00:00Z",
  started_at: null,
  completed_at: null,
  row_count: null,
  byte_count: null,
  error: null,
};

const DONE = { ...PENDING, status: "done", row_count: 128, download_token: "test", download_token_header: "X-Agent-Bom-Download-Token" };

beforeEach(() => {
  Object.values(apiMock).forEach((fn) => fn.mockReset());
  URL.createObjectURL = vi.fn(() => "blob:mock");
  URL.revokeObjectURL = vi.fn();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("ReportsPanel", () => {
  it("queues an export and shows the job row", async () => {
    apiMock.createReportJob.mockResolvedValue(PENDING);
    render(<ReportsPanel />);
    fireEvent.change(screen.getByTestId("report-sort-select"), { target: { value: "cvss" } });
    fireEvent.click(screen.getByTestId("report-create-submit"));
    await waitFor(() =>
      expect(apiMock.createReportJob).toHaveBeenCalledWith({ format: "ndjson", sort: "cvss", severity: null }),
    );
    expect(await screen.findByText(/job-abcd/)).toBeInTheDocument();
  });

  it("polls a pending job until it completes", async () => {
    apiMock.createReportJob.mockResolvedValue(PENDING);
    apiMock.getReportJob.mockResolvedValue(DONE);
    render(<ReportsPanel />);
    fireEvent.click(screen.getByTestId("report-create-submit"));
    // A pending row appears immediately; the 2.5s poll interval then advances it.
    expect(await screen.findByText(/job-abcd/)).toBeInTheDocument();
    await waitFor(
      () => expect(apiMock.getReportJob).toHaveBeenCalledWith("job-abcdef12"),
      { timeout: 4000 },
    );
    await waitFor(() => expect(screen.getByTestId("reports-table")).toHaveTextContent("done"));
  });

  it("downloads a completed report using the job-scoped token header", async () => {
    apiMock.createReportJob.mockResolvedValue(DONE);
    apiMock.downloadReportArtifact.mockResolvedValue(new Blob(["x"]));
    render(<ReportsPanel />);
    fireEvent.click(screen.getByTestId("report-create-submit"));
    const btn = await screen.findByTestId("report-download-job-abcd");
    fireEvent.click(btn);
    await waitFor(() =>
      expect(apiMock.downloadReportArtifact).toHaveBeenCalledWith("job-abcdef12", "test"),
    );
  });
});
