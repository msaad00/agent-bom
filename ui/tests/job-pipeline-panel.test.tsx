import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { JobPipelinePanel } from "@/components/job-pipeline-panel";

const mocks = vi.hoisted(() => ({ getScan: vi.fn() }));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, getScan: mocks.getScan } };
});

vi.mock("@/lib/use-scan-stream", () => ({
  useScanStream: () => ({ pipelineSteps: new Map(), streaming: false, messages: [] }),
}));

vi.mock("@/components/scan-pipeline", () => ({
  ScanPipeline: ({ onStepClick }: { onStepClick: (id: string) => void }) => (
    <button type="button" onClick={() => onStepClick("sca")}>Select scanning stage</button>
  ),
}));

describe("JobPipelinePanel evidence explainability", () => {
  beforeEach(() => {
    mocks.getScan.mockReset();
    mocks.getScan.mockResolvedValue({
      job_id: "scan-1",
      status: "done",
      created_at: "2026-08-23T12:00:00Z",
      completed_at: "2026-08-23T12:00:08Z",
      triggered_by: "schedule",
      schedule_id: "schedule-prod",
      source_id: "source-cloud",
      request: {},
      progress: [
        ...["discovery", "extraction", "enrichment", "analysis", "output"].map((stepId) =>
          JSON.stringify({
            type: "step",
            step_id: stepId,
            status: "done",
            message: `${stepId} complete`,
            started_at: "2026-08-23T12:00:00Z",
            completed_at: "2026-08-23T12:00:01Z",
            stats: {},
          }),
        ),
        JSON.stringify({
          type: "step",
          step_id: "scanning",
          status: "done",
          message: "Scanners completed with partial evidence",
          started_at: "2026-08-23T12:00:02Z",
          completed_at: "2026-08-23T12:00:06Z",
          stats: { vulnerabilities: 9 },
        }),
      ],
      result: {
        agents: [],
        blast_radius: [],
        vuln_data_freshness: {
          mode: "local",
          age_hours: 26,
          stale: true,
        },
        scan_run: {
          outcome: "partial",
          issues: [
            {
              code: "scanner_coverage_gap",
              stage: "scanning",
              source: "ast-js-ts",
              message: "Structured JS/TS analysis did not complete; regex fallback coverage is partial.",
              severity: "warning",
              affects_coverage: true,
            },
          ],
        },
      },
    });
  });

  it("surfaces provenance, freshness, stage timing, stats, and collector issues", async () => {
    render(
      <JobPipelinePanel
        jobId="scan-1"
        status="done"
        createdAt="2026-08-23T12:00:00Z"
        completedAt="2026-08-23T12:00:08Z"
      />,
    );

    await waitFor(() => expect(screen.getByText("Trigger: Schedule")).toBeInTheDocument());
    expect(screen.getByText("Schedule schedule-prod")).toBeInTheDocument();
    expect(screen.getByText("Source source-cloud")).toBeInTheDocument();
    expect(screen.getByText("Vuln data 26h old")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Select scanning stage" }));
    expect(screen.getByText("9 vulnerabilities")).toBeInTheDocument();
    expect(screen.getByText("ast-js-ts")).toBeInTheDocument();
    expect(screen.getByText("scanner_coverage_gap")).toBeInTheDocument();
    expect(screen.getByText("Structured JS/TS analysis did not complete; regex fallback coverage is partial.")).toBeInTheDocument();
    expect(screen.getByText("Coverage affected")).toBeInTheDocument();
  });
});
