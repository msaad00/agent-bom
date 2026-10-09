import { render, screen, waitFor } from "@testing-library/react";
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
  ScanPipeline: () => <div data-testid="scan-pipeline" />,
}));

function seededJob(summary: Record<string, unknown>) {
  return {
    job_id: "seeded-1",
    status: "done",
    created_at: "2026-10-08T12:00:00Z",
    completed_at: "2026-10-08T12:00:00Z",
    triggered_by: "demo-estate-bootstrap",
    request: {},
    progress: ["Seeded demo estate scan (offline curated sample)"],
    result: { agents: [], blast_radius: [], summary },
  };
}

function chip(label: string): number | null {
  const pattern = new RegExp(`^\\d+ ${label}$`);
  const node = screen
    .queryAllByText((_, el) => el?.tagName === "SPAN" && pattern.test(el.textContent ?? ""))
    .at(0);
  return node ? Number((node.textContent ?? "").split(" ")[0]) : null;
}

describe("JobPipelinePanel result chips and stage telemetry", () => {
  beforeEach(() => mocks.getScan.mockReset());

  it("takes findings and critical from the unified finding summary so critical never exceeds total", async () => {
    mocks.getScan.mockResolvedValue(
      seededJob({
        total_agents: 5,
        total_servers: 10,
        total_packages: 23,
        total_vulnerabilities: 22,
        critical_findings: 103,
        total_findings: 3468,
        critical_unified_findings: 527,
      }),
    );
    render(<JobPipelinePanel jobId="seeded-1" status="done" createdAt="2026-10-08T12:00:00Z" />);
    await waitFor(() => expect(chip("findings")).not.toBeNull());
    expect(chip("findings")).toBe(3468);
    expect(chip("critical")).toBe(527);
  });

  it("drops a critical chip that cannot be reconciled with the findings total", async () => {
    mocks.getScan.mockResolvedValue(
      seededJob({ total_packages: 23, total_vulnerabilities: 22, critical_findings: 103 }),
    );
    render(<JobPipelinePanel jobId="seeded-1" status="done" createdAt="2026-10-08T12:00:00Z" />);
    await waitFor(() => expect(chip("findings")).toBe(22));
    expect(chip("critical")).toBeNull();
  });

  it("hides stage timing rows and wall clock when no stage telemetry exists", async () => {
    mocks.getScan.mockResolvedValue(seededJob({ total_packages: 23, total_vulnerabilities: 22 }));
    render(<JobPipelinePanel jobId="seeded-1" status="done" createdAt="2026-10-08T12:00:00Z" />);
    await waitFor(() => expect(chip("findings")).toBe(22));
    expect(screen.queryByText("Stage timing")).not.toBeInTheDocument();
    expect(screen.queryByText("Unavailable")).not.toBeInTheDocument();
    expect(screen.queryByText(/Wall clock/)).not.toBeInTheDocument();
  });
});
