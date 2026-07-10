import { describe, expect, it } from "vitest";

import {
  formatDurationMs,
  jobWallClockMs,
  mergePipelineSteps,
  parsePipelineStepsFromProgress,
  summarizePipeline,
} from "@/lib/scan-pipeline-progress";

describe("scan-pipeline-progress", () => {
  it("replays the latest event per pipeline step from persisted progress", () => {
    const progress = [
      JSON.stringify({
        type: "step",
        step_id: "discovery",
        status: "running",
        message: "Discovering agents",
        started_at: "2026-06-27T00:00:00Z",
      }),
      JSON.stringify({
        type: "step",
        step_id: "discovery",
        status: "done",
        message: "Found 3 agents",
        started_at: "2026-06-27T00:00:00Z",
        completed_at: "2026-06-27T00:00:05Z",
        stats: { agents: 3 },
      }),
      "legacy plain-text progress line",
    ];

    const steps = parsePipelineStepsFromProgress(progress);
    expect(steps.get("discovery")?.status).toBe("done");
    expect(steps.get("discovery")?.stats).toEqual({ agents: 3 });
  });

  it("merges live SSE steps over persisted replay", () => {
    const persisted = parsePipelineStepsFromProgress([
      JSON.stringify({
        type: "step",
        step_id: "scanning",
        status: "running",
        message: "Querying databases",
        started_at: "2026-06-27T00:00:10Z",
      }),
    ]);
    const live = new Map([
      [
        "scanning",
        {
          type: "step" as const,
          step_id: "scanning",
          status: "done" as const,
          message: "Scan complete",
          started_at: "2026-06-27T00:00:10Z",
          completed_at: "2026-06-27T00:00:20Z",
        },
      ],
    ]);

    const merged = mergePipelineSteps(persisted, live);
    expect(merged.get("scanning")?.status).toBe("done");
  });

  it("summarizes wall clock and per-step durations", () => {
    const steps = parsePipelineStepsFromProgress([
      JSON.stringify({
        type: "step",
        step_id: "discovery",
        status: "done",
        message: "done",
        started_at: "2026-06-27T00:00:00Z",
        completed_at: "2026-06-27T00:00:02Z",
      }),
      JSON.stringify({
        type: "step",
        step_id: "extraction",
        status: "running",
        message: "extracting",
        started_at: "2026-06-27T00:00:02Z",
      }),
    ]);

    const summary = summarizePipeline(steps, {
      created_at: "2026-06-27T00:00:00Z",
      started_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:00:30Z",
      status: "running",
    });

    expect(summary.completedSteps).toBe(1);
    expect(summary.currentStepLabel).toBe("Extraction");
    expect(summary.wallClockMs).toBe(30_000);
    expect(summary.stepDurationsMs.discovery).toBe(2_000);
    expect(formatDurationMs(2_000)).toBe("2.0s");
    expect(jobWallClockMs({
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:00:30Z",
    })).toBe(30_000);
  });
});
