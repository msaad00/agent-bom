import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import DemoEstatePage from "@/app/demo-estate/page";
import type { EnterpriseDemoStory } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { getEnterpriseDemoStory: vi.fn() },
}));

vi.mock("@/lib/api", () => ({ api: apiMock }));

const correlation = {
  correlation_version: "enterprise_correlation.v1",
  correlation_id: "corr-primary",
  tenant_id: "tenant-a",
  trace_id: "trace-egress",
  kind: "data_egress_attempt",
  outcome: "blocked",
  started_at: "2026-07-13T19:00:00Z",
  ended_at: "2026-07-13T19:05:00Z",
  event_ids: ["event-1"],
  sources: ["github_actions", "aws_cloudtrail", "otel_llm"],
  asset_ids: ["github:workflow", "aws:role", "openai:model"],
  asset_path: ["github:workflow", "aws:role", "openai:model"],
  data_classifications: ["phi"],
  evidence_hashes: ["a".repeat(64)],
  evidence_quality: "complete",
  incomplete_sources: [],
};

const story: EnterpriseDemoStory = {
  schema_version: "enterprise_demo_story.v1",
  synthetic: true,
  fictional: true,
  disclosure: "This estate is entirely fictional and contains no customer data.",
  estate_id: "northstar-health-ai",
  estate_name: "Northstar Health AI",
  tenant_id: "tenant-a",
  scenario: "A multi-vendor identity path reaches PHI and is blocked before model egress.",
  estate_content_hash: "b".repeat(64),
  story_content_hash: "c".repeat(64),
  summary: {
    assets: 20,
    observations: 15,
    evidence_sources: 9,
    complete_sources: 8,
    partial_sources: 1,
    correlations: 4,
    snapshots: 3,
  },
  primary_correlation: correlation,
  events: [
    {
      normalization_version: "enterprise_event.v1",
      event_id: "event-1",
      tenant_id: "tenant-a",
      stage: "detected",
      source: "github_actions",
      event_type: "workflow_run",
      observed_at: "2026-07-13T19:00:00Z",
      trace_id: "trace-egress",
      actor_id: "agent:release-bot",
      resource_ids: ["github:workflow"],
      evidence_hash: "a".repeat(64),
      source_run_id: "run-1",
      event_relationships: {},
      graph_projection: {},
    },
  ],
  correlations: [correlation],
  collection_health: [
    {
      source: "gcp_audit",
      status: "partial",
      records_read: 2,
      watermark: "2026-07-13T19:06:00Z",
      source_schema: "google-cloud-audit-log",
      schema_url: "https://example.invalid/gcp.audit.v1",
      failure_code: "rate_limited_after_page_2",
    },
  ],
};

beforeEach(() => {
  apiMock.getEnterpriseDemoStory.mockReset();
});

describe("DemoEstatePage", () => {
  it("renders one honest cross-vendor story from the canonical API model", async () => {
    apiMock.getEnterpriseDemoStory.mockResolvedValue(story);
    render(<DemoEstatePage />);

    expect(await screen.findByRole("heading", { name: "Northstar Health AI" })).toBeInTheDocument();
    expect(screen.getByText("Synthetic enterprise evidence")).toBeInTheDocument();
    expect(screen.getByText("Sensitive-data path stopped before model egress")).toBeInTheDocument();
    expect(screen.getByText("rate_limited_after_page_2")).toBeInTheDocument();
    expect(screen.getByText("GCP Audit Logs")).toBeInTheDocument();
    expect(screen.getByText("2 records · google-cloud-audit-log")).toBeInTheDocument();
    expect(screen.getByText("workflow_run")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open security graph/ })).toHaveAttribute("href", "/security-graph");
  });

  it("does not substitute live data when demo mode is unavailable", async () => {
    apiMock.getEnterpriseDemoStory.mockRejectedValue(new Error("Demo estate is not enabled"));
    render(<DemoEstatePage />);

    await waitFor(() => expect(screen.getByTestId("demo-estate-error")).toBeInTheDocument());
    expect(screen.getByText("Enterprise demo is not enabled")).toBeInTheDocument();
    expect(screen.getByText("agent-bom serve --demo-estate --allow-insecure-no-auth")).toBeInTheDocument();
  });
});
