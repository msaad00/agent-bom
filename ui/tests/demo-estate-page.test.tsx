import { render, screen, waitFor, within } from "@testing-library/react";
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
    cross_source_correlations: 1,
    snapshots: 3,
    findings: 439,
  },
  bounds: {
    events: { returned: 1, total: 15, limit: 200, truncated: true },
    correlations: { returned: 1, total: 4, limit: 50, truncated: true },
    findings: { returned: 1, total: 439, limit: 100, truncated: true },
  },
  count_metadata: {
    attack_paths_evidenced: {
      definition: "Unique correlation identifiers referenced by synthetic finding evidence; not persisted or derived graph paths.",
      source: "synthetic_finding_evidence",
      scope: "whole bundled fictional estate",
      window: "bundled synthetic snapshot",
      filters: ["finding evidence has correlation_id"],
      returned: 4,
      total: 4,
      completeness: "complete",
    },
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
  finding_summary: {
    schema_version: "enterprise_findings.v1",
    total: 439,
    // Sums to `total`, `unrated` included — the invariant the page renders.
    by_severity: { critical: 26, high: 204, medium: 180, low: 1, unrated: 28 },
    assets_affected: 407,
    assets_total: 2068,
    controls_evidenced: 45,
    frameworks_evidenced: ["generic", "mitre_attack"],
    attack_paths_evidenced: 4,
    identities_implicated: 399,
  },
  findings: [
    {
      finding_id: "finding-1",
      finding_type: "CIS_FAIL",
      severity: "critical",
      severity_bucket: "critical",
      title: "CIS 1.16: No full-admin IAM policies attached",
      security_domain: "cspm",
      provider: "aws",
      account_ref: "aws:123456789012",
      region: "global",
      environment: "production",
      asset_id: "cloud_resource:aws:iam:role:member-copilot-prod",
      asset_canonical_id: "d".repeat(36),
      asset_display_name: "member-copilot-prod",
      identity_asset_id: "cloud_resource:aws:iam:role:member-copilot-prod",
      identity_display_name: "member-copilot-prod",
      identity_actor_id: "arn:aws:sts::123456789012:assumed-role/member-copilot-prod",
      configuration_setting: "attached_policy_actions",
      configuration_observed: "Action '*' on Resource '*'",
      configuration_expected: "Least-privilege actions scoped to named resources",
      controls: ["generic:CIS-1.16", "mitre_attack:T1068", "mitre_attack:T1134", "mitre_attack:T1548"],
      correlation_id: "corr-primary",
      attack_path: ["github:workflow", "aws:role", "openai:model"],
    },
    {
      finding_id: "finding-2",
      finding_type: "CIS_ERROR",
      severity: "unknown",
      severity_bucket: "unrated",
      title: "CIS 2.1.2: S3 bucket server-side encryption enabled",
      security_domain: "cspm",
      provider: "aws",
      account_ref: "aws:100000000000",
      region: "us-east-1",
      environment: "staging",
      asset_id: "aws:bucket:100000000000:aws-s3-00-001",
      asset_canonical_id: "e".repeat(36),
      asset_display_name: "aws-s3-00-001",
      identity_asset_id: "aws:iam_role:100000000000:aws-iam-00-002",
      identity_display_name: "aws-iam-00-002",
      identity_actor_id: "",
      configuration_setting: "ServerSideEncryptionConfiguration",
      configuration_observed: "unreadable",
      configuration_expected: "ApplyServerSideEncryptionByDefault=aws:kms",
      controls: ["generic:CIS-2.1.2"],
      correlation_id: "",
      attack_path: [],
    },
  ],
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
    expect(screen.getByText("Demo findings")).toBeInTheDocument();
    expect(screen.getByText("Evidence-linked correlations")).toBeInTheDocument();
    expect(screen.queryByText("Attack paths")).not.toBeInTheDocument();
    const incident = screen.getByRole("heading", { name: /Sensitive-data path stopped/i }).closest("section");
    expect(within(incident!).getByTitle(story.primary_correlation.asset_path[0]!)).toHaveClass("break-all");
    const starts = screen.getByRole("region", { name: /Start by workflow/i });
    for (const label of [
      "CLI scan",
      "Docker scan",
      "GitHub Action",
      "Control plane",
      "Compliance evidence",
      "Runtime enforcement",
    ]) {
      expect(within(starts).getByText(label)).toBeInTheDocument();
    }
  });

  it("renders each finding as a chain, with counts that reconcile", async () => {
    apiMock.getEnterpriseDemoStory.mockResolvedValue(story);
    render(<DemoEstatePage />);

    const posture = await screen.findByTestId("demo-estate-posture");

    // The severity strip carries every band including `unrated`, and the label
    // beside it states the total those bands sum to.
    const bands = story.finding_summary.by_severity;
    for (const band of ["critical", "high", "medium", "low", "unrated"]) {
      expect(posture).toHaveTextContent(new RegExp(`${band}\\s+${bands[band]}`, "i"));
    }
    const summed = Object.values(bands).reduce((a, b) => a + b, 0);
    expect(summed).toBe(story.finding_summary.total);
    expect(posture).toHaveTextContent(`= ${story.finding_summary.total} findings`);

    // The bounded list states what it is bounded against — never its own length
    // dressed up as the estate total.
    expect(posture).toHaveTextContent(
      `Showing ${story.findings.length} of ${story.finding_summary.total}`,
    );
    expect(posture).toHaveTextContent("407 / 2068");

    // Every link of the chain is on screen for the incident row.
    expect(posture).toHaveTextContent("CIS 1.16: No full-admin IAM policies attached");
    expect(posture).toHaveTextContent("member-copilot-prod");
    expect(posture).toHaveTextContent("attached_policy_actions");
    expect(posture).toHaveTextContent("Least-privilege actions scoped to named resources");
    expect(posture).toHaveTextContent("generic:CIS-1.16");
    expect(posture).toHaveTextContent("on a correlated attack path (3 hops)");

    // An unevaluable control renders as unrated rather than borrowing a band.
    expect(posture).toHaveTextContent("unreadable");

    // The correlations list is bounded too, and says so.
    expect(
      screen.getByText(
        `Showing ${story.correlations.length} of ${story.summary.correlations} — the incident first. ${story.summary.cross_source_correlations} span more than one evidence source.`,
      ),
    ).toBeInTheDocument();
  });

  it("labels every bounded list, including the evidence timeline", async () => {
    apiMock.getEnterpriseDemoStory.mockResolvedValue(story);
    render(<DemoEstatePage />);
    await waitFor(() =>
      expect(screen.getByTestId("demo-estate-summary")).toBeInTheDocument(),
    );

    // The timeline renders `events`, which the API bounds against the estate's
    // whole observation count. A slice that serialises as the whole is the
    // #4631 defect class, and the two sibling sections already say so.
    expect(
      screen.getByText(
        `Showing ${story.events.length} of ${story.summary.observations} normalized events — the correlated incident included, then oldest first.`,
      ),
    ).toBeInTheDocument();
  });

  it("never presents single-source traces as cross-vendor correlations", async () => {
    apiMock.getEnterpriseDemoStory.mockResolvedValue(story);
    render(<DemoEstatePage />);

    const strip = await screen.findByTestId("demo-estate-summary");
    // The headline tile counts trace groups; on the shipped estate almost all
    // of them are one event from one source. The tile must qualify itself.
    expect(strip).toHaveTextContent(
      `${story.summary.cross_source_correlations} cross-source`,
    );
  });

  it("does not substitute live data when demo mode is unavailable", async () => {
    apiMock.getEnterpriseDemoStory.mockRejectedValue(new Error("Demo estate is not enabled"));
    render(<DemoEstatePage />);

    await waitFor(() => expect(screen.getByTestId("demo-estate-error")).toBeInTheDocument());
    expect(screen.getByText("Enterprise demo is not enabled")).toBeInTheDocument();
    expect(screen.getByText("agent-bom serve --demo-estate --allow-insecure-no-auth")).toBeInTheDocument();
  });
});
