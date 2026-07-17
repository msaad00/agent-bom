import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { RiskCampaignCommandCenter } from "@/components/risk-campaign-command-center";
import { api } from "@/lib/api";
import type { RiskCampaignsResponse } from "@/lib/api-types";
import { ApiConflictError } from "@/lib/api-errors";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      listTicketingConnections: vi.fn(),
      listRiskCampaigns: vi.fn(),
      updateRiskCampaign: vi.fn(),
      verifyRiskCampaign: vi.fn(),
      createRiskCampaignTickets: vi.fn(),
      syncRiskCampaignTickets: vi.fn(),
    },
  };
});

const response: RiskCampaignsResponse = {
  schema_version: "risk-campaigns.v1",
  tenant_id: "tenant-a",
  count: 1,
  finding_window_days: 90,
  finding_limit: 1000,
  truncated: true,
  total_findings: 1200,
  total_approximate: true,
  membership_complete: false,
  campaigns: [
    {
      id: "campaign-1",
      tenant_id: "tenant-a",
      title: "Upgrade openssl to 3.0.14",
      finding_ids: ["finding-1", "finding-2"],
      finding_count: 2,
      severity: "critical",
      priority_score: 9.2,
      priority_score_method: "bounded additive model over observed evidence; unknown factors add no boost",
      priority_score_components: {
        base_risk: 7.5,
        exploitability_boost: 1,
        reachability_boost: 0.7,
        crown_jewel_boost: 0,
        cap: 10,
      },
      score_factors: {
        severity: { value: "critical", status: "observed", bands_present: ["critical", "high"] },
        exploitability: { value: "known_exploited", status: "observed", signals: ["kev"] },
        reachability: { value: true, status: "observed" },
        business_context: { value: null, status: "unknown" },
        crown_jewel: { value: null, status: "unknown" },
      },
      expected_risk_reduction: {
        modeled_window_percent: 18.5,
        modeled_risk_points: 44,
        assumption: "Both findings are remediated and re-verified.",
        method: "Server-side campaign model v1",
        scope: "last 90 days, first 1000 findings",
        portfolio_complete: false,
      },
      owner: "platform-security",
      sla_due_at: "2026-07-22T12:00:00Z",
      state: "in_progress",
      verification_status: "pending",
      updated_at: "2026-07-17T12:00:00Z",
      source: "correlated_findings",
      membership_fingerprint: "sha256:campaign-membership",
      generation: 2,
      version: 4,
      active: true,
      membership_complete: true,
      membership_provisional: false,
    },
  ],
};

describe("RiskCampaignCommandCenter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.listRiskCampaigns).mockResolvedValue(response);
    vi.mocked(api.listTicketingConnections).mockResolvedValue({
      schema_version: "ticketing.connections.v1",
      tenant_id: "tenant-a",
      count: 1,
      connections: [{
        id: "connection-1",
        tenant_id: "tenant-a",
        provider: "jira",
        transport: "mcp",
        auth_method: "oauth",
        display_name: "Security tickets",
        endpoint: "mcp://ticketing",
        auth_params: {},
        status: "active",
        status_detail: "",
        created_at: "2026-07-17T12:00:00Z",
        updated_at: "2026-07-17T12:00:00Z",
        has_secret: true,
      }],
    });
  });

  it("renders server-authored priority, context, SLA, score factors, and truncation honesty", async () => {
    render(<RiskCampaignCommandCenter />);

    expect(screen.getByText(/Loading prioritized campaigns/i)).toBeInTheDocument();
    expect(await screen.findByText(response.campaigns[0]!.title)).toBeInTheDocument();
    expect(screen.getByText("9.2")).toBeInTheDocument();
    expect(screen.getByText(/18.5% modeled window risk/i)).toBeInTheDocument();
    expect(screen.getByText(/not full portfolio/i)).toBeInTheDocument();
    expect(screen.getByText(/platform-security/i)).toBeInTheDocument();
    expect(screen.getByText(/Results may be incomplete/i)).toBeInTheDocument();
    expect(screen.getByText(/approximately 1,200 total findings/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Why this priority/i }));
    expect(screen.getAllByText(/Exploitability/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Crown jewel/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Base risk/i)).toBeInTheDocument();
    expect(screen.getByText(/Unknown evidence is neutral/i)).toBeInTheDocument();
    expect(screen.getByText(/Server-side campaign model v1/i)).toBeInTheDocument();
    expect(screen.getAllByText("Unknown").length).toBeGreaterThan(0);
  });

  it("renders an honest empty state without a success claim", async () => {
    vi.mocked(api.listRiskCampaigns).mockResolvedValue({
      ...response,
      campaigns: [],
      count: 0,
      truncated: false,
    });

    render(<RiskCampaignCommandCenter />);

    expect(await screen.findByText(/No prioritized campaigns yet/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Run a scan/i })).toHaveAttribute("href", "/scan");
    expect(screen.queryByText(/all clear/i)).not.toBeInTheDocument();
  });

  it("pauses workflow and ticket actions for provisional membership", async () => {
    vi.mocked(api.listRiskCampaigns).mockResolvedValue({
      ...response,
      campaigns: [{
        ...response.campaigns[0]!,
        membership_complete: false,
        membership_provisional: true,
      }],
      membership_complete: false,
      truncated: true,
    });

    render(<RiskCampaignCommandCenter />);

    expect(await screen.findByText(/Workflow actions are paused/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Create campaign tickets/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Sync tickets/i })).toBeDisabled();
    expect(screen.getByLabelText(/Campaign state/i)).toBeDisabled();
    expect(screen.getByRole("button", { name: /Edit owner and SLA/i })).toBeDisabled();
  });

  it("requires a stored active connection for ticket creation but still permits sync", async () => {
    vi.mocked(api.listTicketingConnections).mockResolvedValue({
      schema_version: "ticketing.connections.v1",
      tenant_id: "tenant-a",
      count: 0,
      connections: [],
    });

    render(<RiskCampaignCommandCenter />);

    await screen.findByText(response.campaigns[0]!.title);
    expect(screen.getByRole("button", { name: /Create campaign tickets/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Sync tickets/i })).toBeEnabled();
    expect(screen.getByRole("link", { name: /Connect ticketing/i })).toHaveAttribute("href", "/connections");
  });

  it("surfaces API errors and retries", async () => {
    vi.mocked(api.listRiskCampaigns)
      .mockRejectedValueOnce(new Error("Campaign service unavailable"))
      .mockResolvedValueOnce({ ...response, truncated: false });

    render(<RiskCampaignCommandCenter />);

    expect(await screen.findByText("Campaign service unavailable")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Retry campaigns/i }));
    expect(await screen.findByText(response.campaigns[0]!.title)).toBeInTheDocument();
  });

  it("reports partial bulk ticket results and never requests a credential", async () => {
    vi.mocked(api.createRiskCampaignTickets).mockResolvedValue({
      schema_version: "risk-campaign-tickets.v1",
      campaign_id: "campaign-1",
      created: 1,
      failed: 1,
      tickets: [],
      errors: [{ finding_id: "finding-2", code: "transport_error", detail: "Ticket creation failed" }],
      per_action_credential: false,
      total: 2,
      processed: 2,
      next_cursor: null,
      has_more: false,
      action_limit: 25,
    });

    render(<RiskCampaignCommandCenter />);
    await screen.findByText(response.campaigns[0]!.title);
    fireEvent.click(screen.getByRole("button", { name: /Create campaign tickets/i }));

    expect(await screen.findByText(/1 ticket created; 1 failed/i)).toBeInTheDocument();
    expect(api.createRiskCampaignTickets).toHaveBeenCalledWith("campaign-1", {
      connection_id: "connection-1",
      limit: 25,
    });
    expect(screen.queryByLabelText(/token|credential|api key/i)).not.toBeInTheDocument();
  });

  it("reports partial ticket sync using the synced count", async () => {
    vi.mocked(api.syncRiskCampaignTickets).mockResolvedValue({
      schema_version: "risk-campaign-ticket-sync.v1",
      campaign_id: "campaign-1",
      synced: 1,
      failed: 1,
      tickets: [],
      errors: [{ ticket_id: "ticket-2", code: "transport_error", detail: "Ticket sync failed" }],
      per_action_credential: false,
      total: 2,
      processed: 2,
      next_cursor: null,
      has_more: false,
      action_limit: 25,
    });

    render(<RiskCampaignCommandCenter />);
    await screen.findByText(response.campaigns[0]!.title);
    fireEvent.click(screen.getByRole("button", { name: /Sync tickets/i }));

    expect(await screen.findByText(/1 ticket synced; 1 failed/i)).toBeInTheDocument();
  });

  it("continues bounded ticket batches and preserves cumulative partial progress", async () => {
    vi.mocked(api.createRiskCampaignTickets)
      .mockResolvedValueOnce({
        schema_version: "risk-campaign-tickets.v1",
        campaign_id: "campaign-1",
        created: 24,
        failed: 1,
        tickets: [],
        errors: [{ finding_id: "finding-25", code: "transport_error", detail: "Ticket creation failed" }],
        per_action_credential: false,
        total: 30,
        processed: 25,
        next_cursor: "cursor-25",
        has_more: true,
        action_limit: 25,
      })
      .mockResolvedValueOnce({
        schema_version: "risk-campaign-tickets.v1",
        campaign_id: "campaign-1",
        created: 5,
        failed: 0,
        tickets: [],
        errors: [],
        per_action_credential: false,
        total: 30,
        processed: 5,
        next_cursor: null,
        has_more: false,
        action_limit: 25,
      });

    render(<RiskCampaignCommandCenter />);
    await screen.findByText(response.campaigns[0]!.title);
    fireEvent.click(screen.getByRole("button", { name: /Create campaign tickets/i }));
    expect(await screen.findByRole("button", { name: /Continue tickets \(25\/30\)/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Continue tickets/i }));

    expect(await screen.findByText(/29 tickets created; 1 failed · 30\/30 processed/i)).toBeInTheDocument();
    expect(api.createRiskCampaignTickets).toHaveBeenNthCalledWith(1, "campaign-1", {
      connection_id: "connection-1",
      limit: 25,
    });
    expect(api.createRiskCampaignTickets).toHaveBeenNthCalledWith(2, "campaign-1", {
      connection_id: "connection-1",
      cursor: "cursor-25",
      limit: 25,
    });
  });

  it("updates workflow state using the authoritative PATCH response", async () => {
    vi.mocked(api.updateRiskCampaign).mockResolvedValue({
      ...response.campaigns[0]!,
      state: "done",
      verification_status: "pending",
    });

    render(<RiskCampaignCommandCenter />);
    await screen.findByText(response.campaigns[0]!.title);
    fireEvent.change(screen.getByLabelText(/Campaign state/i), {
      target: { value: "done" },
    });

    await waitFor(() =>
      expect(api.updateRiskCampaign).toHaveBeenCalledWith("campaign-1", {
        version: 4,
        state: "done",
      }),
    );
    expect((await screen.findAllByText(/Pending verification/i)).length).toBeGreaterThan(0);
  });

  it("re-verifies against server-owned canonical evidence and renders remaining evidence", async () => {
    vi.mocked(api.verifyRiskCampaign).mockResolvedValue({
      schema_version: "risk-campaign-verification.v1",
      campaign_id: "campaign-1",
      verification_status: "failed",
      state: "in_progress",
      remaining_finding_ids: ["finding-2"],
      remaining_count: 1,
      original_member_count: 2,
      evidence_scope: {
        source: "canonical_findings_spine",
        finding_window_days: 90,
        finding_limit: 1000,
        membership_complete: true,
      },
      version: 5,
      verified_at: "2026-07-17T13:00:00Z",
    });

    render(<RiskCampaignCommandCenter />);
    await screen.findByText(response.campaigns[0]!.title);
    fireEvent.click(screen.getByRole("button", { name: /Re-verify remediation/i }));

    await waitFor(() => expect(api.verifyRiskCampaign).toHaveBeenCalledWith("campaign-1", { version: 4 }));
    expect(await screen.findByText(/1 of 2 original findings remain/i)).toBeInTheDocument();
    expect(screen.getByText(/canonical findings spine/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Verification failed/i).length).toBeGreaterThan(0);
  });

  it("reports successful server verification without caller-authored status", async () => {
    vi.mocked(api.verifyRiskCampaign).mockResolvedValue({
      schema_version: "risk-campaign-verification.v1",
      campaign_id: "campaign-1",
      verification_status: "verified",
      state: "done",
      remaining_finding_ids: [],
      remaining_count: 0,
      original_member_count: 2,
      evidence_scope: {
        source: "canonical_findings_spine",
        finding_window_days: 90,
        finding_limit: 1000,
        membership_complete: true,
      },
      version: 5,
      verified_at: "2026-07-17T13:00:00Z",
    });

    render(<RiskCampaignCommandCenter />);
    await screen.findByText(response.campaigns[0]!.title);
    fireEvent.click(screen.getByRole("button", { name: /Re-verify remediation/i }));

    expect(await screen.findByText(/No original findings remain/i)).toBeInTheDocument();
    expect((await screen.findAllByText("Verified")).length).toBeGreaterThan(0);
    expect(api.updateRiskCampaign).not.toHaveBeenCalled();
  });

  it("assigns an owner and SLA through the campaign workflow API", async () => {
    vi.mocked(api.updateRiskCampaign).mockResolvedValue({
      ...response.campaigns[0]!,
      owner: "appsec",
      sla_due_at: "2026-07-25T00:00:00.000Z",
    });

    render(<RiskCampaignCommandCenter />);
    await screen.findByText(response.campaigns[0]!.title);
    fireEvent.click(screen.getByRole("button", { name: /Edit owner and SLA/i }));
    fireEvent.change(screen.getByLabelText(/Campaign owner/i), { target: { value: "appsec" } });
    fireEvent.change(screen.getByLabelText(/Campaign SLA/i), { target: { value: "2026-07-25" } });
    fireEvent.click(screen.getByRole("button", { name: /Save owner and SLA/i }));

    await waitFor(() => expect(api.updateRiskCampaign).toHaveBeenCalledWith("campaign-1", {
      version: 4,
      owner: "appsec",
      sla_due_at: "2026-07-25T00:00:00.000Z",
    }));
  });

  it("shows a stale-version conflict and reloads authoritative state", async () => {
    vi.mocked(api.updateRiskCampaign).mockRejectedValue(new ApiConflictError(
      "Campaign changed since it was loaded",
      { status: 409, statusText: "Conflict", url: "/v1/campaigns/campaign-1", method: "PATCH" },
    ));

    render(<RiskCampaignCommandCenter />);
    await screen.findByText(response.campaigns[0]!.title);
    fireEvent.change(screen.getByLabelText(/Campaign state/i), { target: { value: "blocked" } });

    expect(await screen.findByText(/Campaign changed since it was loaded/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Reload campaigns/i }));
    await waitFor(() => expect(api.listRiskCampaigns).toHaveBeenCalledTimes(2));
  });
});
