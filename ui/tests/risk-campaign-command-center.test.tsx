import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { RiskCampaignCommandCenter } from "@/components/risk-campaign-command-center";
import { api } from "@/lib/api";
import type { RiskCampaignsResponse } from "@/lib/api-types";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      listTicketingConnections: vi.fn(),
      listRiskCampaigns: vi.fn(),
      updateRiskCampaign: vi.fn(),
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
  campaigns: [
    {
      id: "campaign-1",
      tenant_id: "tenant-a",
      title: "Upgrade openssl to 3.0.14",
      finding_ids: ["finding-1", "finding-2"],
      finding_count: 2,
      severity: "critical",
      priority_score: 92,
      priority_score_method: "maximum finding risk; context factors do not modify the score",
      score_factors: {
        severity: { value: "critical", status: "observed", bands_present: ["critical", "high"] },
        exploitability: { value: "known_exploited", status: "observed", signals: ["kev"] },
        reachability: { value: true, status: "observed" },
        business_context: { value: null, status: "unknown" },
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
    expect(screen.getByText("92")).toBeInTheDocument();
    expect(screen.getByText(/18.5% modeled window risk/i)).toBeInTheDocument();
    expect(screen.getByText(/not full portfolio/i)).toBeInTheDocument();
    expect(screen.getByText(/platform-security/i)).toBeInTheDocument();
    expect(screen.getByText(/Results may be incomplete/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Why this priority/i }));
    expect(screen.getByText(/Exploitability/i)).toBeInTheDocument();
    expect(screen.getByText(/Server-side campaign model v1/i)).toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
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
    });

    render(<RiskCampaignCommandCenter />);
    await screen.findByText(response.campaigns[0]!.title);
    fireEvent.click(screen.getByRole("button", { name: /Create campaign tickets/i }));

    expect(await screen.findByText(/1 ticket created; 1 failed/i)).toBeInTheDocument();
    expect(api.createRiskCampaignTickets).toHaveBeenCalledWith("campaign-1", {
      connection_id: "connection-1",
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
    });

    render(<RiskCampaignCommandCenter />);
    await screen.findByText(response.campaigns[0]!.title);
    fireEvent.click(screen.getByRole("button", { name: /Sync tickets/i }));

    expect(await screen.findByText(/1 ticket synced; 1 failed/i)).toBeInTheDocument();
  });

  it("updates workflow state using the authoritative PATCH response", async () => {
    vi.mocked(api.updateRiskCampaign).mockResolvedValue({
      ...response.campaigns[0]!,
      state: "done",
      verification_status: "verified",
    });

    render(<RiskCampaignCommandCenter />);
    await screen.findByText(response.campaigns[0]!.title);
    fireEvent.change(screen.getByLabelText(/Campaign state/i), {
      target: { value: "done" },
    });

    await waitFor(() =>
      expect(api.updateRiskCampaign).toHaveBeenCalledWith("campaign-1", {
        state: "done",
      }),
    );
    expect((await screen.findAllByText(/Verified/i)).length).toBeGreaterThan(0);
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
      owner: "appsec",
      sla_due_at: "2026-07-25T00:00:00.000Z",
    }));
  });
});
