import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import CostPage from "@/app/cost/page";
import IdentityPage from "@/app/identity/page";
import DriftPage from "@/app/drift/page";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getCostReport: vi.fn(),
    getCostAnomalies: vi.fn(),
    getCostForecast: vi.fn(),
    listIdentities: vi.fn(),
    listJitGrants: vi.fn(),
    listConditionalAccessPolicies: vi.fn(),
    getCredentialExpiry: vi.fn(),
    listAccessReviews: vi.fn(),
    discoverNonHumanIdentities: vi.fn(),
    listDriftIncidents: vi.fn(),
    resolveDriftIncident: vi.fn(),
    getPostureCounts: vi.fn(),
    formatDate: (s: string) => s,
  },
}));

vi.mock("@/lib/api", () => ({
  api: apiMock,
  formatDate: (s: string) => s,
}));

beforeEach(() => {
  Object.values(apiMock).forEach(
    (fn) => typeof fn === "function" && "mockReset" in fn && fn.mockReset(),
  );
  apiMock.getPostureCounts.mockResolvedValue({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
    kev: 0,
    compound_issues: 0,
    services: {
      ai_spend: { state: "live", count: 1 },
    },
  });
});

afterEach(() => vi.restoreAllMocks());

describe("CostPage", () => {
  it("renders spend totals, an enforced budget bar, and anomalies", async () => {
    apiMock.getCostReport.mockResolvedValue({
      schema_version: "observability.costs.v1",
      tenant_id: "t1",
      price_model_captured: {},
      total_cost_usd: 12.5,
      total_calls: 42,
      total_input_tokens: 1000,
      total_output_tokens: 500,
      unpriced_calls: 3,
      by_agent: [
        {
          key: "agent-a",
          calls: 42,
          input_tokens: 1000,
          output_tokens: 500,
          cost_usd: 12.5,
          unpriced_calls: 3,
        },
      ],
      by_model: [
        {
          key: "gpt-4",
          calls: 42,
          input_tokens: 1000,
          output_tokens: 500,
          cost_usd: 12.5,
          unpriced_calls: 3,
        },
      ],
      by_provider: [
        {
          key: "openai",
          calls: 42,
          input_tokens: 1000,
          output_tokens: 500,
          cost_usd: 12.5,
          unpriced_calls: 0,
        },
      ],
      by_cost_center: [
        {
          key: "platform-eng",
          calls: 30,
          input_tokens: 700,
          output_tokens: 350,
          cost_usd: 9.0,
          unpriced_calls: 0,
        },
        {
          key: "unallocated",
          calls: 12,
          input_tokens: 300,
          output_tokens: 150,
          cost_usd: 3.5,
          unpriced_calls: 3,
        },
      ],
      budget: {
        configured: true,
        agent: null,
        mode: "enforce",
        limit_usd: 20,
        spend_usd: 12.5,
        remaining_usd: 7.5,
        exceeded: false,
        utilization: 0.625,
      },
    });
    apiMock.getCostForecast.mockResolvedValue({
      schema_version: "observability.cost_forecast.v1",
      agent: null,
      now: "2026-06-18T00:00:00Z",
      status: "ok",
      current_spend_usd: 12.5,
      budget_limit_usd: 20,
      burn_rate_usd_per_day: 1.25,
      burn_rate_basis: "trailing_24h",
      projected_period_spend_usd: 18.0,
      period_start: "2026-06-01T00:00:00Z",
      period_end: "2026-07-01T00:00:00Z",
      days_remaining: 6,
      projected_exhaustion_at: "2026-06-24T00:00:00Z",
      tenant_id: "t1",
    });
    apiMock.getCostAnomalies.mockResolvedValue({
      schema_version: "observability.anomalies.v1",
      tenant_id: "t1",
      z_threshold: 3,
      anomaly_count: 1,
      cost_anomalies: [
        {
          type: "cost_spike",
          severity: "high",
          agent: "agent-a",
          metric: "total_cost_usd",
          value: 12.5,
          baseline_median: 2,
          z_score: 5.1,
          recommendation: "investigate",
        },
      ],
      behavior_anomalies: [],
    });

    render(<CostPage />);

    await waitFor(() =>
      expect(screen.getByText("Spend by agent (top 10)")).toBeInTheDocument(),
    );
    expect(screen.getByText("enforce")).toBeInTheDocument();
    expect(screen.getAllByText(/\$12\.5/).length).toBeGreaterThan(0);
    expect(screen.getByText("cost spike")).toBeInTheDocument();
    // Forecast/runway panel
    expect(screen.getByText("Forecast & runway")).toBeInTheDocument();
    expect(screen.getByText("at risk")).toBeInTheDocument();
    expect(screen.getByText("trailing 24h")).toBeInTheDocument();
    // Chargeback by cost-center panel
    expect(screen.getByText("Chargeback by cost-center")).toBeInTheDocument();
    expect(screen.getByText("platform-eng")).toBeInTheDocument();
  });
});

describe("IdentityPage", () => {
  it("renders identities, JIT grants, and conditional policies", async () => {
    apiMock.listIdentities.mockResolvedValue({
      schema_version: "agent.identity.v1",
      tenant_id: "t1",
      count: 1,
      identities: [
        {
          identity_id: "id_1",
          agent_id: "agent-a",
          tenant_id: "t1",
          token_prefix: "abcd1234",
          role: "agent",
          blueprint_id: "developer",
          status: "active",
          issued_at: "2026-06-01T00:00:00Z",
          expires_at: "2026-09-01T00:00:00Z",
          allowed_tools: ["list_files"],
          rotated_to_id: "",
          revoked_at: "",
          revoked_reason: "",
        },
      ],
    });
    apiMock.listJitGrants.mockResolvedValue({
      schema_version: "agent.identity.jit.v1",
      tenant_id: "t1",
      count: 1,
      grants: [
        {
          grant_id: "jit_1",
          identity_id: "id_1",
          agent_id: "agent-a",
          tenant_id: "t1",
          tool_name: "read_file",
          status: "active",
          requested_at: "2026-06-01T00:00:00Z",
          requested_by: "admin",
          approved_at: "2026-06-01T00:00:00Z",
          approved_by: "admin",
          starts_at: "2026-06-01T00:00:00Z",
          expires_at: "2026-06-01T01:00:00Z",
          reason: "incident",
          ticket_id: "INC-42",
          revoked_at: "",
          revoked_reason: "",
          denied_at: "",
          denied_reason: "",
        },
      ],
    });
    apiMock.listConditionalAccessPolicies.mockResolvedValue({
      schema_version: "agent.identity.conditional.v1",
      tenant_id: "t1",
      count: 1,
      policies: [
        {
          policy_id: "cap_1",
          tenant_id: "t1",
          name: "prod-only",
          effect: "require",
          status: "active",
          created_at: "2026-06-01T00:00:00Z",
          priority: 100,
          identity_ids: [],
          agent_ids: ["agent-a"],
          tools: [],
          allowed_environments: ["prod"],
          allowed_hours_utc: [],
          allowed_weekdays: [],
          allowed_source_cidrs: [],
          updated_at: "2026-06-01T00:00:00Z",
          description: "",
        },
      ],
    });
    apiMock.getCredentialExpiry.mockResolvedValue({
      status: "attention_required",
      secret_values_included: false,
      evaluated: 2,
      counts: { overdue: 0, expired: 0, rotation_due: 1, near_expiry: 0, unknown_age: 0, ok: 1 },
      blockers: [],
      warnings: ["audit_hmac_secret"],
      thresholds: { near_expiry_days: 14, rotation_days: 90, max_age_days: null },
      credentials: [],
      action_required: [
        {
          id: "audit_hmac_secret",
          name: "audit_hmac_secret",
          provider: "control_plane",
          identity_type: "secret",
          state: "rotation_due",
          priority: 2,
          blocking: false,
          age_days: 120,
          days_until_expiry: null,
          credential_expires_at: null,
          last_rotated: "2026-02-01T00:00:00Z",
          near_expiry_days: 14,
          rotation_days: 90,
          max_age_days: null,
          reasons: ["age 120d past rotation interval 90d"],
        },
      ],
      message: "One or more credentials are nearing expiry.",
      generated_from: "/v1/auth/secrets/credential-expiry",
      control_plane_included: true,
      discovered_credential_count: 0,
    });
    apiMock.listAccessReviews.mockResolvedValue({
      schema_version: "identity.access_review.v1",
      tenant_id: "t1",
      count: 1,
      campaigns: [
        {
          campaign_id: "rev_1",
          tenant_id: "t1",
          name: "Q3 NHI recertification",
          status: "in_progress",
          created_at: "2026-06-01T00:00:00Z",
          created_by: "admin",
          due_at: "2026-06-30T00:00:00Z",
          completed_at: "",
          description: "",
          item_count: 8,
          decided_count: 3,
        },
      ],
    });
    apiMock.discoverNonHumanIdentities.mockResolvedValue({
      schema_version: "identity.nhi.discovery.v1",
      tenant_id: "t1",
      status: "empty",
      providers: [
        { provider: "okta", status: "disabled", count: 0 },
        { provider: "entra", status: "disabled", count: 0 },
      ],
      count: 0,
      identities: [],
      warnings: [],
    });

    render(<IdentityPage />);

    await waitFor(() =>
      expect(screen.getByText("Managed identities")).toBeInTheDocument(),
    );
    expect(screen.getByText("JIT access grants")).toBeInTheDocument();
    expect(screen.getByText("Conditional-access policies")).toBeInTheDocument();
    expect(screen.getByText("prod-only")).toBeInTheDocument();
    expect(screen.getByText(/env ∈ \{prod\}/)).toBeInTheDocument();
    expect(screen.getByText("INC-42")).toBeInTheDocument();
    // Credential-expiry posture
    expect(
      screen.getByText("Credential expiry & rotation"),
    ).toBeInTheDocument();
    expect(screen.getByText("audit_hmac_secret")).toBeInTheDocument();
    // Access-review campaigns
    expect(screen.getByText("Access-review campaigns")).toBeInTheDocument();
    expect(screen.getByText("Q3 NHI recertification")).toBeInTheDocument();
    expect(screen.getByText("3 / 8")).toBeInTheDocument();
    // Discovered NHI — disabled state
    expect(
      screen.getByText("Discovered non-human identities"),
    ).toBeInTheDocument();
    expect(screen.getByText(/NHI discovery is disabled/)).toBeInTheDocument();
  });
});

describe("DriftPage", () => {
  it("lists open incidents and resolves one through the API", async () => {
    apiMock.listDriftIncidents.mockResolvedValue({
      schema_version: "runtime.drift_incidents.v1",
      tenant_id: "t1",
      count: 1,
      open_count: 1,
      incidents: [
        {
          incident_id: "inc_1",
          tenant_id: "t1",
          blueprint_id: "developer",
          status: "drift_detected",
          drift_score: 0.8,
          violation_count: 2,
          warning_count: 0,
          top_violations: [
            { tool_name: "run_shell", type: "unauthorized_tool" },
          ],
          first_detected_at: "2026-06-01T00:00:00Z",
          last_detected_at: "2026-06-02T00:00:00Z",
          occurrences: 3,
          resolved: false,
          resolved_at: "",
          resolved_by: "",
          resolution_note: "",
        },
      ],
    });
    apiMock.resolveDriftIncident.mockResolvedValue({ resolved: true });

    render(<DriftPage />);

    await waitFor(() =>
      expect(screen.getByText("developer")).toBeInTheDocument(),
    );
    expect(screen.getByText("run_shell")).toBeInTheDocument();

    const card = screen.getByText("developer").closest("div.rounded-xl");
    expect(card).not.toBeNull();
    fireEvent.click(
      within(card as HTMLElement).getByRole("button", { name: /Resolve/ }),
    );

    await waitFor(() =>
      expect(apiMock.resolveDriftIncident).toHaveBeenCalledWith(
        "inc_1",
        "Resolved from drift cockpit",
      ),
    );
  });
});
