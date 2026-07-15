import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import CostPage from "@/app/cost/page";

vi.mock("@/hooks/use-deployment-context", () => ({
  useDeploymentContext: () => ({ counts: { services: {} } }),
}));

const { report, anomalies, forecast } = vi.hoisted(() => {
  const row = (
    key: string,
    cost: number,
    calls: number,
    unpriced = 0,
  ) => ({
    key,
    calls,
    input_tokens: calls * 10,
    output_tokens: calls * 4,
    cost_usd: cost,
    unpriced_calls: unpriced,
  });
  return {
    report: {
      schema_version: "1",
      tenant_id: "tenant-a",
      price_model_captured: {},
      total_cost_usd: 12.5,
      total_calls: 100,
      total_input_tokens: 2000,
      total_output_tokens: 500,
      unpriced_calls: 2,
      by_agent: [row("agent-alpha", 8, 60, 1), row("agent-beta", 4.5, 40)],
      by_model: [row("gpt-x", 10, 70)],
      by_provider: [row("openai", 12.5, 100)],
      by_cost_center: [],
      by_owner: [row("owner-jane", 12.5, 100)],
      budget: {
        configured: true,
        owner: "owner-jane",
        mode: "enforce",
        limit_usd: 100,
        spend_usd: 12.5,
        remaining_usd: 87.5,
        exceeded: false,
        utilization: 0.125,
      },
    },
    anomalies: {
      schema_version: "1",
      tenant_id: "tenant-a",
      z_threshold: 3,
      anomaly_count: 0,
      cost_anomalies: [],
      behavior_anomalies: [],
    },
    forecast: {
      schema_version: "1",
      agent: null,
      now: "2026-07-15T00:00:00Z",
      status: "ok",
      current_spend_usd: 12.5,
      budget_limit_usd: 100,
      burn_rate_usd_per_day: 1,
      burn_rate_basis: "trailing_7d",
      projected_period_spend_usd: 30,
      period_start: null,
      period_end: null,
      days_remaining: 30,
      projected_exhaustion_at: null,
    },
  };
});

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      getCostReport: vi.fn().mockResolvedValue(report),
      getCostAnomalies: vi.fn().mockResolvedValue(anomalies),
      getCostForecast: vi.fn().mockResolvedValue(forecast),
    },
  };
});

describe("CostPage (dense restyle)", () => {
  it("renders the KPI strip, budget, and a dense breakdown table", async () => {
    render(<CostPage />);

    const strip = await screen.findByTestId("cost-kpi-strip");
    expect(within(strip).getByText("Total spend")).toBeInTheDocument();
    expect(within(strip).getByText("LLM calls")).toBeInTheDocument();

    // Owner-scoped budget in enforce mode.
    expect(screen.getByText(/owner owner-jane/i)).toBeInTheDocument();
    expect(screen.getByText("enforce")).toBeInTheDocument();

    // Breakdown DataTable defaults to the agent dimension.
    const table = screen.getByTestId("cost-breakdown-table");
    expect(within(table).getByText("agent-alpha")).toBeInTheDocument();
    expect(within(table).getByText("agent-beta")).toBeInTheDocument();
  });

  it("switches breakdown dimension to owner and opens a row drawer", async () => {
    render(<CostPage />);
    await screen.findByTestId("cost-kpi-strip");

    fireEvent.click(screen.getByRole("button", { name: "Owner" }));
    const table = screen.getByTestId("cost-breakdown-table");
    const ownerCell = within(table).getByText("owner-jane");
    expect(ownerCell).toBeInTheDocument();

    fireEvent.click(ownerCell);
    await waitFor(() =>
      expect(screen.getByText("Avg cost / call")).toBeInTheDocument(),
    );
  });
});
