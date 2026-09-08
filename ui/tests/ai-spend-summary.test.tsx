import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AiSpendSummary } from "@/components/ai-spend-summary";
import type { OverviewDomain } from "@/lib/api-types";

const domain: OverviewDomain = { label: "AI Spend", href: "/cost", metric: 12.5, metric_label: "USD estimated", status: "ok", detail: { available: true, period: "all_recorded", total_calls: 100, total_cost_usd: 12.5, total_input_tokens: 2000, total_output_tokens: 500, agents: 2, unpriced_calls: 1 } };

describe("AI spend summary", () => {
  it("shows tenant ledger scope and incomplete pricing alongside totals", () => {
    render(<AiSpendSummary domain={domain} loading={false} />);
    const card = screen.getByRole("region", { name: "AI spend & usage" });
    const toggle = within(card).getByRole("button");
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(toggle).toHaveTextContent("$12.50 estimated");
    expect(within(card).queryByText("Recorded tokens")).not.toBeVisible();
    fireEvent.click(toggle);
    expect(within(card).getByText("2,500")).toBeVisible();
    expect(within(card).getByText(/All retained usage/)).toBeVisible();
    expect(within(card).getByText(/Unpriced calls leave spend incomplete/)).toBeVisible();
    expect(within(card).getByRole("link")).toHaveAttribute("href", "/cost");
  });
  it("does not turn missing scope or unavailable storage into zero spend", () => {
    render(<AiSpendSummary domain={{ ...domain, metric: null, detail: { available: false } }} loading={false} />);
    expect(screen.getByRole("status")).toHaveTextContent("Usage scope unavailable");
    expect(screen.queryByText("$0.00")).not.toBeInTheDocument();
  });
  it("shows unavailable money when every call is unpriced", () => {
    render(<AiSpendSummary domain={{ ...domain, detail: { ...domain.detail, unpriced_calls: 100, total_cost_usd: 0 } }} loading={false} />);
    expect(screen.getByRole("status")).toHaveTextContent("Unavailable");
    expect(screen.queryByText("$0.00")).not.toBeInTheDocument();
  });
});
