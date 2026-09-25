import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { OverviewHistory } from "@/components/overview-history";
const getTrends = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({ api: { getTrends } }));
const point = (scope: string, scan: string) => ({ timestamp: "2026-09-24T12:00:00Z", scope_id: scope, scan_id: scan,
  comparison: { status: "comparable", reason: null, new_findings: 3, still_open: 2, no_longer_detected: 1 },
  open_finding_age_days: 4, evidence_age_days: null, age_sample_count: 5, evidence_sample_count: 0 });
beforeEach(() => { getTrends.mockReset(); });
describe("scoped overview history", () => {
  it("loads on expansion and keeps distinct scopes separate", async () => {
    getTrends.mockResolvedValue({data_points: [point("repo-a", "scan-a"), point("repo-b", "scan-b")], count: 2});
    render(<OverviewHistory />); expect(getTrends).not.toHaveBeenCalled();
    await userEvent.click(screen.getByText("Changes over time"));
    await waitFor(() => expect(getTrends).toHaveBeenCalledWith(365, {days: 30}));
    expect(await screen.findByRole("link")).toHaveAttribute("href", "/findings?scan_id=scan-a");
    expect(screen.getByText(/No longer detected does not establish verified remediation/)).toBeVisible();
    await userEvent.selectOptions(screen.getByLabelText("History scan scope"), "repo-b");
    expect(screen.getByRole("link")).toHaveAttribute("href", "/findings?scan_id=scan-b");
  });
  it("shows unavailable comparisons rather than zero for legacy points", async () => {
    getTrends.mockResolvedValue({data_points: [{timestamp: "2026-09-24T12:00:00Z", scan_id: "legacy"}], count: 1});
    render(<OverviewHistory />); await userEvent.click(screen.getByText("Changes over time"));
    expect(await screen.findByText("Comparison metadata unavailable")).toBeVisible();
    expect(screen.getAllByText("No supported observations in this window.")).toHaveLength(2);
    await userEvent.click(screen.getByRole("button", {name: "Age & freshness"}));
    expect(screen.getAllByText("No supported observations in this window.")).toHaveLength(2);
  });
  it("hides old values while a different window loads", async () => {
    getTrends.mockResolvedValueOnce({data_points: [point("repo-a", "scan-a")], count: 1}).mockImplementationOnce(() => new Promise(() => {}));
    render(<OverviewHistory />); await userEvent.click(screen.getByText("Changes over time"));
    await screen.findByRole("link"); await userEvent.selectOptions(screen.getByLabelText("History window"), "7");
    expect(screen.getByText("Loading history…")).toBeVisible(); expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
  it("offers retry when unavailable", async () => {
    getTrends.mockRejectedValue(new Error("offline")); render(<OverviewHistory />);
    await userEvent.click(screen.getByText("Changes over time"));
    expect(await screen.findByText("History unavailable.")).toBeVisible();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    getTrends.mockResolvedValue({ data_points: [point("repo-a", "scan-a")], count: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Retry history" }));
    expect(await screen.findByRole("link")).toHaveAttribute("href", "/findings?scan_id=scan-a");
  });
});
