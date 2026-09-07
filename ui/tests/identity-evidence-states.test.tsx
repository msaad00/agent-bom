import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import IdentityPage from "@/app/identity/page";

const apiMock = vi.hoisted(() => ({
  listIdentities: vi.fn(), listJitGrants: vi.fn(), listConditionalAccessPolicies: vi.fn(),
  getCredentialExpiry: vi.fn(), listAccessReviews: vi.fn(), discoverNonHumanIdentities: vi.fn(), getNhiGovernance: vi.fn(),
}));
vi.mock("@/lib/api", async () => ({ ...await vi.importActual<typeof import("@/lib/api")>("@/lib/api"), api: apiMock }));

function tile(label: string) { return within(screen.getByText(label).closest("div")!.parentElement!); }

beforeEach(() => {
  vi.resetAllMocks();
  apiMock.listIdentities.mockResolvedValue({ identities: [] });
  apiMock.listJitGrants.mockResolvedValue({ grants: [] });
  apiMock.listConditionalAccessPolicies.mockResolvedValue({ policies: [] });
  apiMock.getCredentialExpiry.mockResolvedValue({ status: "ok", evaluated: 0, counts: {}, action_required: [], credentials: [] });
  apiMock.listAccessReviews.mockResolvedValue({ campaigns: [] });
  apiMock.discoverNonHumanIdentities.mockResolvedValue({ count: 0, providers: [{ provider: "okta", status: "disabled", count: 0 }], warnings: [] });
  apiMock.getNhiGovernance.mockResolvedValue({ scan_id: "snapshot-evidence", counts: {}, identities: [] });
});

describe("Identity evidence source states", () => {
  it("does not convert unavailable JIT and policies into zero", async () => {
    apiMock.listJitGrants.mockRejectedValue(new Error("private failure"));
    apiMock.listConditionalAccessPolicies.mockRejectedValue(new Error("private failure"));
    render(<IdentityPage />);
    await screen.findByRole("heading", { name: "Identity" });
    expect(tile("Active JIT grants").getByText("Unavailable")).toBeVisible();
    expect(tile("Conditional policies").getByText("Unavailable")).toBeVisible();
    expect(screen.queryByText("private failure")).not.toBeInTheDocument();
  });
  it("preserves successful sections when managed identity loading fails", async () => {
    apiMock.listIdentities.mockRejectedValue(new Error("private failure"));
    render(<IdentityPage />);
    await screen.findByRole("heading", { name: "Identity" });
    expect(tile("Active identities").getByText("Unavailable")).toBeVisible();
    expect(tile("Active JIT grants").getByText("0")).toBeVisible();
    expect(screen.getByText("Discovered non-human identities")).toBeVisible();
  });
  it("does not call failed discovery disabled or failed reviews empty", async () => {
    apiMock.discoverNonHumanIdentities.mockRejectedValue(new Error("private failure"));
    apiMock.listAccessReviews.mockRejectedValue(new Error("private failure"));
    render(<IdentityPage />);
    await screen.findByText("Identity discovery unavailable");
    expect(screen.queryByText(/NHI discovery is disabled/)).not.toBeInTheDocument();
    expect(screen.queryByText(/No recertification campaigns/)).not.toBeInTheDocument();
    expect(screen.getByText("Access reviews unavailable")).toBeVisible();
  });
  it("shows provider failure instead of claiming discovery is disabled", async () => {
    apiMock.discoverNonHumanIdentities.mockResolvedValue({ count: 0, providers: [{ provider: "okta", status: "error", count: 0 }], warnings: ["Provider unavailable"] });
    render(<IdentityPage />);
    await screen.findByText(/Provider unavailable/);
    expect(screen.queryByText(/NHI discovery is disabled/)).not.toBeInTheDocument();
  });
  it("marks credential expiry unavailable while preserving known empty lists", async () => {
    apiMock.getCredentialExpiry.mockRejectedValue(new Error("private failure"));
    render(<IdentityPage />);
    await screen.findByText("Credential expiry unavailable");
    expect(tile("Active identities").getByText("0")).toBeVisible();
    expect(screen.queryByText("private failure")).not.toBeInTheDocument();
  });
  it("retains explicitly disabled discovery and successful empty counts", async () => {
    render(<IdentityPage />);
    await screen.findByText(/NHI discovery is disabled/);
    expect(tile("Active JIT grants").getByText("0")).toBeVisible();
    expect(screen.queryByText("Identity discovery unavailable")).not.toBeInTheDocument();
  });
  it("labels list-derived counts as a bounded loaded population", async () => {
    render(<IdentityPage />);
    await screen.findByRole("heading", { name: "Identity" });
    expect(screen.getByText(/Counts cover up to 200 loaded records per list/)).toBeVisible();
    expect(apiMock.listIdentities).toHaveBeenCalledWith(true, 200);
    expect(apiMock.listJitGrants).toHaveBeenCalledWith(true, 200);
    expect(apiMock.listConditionalAccessPolicies).toHaveBeenCalledWith(true, 200);
    expect(apiMock.listAccessReviews).toHaveBeenCalledWith(200);
  });
  it("retries failed sources through the visible refresh action", async () => {
    apiMock.listJitGrants.mockRejectedValueOnce(new Error("private failure"))
      .mockResolvedValueOnce({ grants: [{ grant_id: "grant-1", status: "active", agent_id: "billing", allowed_tools: [], expires_at: "2026-09-08T00:00:00Z" }] });
    render(<IdentityPage />);
    await screen.findByText("JIT grants unavailable");
    fireEvent.click(screen.getByRole("button", { name: "Refresh evidence" }));
    await waitFor(() => expect(tile("Active JIT grants").getByText("1")).toBeVisible());
    expect(screen.queryByText("JIT grants unavailable")).not.toBeInTheDocument();
    expect(tile("Active identities").getByText("0")).toBeVisible();
    expect(apiMock.listJitGrants).toHaveBeenCalledTimes(2);
    await waitFor(() => expect(apiMock.getNhiGovernance).toHaveBeenCalledTimes(2));
  });
  it("links graph identities by canonical node and returned snapshot", async () => {
    apiMock.getNhiGovernance.mockResolvedValue({ scan_id: "snapshot-evidence", counts: { total: 1 }, identities: [{ node_id: "identity:billing", label: "Billing service identity", risk_score: 4 }] });
    render(<IdentityPage />);
    const link = await screen.findByRole("link", { name: /Billing service identity/ });
    const url = new URL(link.getAttribute("href")!, "http://localhost");
    expect(url.searchParams.get("scan")).toBe("snapshot-evidence");
    expect(url.searchParams.get("root")).toBe("identity:billing");
    expect(url.searchParams.has("agent")).toBe(false);
    await waitFor(() => expect(apiMock.getNhiGovernance).toHaveBeenCalled());
  });
});
