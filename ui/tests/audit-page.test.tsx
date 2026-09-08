import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AuditLogPage from "@/app/audit/page";

const { apiMock, authMock } = vi.hoisted(() => ({
  apiMock: { listAuditEntries: vi.fn(), getAuditIntegrity: vi.fn(), getAuthPolicy: vi.fn(), listKeys: vi.fn() },
  authMock: { session: { role: "admin" }, loading: false, hasCapability: vi.fn(() => true) },
}));
vi.mock("@/lib/api", () => ({ api: apiMock, formatDate: (date: string) => date }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => authMock }));
vi.mock("@/components/key-lifecycle-panel", () => ({ KeyLifecyclePanel: () => <div>Key controls</div> }));
vi.mock("@/components/audit-evidence-panel", () => ({ AuditEvidencePanel: () => <div>Export controls</div> }));

const event = {
  entry_id: "receipt-1", action: "gateway.policy.denied", actor: "agent-reviewer", resource: "tool/shell",
  timestamp: "2026-09-08T01:00:00Z", hmac_signature: "signature",
  details: { decision: "denied", before: { allowed: true }, after: { allowed: false }, node_id: "tool:shell", finding_id: "finding-1", scan_id: "scan-1" },
};
beforeEach(() => {
  vi.clearAllMocks();
  authMock.hasCapability.mockReturnValue(true);
  apiMock.listAuditEntries.mockResolvedValue({ entries: [event], total: 1 });
  apiMock.getAuditIntegrity.mockResolvedValue({ verified: 78, checked: 78, tampered: 0 });
  apiMock.getAuthPolicy.mockResolvedValue({});
  apiMock.listKeys.mockResolvedValue({ keys: [] });
});

describe("Audit trail", () => {
  it("leads with events and distinguishes filtered totals from control-plane integrity", async () => {
    render(<AuditLogPage />);
    expect(await screen.findByRole("button", { name: /gateway.policy.denied/ })).toBeVisible();
    expect(screen.getByText("1 matching events")).toBeVisible();
    expect(screen.getByRole("region", { name: "Control-plane integrity" })).toHaveTextContent("78 verified / 78 checked");
    expect(apiMock.getAuditIntegrity).toHaveBeenCalledWith(1000, false);
    expect(screen.getByRole("button", { name: "Export and verify evidence" })).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByRole("button", { name: "Key management and revocation" })).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByText("Key controls")).not.toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Export and verify evidence" }));
    expect(screen.getByText("Export controls")).toBeVisible();
  });

  it("keeps events available when integrity verification fails", async () => {
    apiMock.getAuditIntegrity.mockRejectedValue(new Error("offline"));
    render(<AuditLogPage />);
    expect(await screen.findByRole("button", { name: /gateway.policy.denied/ })).toBeVisible();
    expect(screen.getByText("Integrity unavailable")).toBeVisible();
    expect(screen.queryByText("No integrity exceptions detected")).not.toBeInTheDocument();
  });

  it("expands recorded changes and preserves exact finding and node link semantics", async () => {
    render(<AuditLogPage />);
    const row = await screen.findByRole("button", { name: /gateway.policy.denied/ });
    expect(row).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(row);
    expect(row).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("heading", { name: /before/i })).toBeVisible();
    expect(screen.getByRole("link", { name: /Open finding/ })).toHaveAttribute("href", "/findings?finding=finding-1");
    const graph = new URL(screen.getByRole("link", { name: /Open in security graph/ }).getAttribute("href")!, "http://localhost");
    expect(graph.searchParams.get("node")).toBe("tool:shell");
    expect(graph.searchParams.get("finding")).toBe("finding-1");
    expect(graph.searchParams.has("cve")).toBe(false);
    expect(screen.getByText(/does not provide a per-event verdict/)).toBeVisible();
  });

  it("does not infer an outcome from an event signature", async () => {
    apiMock.listAuditEntries.mockResolvedValue({ entries: [{ ...event, details: {} }], total: 1 });
    render(<AuditLogPage />);
    const row = await screen.findByRole("button", { name: /gateway.policy.denied/ });
    expect(within(row).getByText("Not recorded")).toBeVisible();
  });

  it("sends resource, exact action and time filters together", async () => {
    render(<AuditLogPage />);
    await screen.findByRole("button", { name: /gateway.policy.denied/ });
    fireEvent.change(screen.getByLabelText("Resource prefix"), { target: { value: "tool/" } });
    fireEvent.change(screen.getByLabelText("Action (exact name)"), { target: { value: "gateway.policy.denied" } });
    fireEvent.change(screen.getByLabelText("Time range"), { target: { value: "7" } });
    await waitFor(() => expect(apiMock.listAuditEntries).toHaveBeenLastCalledWith(expect.objectContaining({
      action: "gateway.policy.denied", resource: "tool/", since: expect.stringMatching(/^\d{4}-\d\d-\d\dT/), offset: 0,
    })));
  });

  it("does not fetch or show key management for a reviewer", async () => {
    authMock.hasCapability.mockReturnValue(false);
    render(<AuditLogPage />);
    await screen.findByRole("button", { name: /gateway.policy.denied/ });
    expect(apiMock.listKeys).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Key management and revocation" })).not.toBeInTheDocument();
  });
});
