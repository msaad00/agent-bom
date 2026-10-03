import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { ComponentCompliance } from "@/components/inventory/component-compliance";
import { api } from "@/lib/api";
import type { GraphIncidentPage } from "@/lib/api-types";
import { ApiError } from "@/lib/api-errors";
const auth = vi.hoisted(() => ({ session: { tenant_id: "one" } as { tenant_id: string } | null }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ session: auth.session, loading: false }) }));
vi.mock("@/lib/api", async () => ({ ...await vi.importActual<typeof import("@/lib/api")>("@/lib/api"), api: { getGraphIncidentEdges: vi.fn() } }));
const fetchPage = vi.mocked(api.getGraphIncidentEdges);
function page(next: string | null = null): GraphIncidentPage {
  return { scan_id: "retained", snapshot_generation: "a".repeat(32), node_id: "asset", found: true, direction: "both", limit: 24,
    node: { id: "asset", label: "shared-name", entity_type: "package", attributes: {}, compliance_tags: [] },
    nodes: [{ id: "check", label: "Recorded check", entity_type: "misconfiguration", compliance_tags: ["CIS-1.1"],
      attributes: { check_id: "1.1", evaluation_status: "fail", evaluation_scope: "resource" } }],
    edges: [{ source: "check", target: "asset", relationship: "affects" }], next_cursor: next,
    completeness: { status: next ? "truncated" : "complete", complete: !next, truncated: Boolean(next), sampled: false, returned: 1 },
  } as unknown as GraphIncidentPage;
}
beforeEach(() => { fetchPage.mockReset(); auth.session = { tenant_id: "one" }; });
it("reads exact snapshot control evidence and exposes missing supporting detail", async () => {
  fetchPage.mockResolvedValue(page());
  render(<ComponentCompliance assetId="asset" scanId="retained" />);
  expect(await screen.findByText("Recorded failed check")).toBeVisible();
  expect(fetchPage).toHaveBeenCalledWith("asset", expect.objectContaining({ scanId: "retained" }));
  expect(screen.getByRole("link", { name: "Recorded check" })).toHaveAttribute("href", "/security-graph?lens=estate&node=check&scan=retained");
  fireEvent.click(screen.getByText("Supporting evidence"));
  expect(screen.getByText("Supporting check detail was not recorded.")).toBeVisible();
});
it("does not fall back to global compliance for missing scope", () => {
  render(<ComponentCompliance assetId="asset" scanId="" />);
  expect(screen.getByRole("alert")).toHaveTextContent("retained scan snapshot");
  expect(fetchPage).not.toHaveBeenCalled();
});
it("clears check results when a paginated snapshot is replaced", async () => {
  fetchPage.mockResolvedValueOnce(page("next")).mockRejectedValueOnce(new ApiError("changed", { status: 400, statusText: "Bad Request", url: "/incident", method: "GET" }));
  render(<ComponentCompliance assetId="asset" scanId="retained" />);
  fireEvent.click(await screen.findByRole("button", { name: "Load more control evidence" }));
  await screen.findByRole("alert");
  expect(fetchPage.mock.calls[1]![1]).toMatchObject({ snapshotGeneration: "a".repeat(32), cursor: "next" });
  expect(screen.queryByText("Recorded failed check")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Download control evidence" })).toBeDisabled();
});
it("clears the prior tenant's evidence immediately on scope change", async () => {
  fetchPage.mockResolvedValueOnce(page()).mockImplementationOnce(() => new Promise(() => {}));
  const view = render(<ComponentCompliance assetId="asset" scanId="retained" />);
  await screen.findByText("Recorded failed check");
  auth.session = { tenant_id: "two" };
  view.rerender(<ComponentCompliance assetId="asset" scanId="retained" />);
  expect(screen.queryByText("Recorded failed check")).not.toBeInTheDocument();
  await waitFor(() => expect(fetchPage).toHaveBeenCalledTimes(2));
});
