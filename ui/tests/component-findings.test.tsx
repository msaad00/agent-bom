import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { ComponentFindings } from "@/components/inventory/component-findings";
import { api } from "@/lib/api";
import type { GraphIncidentPage } from "@/lib/api-types";
import { ApiError } from "@/lib/api-errors";
const auth = vi.hoisted(() => ({ session: { tenant_id: "tenant-one", role: "analyst" } as { tenant_id: string; role: string } | null }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ session: auth.session, loading: false }) }));
vi.mock("@/lib/api", async () => ({ ...await vi.importActual<typeof import("@/lib/api")>("@/lib/api"), api: { getGraphIncidentEdges: vi.fn() } }));
const fetchPage = vi.mocked(api.getGraphIncidentEdges);
function page(assetId = "aws:one", next: string | null = null): GraphIncidentPage {
  return { scan_id: "snapshot-one", snapshot_generation: "a".repeat(32), node_id: assetId, found: true, direction: "both", limit: 24,
    node: { id: assetId, label: "shared-library", entity_type: "package", attributes: {} },
    nodes: [{ id: "vuln:one", label: "Linked vulnerability", entity_type: "vulnerability", severity: "high", attributes: {} },
      { id: "vuln:unrelated", label: "Unrelated same-name evidence", entity_type: "vulnerability", attributes: {} }],
    edges: [{ id: "e1", source: assetId, target: "vuln:one", relationship: "vulnerable_to", direction: "directed" }],
    next_cursor: next, completeness: { status: next ? "truncated" : "complete", complete: !next, truncated: Boolean(next), sampled: false, returned: 1, scope: "incident_edge_page", missing_endpoint_count: 0 },
  } as GraphIncidentPage;
}
beforeEach(() => { fetchPage.mockReset(); auth.session = { tenant_id: "tenant-one", role: "analyst" }; });
it("uses exact component scope and excludes unrelated hydrated finding nodes", async () => {
  fetchPage.mockResolvedValue(page());
  render(<ComponentFindings assetId="aws:one" scanId="snapshot-one" />);
  expect(await screen.findByRole("link", { name: "Linked vulnerability" })).toHaveAttribute("href", "/security-graph?lens=estate&node=vuln%3Aone&scan=snapshot-one");
  expect(fetchPage).toHaveBeenCalledWith("aws:one", expect.objectContaining({ scanId: "snapshot-one", direction: "both" }));
  expect(screen.queryByText("Unrelated same-name evidence")).not.toBeInTheDocument();
});
it("requires a snapshot and never broadens a missing scope", () => {
  render(<ComponentFindings assetId="aws:one" scanId="" />);
  expect(screen.getByRole("alert")).toHaveTextContent(/retained scan snapshot/);
  expect(fetchPage).not.toHaveBeenCalled();
});
it("does not request evidence before authentication resolves", () => {
  auth.session = null;
  render(<ComponentFindings assetId="aws:one" scanId="snapshot-one" />);
  expect(fetchPage).not.toHaveBeenCalled();
});
it("continues in the same generation and clears stale evidence on replacement", async () => {
  fetchPage.mockResolvedValueOnce(page("aws:one", "next")).mockRejectedValueOnce(new ApiError("changed", { status: 400, statusText: "Bad Request", url: "/incident", method: "GET" }));
  render(<ComponentFindings assetId="aws:one" scanId="snapshot-one" />);
  fireEvent.click(await screen.findByRole("button", { name: "Load more component relationships" }));
  await screen.findByRole("alert");
  expect(fetchPage.mock.calls[1]![1]).toMatchObject({ cursor: "next", snapshotGeneration: "a".repeat(32) });
  expect(screen.queryByText("Linked vulnerability")).not.toBeInTheDocument();
  expect(screen.queryByText(/End of recorded/)).not.toBeInTheDocument();
});
it("discards the previous tenant's records before requesting the next tenant", async () => {
  fetchPage.mockResolvedValueOnce(page()).mockImplementationOnce(() => new Promise(() => {}));
  const view = render(<ComponentFindings assetId="aws:one" scanId="snapshot-one" />);
  await screen.findByText("Linked vulnerability");
  auth.session = { tenant_id: "tenant-two", role: "analyst" };
  view.rerender(<ComponentFindings assetId="aws:one" scanId="snapshot-one" />);
  expect(screen.queryByText("Linked vulnerability")).not.toBeInTheDocument();
  await waitFor(() => expect(fetchPage).toHaveBeenCalledTimes(2));
});
it("reports missing endpoints rather than claiming clean coverage", async () => {
  const response = page(); response.nodes = []; response.edges = [];
  response.completeness = { ...response.completeness, complete: false, missing_endpoint_count: 1 };
  fetchPage.mockResolvedValue(response);
  render(<ComponentFindings assetId="aws:one" scanId="snapshot-one" />);
  expect(await screen.findByText(/Finding coverage is incomplete/)).toBeVisible();
  expect(screen.getByText(/does not establish a clean component/)).toBeVisible();
});
