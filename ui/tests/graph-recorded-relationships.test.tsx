import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { GraphRecordedRelationships, GraphRecordedRelationshipScope } from "@/components/graph-recorded-relationships";
import { api } from "@/lib/api";
import type { GraphIncidentPage } from "@/lib/api-types";
import { ApiError } from "@/lib/api-errors";
import * as bundleExport from "@/lib/graph-investigation-bundle";
vi.mock("@/lib/api", () => ({ api: { getGraphIncidentEdges: vi.fn() } }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ loading: false, session: { tenant_id: "t-1", role: "analyst" } }) }));
const fetchPage = vi.mocked(api.getGraphIncidentEdges);
const generation = "a".repeat(32);
function page(next: string | null = null, missing = false): GraphIncidentPage {
  return {
    scan_id: "s-1", snapshot_generation: generation, node_id: "agent:one", found: true, direction: "both", limit: 24,
    node: { id: "agent:one", entity_type: "agent", label: "Agent One", attributes: {} },
    nodes: missing ? [] : [{ id: "server:opaque-id", entity_type: "server", label: "Recorded server name", attributes: {} }],
    edges: [{ id: "e-1", source: "agent:one", target: "server:opaque-id", relationship: "uses", direction: "directed", evidence: {} }],
    next_cursor: next,
    completeness: { status: missing ? "partial" : "complete", complete: !missing, sampled: false, truncated: false, returned: 1, total: null, scope: "incident_edge_page", missing_endpoint_count: missing ? 1 : 0 },
  } as GraphIncidentPage;
}
beforeEach(() => { fetchPage.mockReset(); });
it("uses recorded labels, retains identifiers and inspects the canonical endpoint", async () => {
  fetchPage.mockResolvedValue(page());
  const inspect = vi.fn();
  render(<GraphRecordedRelationshipScope scanId="s-1" nodeId="agent:one"><GraphRecordedRelationships scanId="s-1" nodeId="agent:one" onInspectNode={inspect} /></GraphRecordedRelationshipScope>);
  const link = await screen.findByRole("button", { name: "Recorded server name" });
  expect(screen.getByText("Outgoing → · Recorded connection")).toBeVisible();
  fireEvent.click(link);
  expect(inspect).toHaveBeenCalledWith("server:opaque-id");
  fireEvent.click(screen.getByText("Canonical identifiers"));
  expect(screen.getByText("server:opaque-id")).toBeVisible();
  expect(screen.getByRole("status")).toHaveTextContent("1 loaded relationships · total unknown");
});
it("loads the next bounded page with the same snapshot generation", async () => {
  fetchPage.mockResolvedValueOnce(page("cursor-next")).mockResolvedValueOnce(page());
  render(<GraphRecordedRelationshipScope scanId="s-1" nodeId="agent:one"><GraphRecordedRelationships scanId="s-1" nodeId="agent:one" /></GraphRecordedRelationshipScope>);
  fireEvent.click(await screen.findByRole("button", { name: "Load more recorded relationships" }));
  await waitFor(() => expect(fetchPage).toHaveBeenCalledTimes(2));
  expect(fetchPage.mock.calls[1]![1]).toMatchObject({ scanId: "s-1", snapshotGeneration: generation, cursor: "cursor-next", direction: "both" });
  await screen.findByText(/End of recorded pages/);
  expect(screen.getByRole("status")).toHaveTextContent("1 loaded relationships");
});
it("retains missing endpoints as canonical IDs without invented labels", async () => {
  fetchPage.mockResolvedValue(page(null, true));
  render(<GraphRecordedRelationshipScope scanId="s-1" nodeId="agent:one"><GraphRecordedRelationships scanId="s-1" nodeId="agent:one" onInspectNode={vi.fn()} /></GraphRecordedRelationshipScope>);
  expect(await screen.findByRole("button", { name: "server:opaque-id" })).toBeVisible();
  expect(screen.getByText(/Some endpoint labels are unavailable/)).toBeVisible();
});
it("discards stale pages and restarts after snapshot replacement", async () => {
  fetchPage.mockResolvedValueOnce(page("cursor-next")).mockRejectedValueOnce(new ApiError("stale", { status: 400, statusText: "Bad Request", url: "/incident", method: "GET" })).mockResolvedValueOnce(page());
  render(<GraphRecordedRelationshipScope scanId="s-1" nodeId="agent:one"><GraphRecordedRelationships scanId="s-1" nodeId="agent:one" /></GraphRecordedRelationshipScope>);
  fireEvent.click(await screen.findByRole("button", { name: "Load more recorded relationships" }));
  await screen.findByRole("alert");
  expect(screen.queryByText("Recorded server name")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Retry relationships" }));
  await screen.findByText("Recorded server name");
  expect(fetchPage.mock.calls[2]![1].snapshotGeneration).toBeUndefined();
});
it("does not treat a failed read as a completed empty neighborhood", async () => {
  fetchPage.mockRejectedValue(new Error("unavailable"));
  render(<GraphRecordedRelationshipScope scanId="s-1" nodeId="agent:one"><GraphRecordedRelationships scanId="s-1" nodeId="agent:one" /></GraphRecordedRelationshipScope>);
  await screen.findByRole("alert");
  expect(screen.queryByText(/End of recorded pages/)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Retry relationships" })).toBeEnabled();
  fireEvent.click(screen.getByText("Export investigation"));
  expect(screen.getByRole("button", { name: "Download investigation JSON" })).toBeDisabled();
});

it("exports only the loaded pinned investigation after a deliberate click", async () => {
  const download = vi.spyOn(bundleExport, "downloadGraphInvestigation").mockImplementation(() => {});
  fetchPage.mockResolvedValue(page("more"));
  render(<GraphRecordedRelationshipScope scanId="s-1" nodeId="agent:one"><GraphRecordedRelationships scanId="s-1" nodeId="agent:one" /></GraphRecordedRelationshipScope>);
  await screen.findByText("Recorded server name");
  expect(download).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText("Export investigation"));
  fireEvent.click(screen.getByRole("button", { name: "Download investigation JSON" }));
  expect(download).toHaveBeenCalledWith(expect.objectContaining({ selection: expect.objectContaining({ scan_id: "s-1", node_id: "agent:one", snapshot_generation: generation }), scope: expect.objectContaining({ more_relationships_available: true }) }));
  expect(fetchPage).toHaveBeenCalledTimes(1);
  download.mockRestore();
});
