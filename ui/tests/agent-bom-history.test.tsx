import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { AgentBomHistory } from "@/components/agent-bom-history";
import { api, type AgentLifecyclePage } from "@/lib/api";

const page: AgentLifecyclePage = { items: ["one", "two"].map((id) => ({ record_id: id, agent_id: "a", snapshot_id: id, recorded_at: "2026-09-26T12:00:00Z", observed_at: "2026-09-25T12:00:00Z", composition_digest: "same", assurance: "operator_recorded" })), next_offset: null };
afterEach(() => vi.restoreAllMocks());
function open() { fireEvent.click(screen.getByText("Saved BOM history")); }
it("loads on demand and distinguishes evidence refresh from composition drift", async () => {
  const load = vi.spyOn(api, "agentLifecycleHistory").mockResolvedValue(page);
  const compare = vi.spyOn(api, "compareAgentSnapshots").mockResolvedValue({ snapshot_changed: true, composition_changed: false });
  render(<AgentBomHistory jobId="scan" agentId="a" />); open();
  expect(load).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText("Load history"));
  await screen.findByText("one");
  expect(load).toHaveBeenCalledWith("a", 0);
  fireEvent.click(screen.getByText("Compare first two snapshots on this page"));
  await screen.findByText(/Snapshot changed; recorded composition is unchanged/);
  expect(compare).toHaveBeenCalledWith("one", "two");
});
it("captures the exact scan agent then refreshes history", async () => {
  const save = vi.spyOn(api, "captureAgentSnapshot").mockResolvedValue(page.items[0]!);
  vi.spyOn(api, "agentLifecycleHistory").mockResolvedValue(page);
  render(<AgentBomHistory jobId="scan" agentId="a" />); open();
  fireEvent.click(screen.getByText("Save this snapshot"));
  await screen.findByText("one");
  expect(save).toHaveBeenCalledWith("scan", "a");
});
it("shows bounded pagination and generic failures without secrets", async () => {
  const load = vi.spyOn(api, "agentLifecycleHistory").mockResolvedValueOnce({ ...page, next_offset: 20 }).mockRejectedValueOnce(new Error("secret-sentinel"));
  render(<AgentBomHistory jobId="scan" agentId="a" />); open();
  fireEvent.click(screen.getByText("Load history"));
  fireEvent.click(await screen.findByText("Next history page"));
  await waitFor(() => expect(load).toHaveBeenLastCalledWith("a", 20));
  expect(await screen.findByRole("alert")).not.toHaveTextContent("secret-sentinel");
});
