import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TraceExplorerPanel } from "@/components/trace-explorer-panel";
import type { TraceExplorerResponse } from "@/lib/api-types";

const { getTraceExplorer } = vi.hoisted(() => ({ getTraceExplorer: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { getTraceExplorer } }));

function fixture(): TraceExplorerResponse {
  const span = (agent: string, tool: string, verdict = "observed") => ({ span_id: tool, agent, tool, verdict, action_type: "tool_call", linked_findings: [], compliance_controls: [] });
  return { schema_version: "1", tenant_id: "tenant", session_count: 2, span_count: 4, blocked_count: 1, sessions: [
    { session_id: "unrelated", agent: "assistant-extra", blocked_count: 0, observed_count: 1, spans: [span("assistant-extra", "unrelated-tool")] },
    { session_id: "mixed", agent: "Assistant", blocked_count: 1, observed_count: 2, spans: [span("Assistant", "wrong-case-tool"), span("assistant", "exact-tool", "blocked"), span("other", "other-tool")] },
  ] };
}
beforeEach(() => { vi.clearAllMocks(); getTraceExplorer.mockResolvedValue(fixture()); });

describe("trace identity and coverage", () => {
  it("matches exact span identities and never selects unrelated session or actors", async () => {
    render(<TraceExplorerPanel agent="assistant" scanId="scan-1" />);
    await screen.findByRole("button", { name: /exact-tool/ });
    expect(getTraceExplorer).toHaveBeenCalledWith(120);
    expect(screen.queryByText("unrelated-tool")).not.toBeInTheDocument();
    expect(screen.queryByText("wrong-case-tool")).not.toBeInTheDocument();
    expect(screen.queryByText("other-tool")).not.toBeInTheDocument();
    expect(screen.getByText("1 sessions · 1 blocked spans")).toBeVisible();
    expect(screen.getByText(/requests up to 120 records per source/)).toBeVisible();
    expect(screen.getByText(/Scan correlation unavailable/)).toHaveTextContent("scan-1");
  });
  it("drops selected spans when the requested identity changes", async () => {
    const { rerender } = render(<TraceExplorerPanel agent="assistant" />);
    fireEvent.click(await screen.findByRole("button", { name: /exact-tool/ }));
    rerender(<TraceExplorerPanel agent="other" />);
    await screen.findByRole("button", { name: /other-tool/ });
    expect(screen.queryByText("exact-tool")).not.toBeInTheDocument();
    rerender(<TraceExplorerPanel agent="absent" />);
    expect(screen.getByText(/No activity matched this agent/)).toBeVisible();
    expect(screen.queryByText("other-tool")).not.toBeInTheDocument();
  });
  it("does not equate an empty bounded sample with no activity", async () => {
    getTraceExplorer.mockResolvedValue({ ...fixture(), sessions: [] });
    render(<TraceExplorerPanel />);
    expect(await screen.findByText(/No runtime activity records were returned/)).toHaveTextContent("does not prove that no activity occurred");
  });
  it("distinguishes unavailable activity from an empty sample", async () => {
    getTraceExplorer.mockRejectedValue(new Error("temporarily unavailable"));
    render(<TraceExplorerPanel agent="assistant" />);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Activity unavailable"));
    expect(screen.queryByText(/No activity matched/)).not.toBeInTheDocument();
  });
});
