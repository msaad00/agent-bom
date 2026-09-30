import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import TracesPage from "@/app/traces/page";

const { ingestTraces, auth } = vi.hoisted(() => ({ ingestTraces: vi.fn(), auth: { session: { tenant_id: "tenant-a" } } }));
vi.mock("@/lib/api", () => ({ api: { ingestTraces } }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => auth }));
vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams() }));
vi.mock("@/hooks/use-deployment-context", () => ({ useDeploymentContext: () => ({ counts: { has_traces: true } }) }));
vi.mock("@/components/trace-explorer-panel", () => ({ TraceExplorerPanel: () => null }));
vi.mock("@/components/hitl-approval-queue-panel", () => ({ HitlApprovalQueuePanel: () => null }));

beforeEach(() => { vi.clearAllMocks(); auth.session = { tenant_id: "tenant-a" }; ingestTraces.mockResolvedValue({ traces: 0, flagged: [] }); });

function intake() {
  const view = render(<TracesPage />);
  fireEvent.click(screen.getByRole("button", { name: "OTLP ingest" }));
  return view;
}

describe("trace intake evidence boundary", () => {
  it("discards late results when the authenticated tenant changes", async () => {
    let resolve!: (value: { traces: number; flagged: [] }) => void;
    ingestTraces.mockImplementation(() => new Promise((done) => { resolve = done; }));
    const { rerender } = intake();
    fireEvent.click(screen.getByRole("button", { name: "Run correlation" }));
    auth.session = { tenant_id: "tenant-b" };
    rerender(<TracesPage />);
    fireEvent.click(screen.getByRole("button", { name: "OTLP ingest" }));
    await act(async () => resolve({ traces: 77, flagged: [] }));
    expect(screen.queryByText("77")).not.toBeInTheDocument();
  });
  it("does not present zero parsed tool calls as a clean result", async () => {
    intake();
    fireEvent.click(screen.getByRole("button", { name: "Run correlation" }));
    expect(await screen.findByText(/No tool-call evidence was parsed/)).toBeVisible();
    expect(screen.queryByText("No vulnerable tool calls were flagged in this payload.")).not.toBeInTheDocument();
  });

  it("clears the previous result when the payload changes", async () => {
    ingestTraces.mockResolvedValue({ traces: 4, flagged: [] });
    intake();
    fireEvent.click(screen.getByRole("button", { name: "Run correlation" }));
    await screen.findByText("4");
    fireEvent.change(screen.getByRole("textbox"), { target: { value: '{"spans": []}' } });
    expect(screen.queryByText("4")).not.toBeInTheDocument();
    expect(screen.getByText("No trace run yet.")).toBeVisible();
  });

  it("ignores a late result after the input is replaced", async () => {
    let resolve!: (value: { traces: number; flagged: [] }) => void;
    ingestTraces.mockImplementation(() => new Promise((done) => { resolve = done; }));
    intake();
    fireEvent.click(screen.getByRole("button", { name: "Run correlation" }));
    fireEvent.change(screen.getByRole("textbox"), { target: { value: '{"spans": []}' } });
    await act(async () => resolve({ traces: 99, flagged: [] }));
    expect(screen.queryByText("99")).not.toBeInTheDocument();
    expect(screen.getByText("No trace run yet.")).toBeVisible();
  });

  it.each(['{"private-secret": broken}', '[]', '{"resourceSpans": [null]}'])("rejects malformed input locally without echoing its contents (%s)", async (payload) => {
    intake();
    fireEvent.change(screen.getByRole("textbox"), { target: { value: payload } });
    fireEvent.click(screen.getByRole("button", { name: "Run correlation" }));
    expect(await screen.findByRole("alert")).not.toHaveTextContent("private-secret");
    expect(ingestTraces).not.toHaveBeenCalled();
  });

  it("rejects oversized files before reading them", () => {
    const read = vi.spyOn(FileReader.prototype, "readAsText");
    const { container } = intake();
    const file = new File(["{}"], "large.json", { type: "application/json" });
    Object.defineProperty(file, "size", { value: 10 * 1024 * 1024 + 1 });
    fireEvent.change(container.querySelector('input[type="file"]')!, { target: { files: [file] } });
    expect(screen.getByRole("alert")).toHaveTextContent("10 MB");
    expect(read).not.toHaveBeenCalled();
    read.mockRestore();
  });

  it("keeps server errors generic and permits a retry", async () => {
    ingestTraces.mockRejectedValueOnce(new Error("credential=private-secret"));
    intake();
    fireEvent.click(screen.getByRole("button", { name: "Run correlation" }));
    expect(await screen.findByRole("alert")).not.toHaveTextContent("private-secret");
    await waitFor(() => expect(screen.getByRole("button", { name: "Run correlation" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Run correlation" }));
    await screen.findByText(/No tool-call evidence was parsed/);
    expect(ingestTraces).toHaveBeenCalledTimes(2);
  });
});
