import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ScanEvidencePanel, selectableScanAgents } from "@/components/scan-evidence-panel";
import { api, type Agent, type ScanResult } from "@/lib/api";

function agent(id?: string): Agent { return { name: "same", ...(id ? { canonical_id: id, stable_id: id } : {}), agent_type: "custom", mcp_servers: [] }; }
function result(agents = [agent("a"), agent("b")]): ScanResult { return { agents, blast_radius: [], generated_at: "2026-09-26T00:00:00Z", scan_run: { outcome: "partial", requested_scope_count: 3, complete_scope_count: 2, incomplete_scope_count: 1 } }; }
function open() { fireEvent.click(screen.getByText(/Evidence & agent BOM/)); }

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("scan evidence and BOM journey", () => {
  it("excludes ambiguous and conflicting IDs even when another record looks valid", () => {
    expect(selectableScanAgents([agent("a"), agent("a"), agent(), { ...agent("b"), stable_id: "c" }, agent("c"), agent("d")])).toEqual([{ id: "d", name: "same" }]);
  });
  it("selects exact same-name identity, preserves scope gaps, and downloads on demand", async () => {
    const download = vi.spyOn(api, "downloadScanAgentBom").mockResolvedValue(new Blob(["{}"]));
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: vi.fn(() => "blob:test"), revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    render(<ScanEvidencePanel jobId="job-a" result={result()} />);
    open();
    expect(screen.getByText("2 of 3 requested scopes complete · 1 incomplete")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download agent BOM" })).toBeDisabled();
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "b" } });
    fireEvent.click(screen.getByRole("button", { name: "Download agent BOM" }));
    await waitFor(() => expect(click).toHaveBeenCalledOnce());
    expect(download).toHaveBeenCalledWith("job-a", "b");
  });
  it("keeps an unavailable denominator unknown instead of showing complete coverage", () => {
    render(<ScanEvidencePanel jobId="job-a" result={{ ...result(), scan_run: undefined }} />);
    open();
    expect(screen.getByText("Collection coverage unknown")).toBeInTheDocument();
    expect(screen.getByText("Scope denominator unavailable or inconsistent")).toBeInTheDocument();
  });
  it("bounds rendered options while allowing exact ID filtering", () => {
    render(<ScanEvidencePanel jobId="job-a" result={result(Array.from({ length: 1000 }, (_, i) => agent(`id-${i}`)))} />);
    open();
    expect(screen.getAllByRole("option")).toHaveLength(51);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "id-999" } });
    expect(screen.getAllByRole("option")).toHaveLength(2);
    expect(screen.getByRole("option", { name: "same · id-999" })).toBeInTheDocument();
  });
  it("does not expose server exception content in failed export feedback", async () => {
    vi.spyOn(api, "downloadScanAgentBom").mockRejectedValue(new Error("secret-sentinel"));
    render(<ScanEvidencePanel jobId="job-a" result={result([agent("a")])} />);
    open();
    fireEvent.click(screen.getByRole("button", { name: "Download agent BOM" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("BOM export unavailable");
    expect(screen.queryByText(/secret-sentinel/)).not.toBeInTheDocument();
  });
  it("discards a pending export when navigating to another scan", async () => {
    let finish!: (value: Blob) => void;
    vi.spyOn(api, "downloadScanAgentBom").mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    const create = vi.fn();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: create }));
    const view = render(<ScanEvidencePanel jobId="job-a" result={result([agent("a")])} />);
    open();
    fireEvent.click(screen.getByRole("button", { name: "Download agent BOM" }));
    view.rerender(<ScanEvidencePanel jobId="job-b" result={result([agent("b")])} />);
    finish(new Blob(["{}"])) ;
    await waitFor(() => expect(screen.getByRole("button", { name: "Download agent BOM" })).toBeEnabled());
    expect(create).not.toHaveBeenCalled();
  });
});
