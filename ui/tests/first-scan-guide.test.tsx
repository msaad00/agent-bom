import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FirstScanGuide } from "@/components/first-scan-guide";

const auth = vi.hoisted(() => ({ loading: false, hasCapability: vi.fn() }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => auth }));

describe("first scan guidance", () => {
  beforeEach(() => { auth.loading = false; auth.hasCapability.mockReturnValue(true); });

  it("links permitted operators to explicit scan targets", () => {
    render(<FirstScanGuide onImport={vi.fn()} />);
    expect(screen.getByRole("link", { name: "Choose a scan target" })).toHaveAttribute("href", "/scan");
    expect(auth.hasCapability).toHaveBeenCalledWith("scan.run");
    expect(screen.getByText(/does not upload it to the control plane/)).toBeVisible();
  });

  it.each([true, false])("withholds scan actions while access is pending or denied (%s)", (pending) => {
    auth.loading = pending;
    auth.hasCapability.mockReturnValue(false);
    render(<FirstScanGuide onImport={vi.fn()} />);
    expect(screen.queryByRole("link", { name: "Choose a scan target" })).not.toBeInTheDocument();
    expect(screen.getByText(pending ? "Checking scan access…" : /Ask an administrator for scan access/)).toBeVisible();
  });

  it("previews a validated local report without a network write", async () => {
    const onImport = vi.fn();
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    render(<FirstScanGuide onImport={onImport} />);
    const report = { agents: [], blast_radius: [], scan_timestamp: "2026-09-29T00:00:00Z" };
    fireEvent.change(screen.getByLabelText("Choose report.json"), { target: { files: [new File([JSON.stringify(report)], "report.json", { type: "application/json" })] } });
    await waitFor(() => expect(onImport).toHaveBeenCalledWith(report));
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("rejects an invalid report before handing it to the dashboard", async () => {
    const onImport = vi.fn();
    render(<FirstScanGuide onImport={onImport} />);
    fireEvent.change(screen.getByLabelText("Choose report.json"), { target: { files: [new File(["not json"], "report.json")] } });
    await waitFor(() => expect(screen.getByRole("alert")).toBeVisible());
    expect(onImport).not.toHaveBeenCalled();
  });
});
