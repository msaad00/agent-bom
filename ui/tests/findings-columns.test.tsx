import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { FindingsQueueTable } from "@/components/findings-queue";
import type { EnrichedVuln } from "@/lib/findings-view";
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ hasCapability: () => false }) }));
const row: EnrichedVuln = {
  id: "CVE-fixture", severity: "high", summary: "Fixture finding", packages: ["example"], agents: [],
  sources: ["SBOM", "CVE"], detection_source: "SBOM", finding_type: "CVE", advisory_sources: ["OSV"],
  affected_servers: [], exposed_credentials: [], reachable_tools: [], references: [], remediation_items: [],
  fixed_version: "2.0", lifecycle_status: "resolved", last_observed: "2026-09-01T00:00:00Z",
};
function mount() { return render(<FindingsQueueTable vulns={[row]} sortKey="severity" sortDir="desc" handleSort={vi.fn()} suppressed={new Set()} onMarkFP={vi.fn()} selectedId={null} onSelect={vi.fn()} />); }
beforeEach(() => { localStorage.clear(); });
it("groups factual detection, optional dates, and unverified remediation without a pretend Finding sort", () => {
  mount();
  expect(screen.queryByRole("button", { name: "Finding" })).not.toBeInTheDocument();
  expect(screen.getByRole("columnheader", { name: "Detection" })).toBeInTheDocument();
  expect(screen.getByText("Source: SBOM")).toBeInTheDocument();
  expect(screen.getByText("Type: CVE")).toBeInTheDocument();
  expect(screen.queryByText("Source: OSV")).not.toBeInTheDocument();
  expect(screen.getByText("First: Unavailable")).toBeInTheDocument();
  expect(screen.getByText("Upgrade 2.0")).toBeInTheDocument();
  expect(screen.getByText("Reported resolved · verification not provided")).toBeInTheDocument();
});
it("persists only valid column preferences and supports visibility, order and reset", () => {
  const view = mount();
  fireEvent.click(screen.getByText("Columns", { exact: true }));
  fireEvent.click(screen.getByRole("checkbox", { name: "Detection" }));
  expect(screen.queryByRole("columnheader", { name: "Detection" })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Move Observed up" }));
  const before = screen.getAllByRole("columnheader").map(cell => cell.textContent);
  view.unmount(); mount();
  expect(screen.getAllByRole("columnheader").map(cell => cell.textContent)).toEqual(before);
  expect(localStorage.getItem("agent-bom:findings-columns:v1")).not.toContain("CVE-fixture");
  fireEvent.click(screen.getByText("Columns", { exact: true }));
  fireEvent.click(screen.getByRole("button", { name: "Reset view" }));
  expect(screen.getByRole("columnheader", { name: "Detection" })).toBeInTheDocument();
  expect(screen.getAllByRole("columnheader")[0]).toHaveTextContent("Finding");
  expect(screen.getAllByRole("columnheader").at(-1)).toHaveTextContent("Action");
});
it("ignores malformed, unknown and duplicate column storage", () => {
  for (const value of ["not-json", JSON.stringify({version: 1, order: ["unknown"], hidden: []}), JSON.stringify({version: 1, order: ["asset", "asset"], hidden: []})]) {
    localStorage.setItem("agent-bom:findings-columns:v1", value);
    const view = mount();
    expect(within(screen.getByRole("table")).getByRole("columnheader", { name: "Detection" })).toBeInTheDocument();
    view.unmount();
  }
});
it("applies visibility and keyboard-button order to mobile evidence cards", () => {
  vi.stubGlobal("matchMedia", vi.fn(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
  const view = mount();
  try {
    const article = screen.getByRole("article");
    expect(within(article).getByText("Source: SBOM")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Columns", { exact: true }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Detection" }));
    expect(within(article).queryByText("Source: SBOM")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox", { name: "Detection" }));
    fireEvent.click(screen.getByRole("button", { name: "Move Observed up" }));
    expect([...article.querySelectorAll("dt")].map(cell => cell.textContent)).toEqual(["Priority", "Affected asset", "Observed", "Detection", "Remediation"]);
    expect(within(article).getByRole("button", { name: "Open details for CVE-fixture" })).toBeInTheDocument();
    expect(within(article).getByRole("button", { name: "Investigate" })).toBeInTheDocument();
  } finally { view.unmount(); vi.unstubAllGlobals(); }
});
