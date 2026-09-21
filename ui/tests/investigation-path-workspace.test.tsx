import { fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { InvestigationPathWorkspace, InvestigationTools } from "@/components/investigation-path-workspace";
import type { RankedPathRow } from "@/components/ranked-path-list";

const rows: RankedPathRow[] = [
  {
    key: "path-a::0",
    selectionKey: "path-a",
    rank: 1,
    title: "Agent to package",
    cve: "CVE-2026-0001",
    riskScore: 9.8,
    nodeCount: 4,
    agents: 1,
  },
  {
    key: "path-b::1",
    selectionKey: "path-b",
    rank: 2,
    title: "Service to identity",
    cve: null,
    riskScore: 8.2,
    nodeCount: 3,
    agents: 0,
  },
];

function Harness() {
  const [selectedKey, setSelectedKey] = useState("path-a");
  return (
    <InvestigationPathWorkspace
      rows={rows}
      selectedKey={selectedKey}
      onSelect={setSelectedKey}
      title="2 ranked paths"
      subtitle="Select a path to focus its graph and evidence."
      filters={<div>Severity and evidence filters</div>}
      detail={<div>{selectedKey === "path-a" ? "Graph for path A" : "Graph for path B"}</div>}
      sideRail={<div>Crown-jewel clusters</div>}
    />
  );
}

function setNarrowViewport(matches: boolean) {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: vi.fn().mockReturnValue({
      matches,
      media: "(max-width: 1023px)",
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }),
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("InvestigationPathWorkspace", () => {
  it("gives a single path the full workspace and keeps filters available on demand", () => {
    render(<InvestigationPathWorkspace rows={rows.slice(0, 1)} selectedKey="path-a" onSelect={vi.fn()}
      title="1 ranked path" subtitle="Selected evidence" filters={<div>Severity filters</div>}
      detail={<div>Selected path evidence</div>} />);
    expect(screen.getByRole("region", { name: "Investigation workspace" })).toHaveAttribute("data-layout", "focused-path");
    expect(screen.getByText("Selected path evidence")).toBeVisible();
    expect(screen.getByText("Severity filters")).not.toBeVisible();
    const summary = screen.getByText("1 path selected · change focus or filters");
    expect(summary.closest("details")).not.toHaveAttribute("open");
    fireEvent.click(summary);
    expect(screen.getByText("Filters & presets")).toBeVisible();
  });

  it("switches mobile panes and returns to the selected path after selection", () => {
    setNarrowViewport(false);
    render(<Harness />);
    const workspace = screen.getByRole("region", { name: "Investigation workspace" });
    expect(workspace).toHaveAttribute("data-mobile-panel", "path");
    fireEvent.click(screen.getByRole("button", { name: "Paths & filters (2)" }));
    expect(workspace).toHaveAttribute("data-mobile-panel", "queue");
    fireEvent.click(screen.getByText("#2").closest("button")!);
    expect(workspace).toHaveAttribute("data-mobile-panel", "path");
    expect(screen.getByRole("button", { name: "Selected path" })).toHaveAttribute("aria-pressed", "true");
  });

  it("keeps the bounded path queue and selected graph detail in one desktop workspace", () => {
    setNarrowViewport(false);
    render(<Harness />);

    const workspace = screen.getByRole("region", { name: "Investigation workspace" });
    expect(workspace).toHaveAttribute("data-layout", "responsive-split");
    expect(within(workspace).getByLabelText("Attack path queue")).toBeInTheDocument();
    expect(within(workspace).getByRole("region", { name: "Selected path detail" })).toHaveTextContent(
      "Graph for path A",
    );
    expect(screen.getByText("#1 fix first").closest("button")).toHaveAttribute(
      "aria-controls",
      "selected-investigation-path",
    );
  });

  it("focuses and announces a selected path without moving the desktop viewport", () => {
    setNarrowViewport(false);
    const scrollIntoView = vi.fn();
    Element.prototype.scrollIntoView = scrollIntoView;
    render(<Harness />);

    fireEvent.click(screen.getByText("#2").closest("button")!);

    expect(screen.getByRole("region", { name: "Selected path detail" })).toHaveTextContent(
      "Graph for path B",
    );
    expect(screen.getByRole("status")).toHaveTextContent("Focused path 2: Service to identity");
    expect(scrollIntoView).not.toHaveBeenCalled();
  });

  it("scrolls the selected detail into view after a mobile path selection", () => {
    setNarrowViewport(true);
    const scrollIntoView = vi.fn();
    Element.prototype.scrollIntoView = scrollIntoView;
    vi.spyOn(window, "requestAnimationFrame").mockImplementation((callback) => {
      callback(0);
      return 1;
    });
    render(<Harness />);

    fireEvent.click(screen.getByText("#2").closest("button")!);

    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: "smooth", block: "start" });
  });

  it("uses arrow keys to focus and announce the next visible path", () => {
    setNarrowViewport(false);
    render(<Harness />);

    fireEvent.keyDown(screen.getByLabelText("Attack path queue"), { key: "ArrowRight" });

    expect(screen.getByRole("region", { name: "Selected path detail" })).toHaveTextContent(
      "Graph for path B",
    );
    expect(screen.getByRole("status")).toHaveTextContent("Focused path 2: Service to identity");
  });

  it("places filters and saved presets behind one compact disclosure", () => {
    setNarrowViewport(false);
    render(<Harness />);

    const summary = screen.getByText("Filters & presets");
    const drawer = summary.closest("details");
    expect(drawer).not.toBeNull();
    expect(drawer).not.toHaveAttribute("open");
    expect(within(drawer!).getByText("Severity and evidence filters")).toBeInTheDocument();
  });
});

describe("InvestigationTools", () => {
  it("keeps secondary tools behind one disclosure and mounts only the selected tool", () => {
    render(<InvestigationTools scope={<div>Snapshot selection</div>} deployment={<div>Deploy check</div>}
      exposure={<div>Exposure query</div>} />);
    expect(screen.getByText("Snapshot selection")).not.toBeVisible();
    expect(screen.queryByText("Deploy check")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText("Investigation tools · snapshots, correlation & checks"));
    expect(screen.getByText("Snapshot selection")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Should I deploy?" }));
    expect(screen.getByText("Deploy check")).toBeVisible();
    expect(screen.queryByText("Snapshot selection")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Exposure paths" }));
    expect(screen.getByText("Exposure query")).toBeVisible();
  });
});
