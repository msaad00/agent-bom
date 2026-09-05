import { fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { InvestigationPathWorkspace } from "@/components/investigation-path-workspace";
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
  it("offers a direct mobile jump to the selected path", () => {
    render(<Harness />);
    expect(screen.getByRole("link", {name: "View selected path"})).toHaveAttribute("href", "#selected-investigation-path");
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
