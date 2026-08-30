import { render, screen, fireEvent, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { RankedPathList, type RankedPathRow } from "@/components/ranked-path-list";

const rows: RankedPathRow[] = [
  {
    key: "k1::0",
    selectionKey: "k1",
    rank: 1,
    title: "Agent → Database → werkzeug",
    cve: "CVE-2026-0002",
    riskScore: 9.6,
    nodeCount: 4,
    agents: 2,
    roleChain: "agent → server → package → finding",
  },
  {
    key: "k2::1",
    selectionKey: "k2",
    rank: 2,
    title: "Agent → API → flask",
    cve: null,
    riskScore: 7.1,
    nodeCount: 3,
    agents: 1,
  },
];

describe("RankedPathList", () => {
  it("renders one compact row per path and never a per-row DAG", () => {
    render(<RankedPathList rows={rows} selectedKey="k1" onSelect={vi.fn()} />);

    expect(screen.getByText("#1 fix first")).toBeInTheDocument();
    expect(screen.getByText("#2")).toBeInTheDocument();
    expect(screen.getByText(/CVE-2026-0002/)).toBeInTheDocument();
    expect(screen.getByText(/3 hops · 2 agents/)).toBeInTheDocument();
    expect(screen.getByText("agent → server → package → finding")).toBeInTheDocument();
    // The single DAG renders in the command-center panel, not per row here.
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("labels a single-node risk signal as one node instead of zero hops", () => {
    render(
      <RankedPathList
        rows={[{ ...rows[0]!, key: "single::0", selectionKey: "single", nodeCount: 1 }]}
        selectedKey="single"
        onSelect={vi.fn()}
      />,
    );

    expect(screen.getByText(/1 node · 2 agents/)).toBeInTheDocument();
    expect(screen.queryByText(/0 hops/)).not.toBeInTheDocument();
  });

  it("selects a path into the shared panel when a collapsed row is clicked", () => {
    const onSelect = vi.fn();
    render(<RankedPathList rows={rows} selectedKey="k1" onSelect={onSelect} />);

    fireEvent.click(screen.getByText("#2").closest("button")!);
    expect(onSelect).toHaveBeenCalledWith("k2");
  });

  it("marks exactly the selected row active (expanded) and leaves the rest collapsed", () => {
    render(<RankedPathList rows={rows} selectedKey="k2" onSelect={vi.fn()} />);

    const active = screen
      .getAllByRole("button")
      .filter((button) => button.getAttribute("aria-pressed") === "true");
    expect(active).toHaveLength(1);
    expect(within(active[0]!).getByText("#2")).toBeInTheDocument();
  });

  it("bounds long path titles while preserving their full value in a tooltip", () => {
    render(<RankedPathList rows={rows} selectedKey="k1" onSelect={vi.fn()} />);

    expect(screen.getByTestId("ranked-path-advisory")).toHaveTextContent("CVE-2026-0002");
    const title = screen.getByText("Agent → Database → werkzeug");
    expect(title).toHaveClass("line-clamp-2", "break-normal");
    expect(title).not.toHaveClass("break-words");
    expect(title).toHaveAttribute("title", "CVE-2026-0002 · Agent → Database → werkzeug");
    expect(title.closest("button")).toHaveClass("grid");
  });

  it("does not repeat a CVE prefix already present in the path title", () => {
    render(
      <RankedPathList
        rows={[
          {
            ...rows[0]!,
            title: "CVE-2026-0002 via Agent → Database → werkzeug",
          },
        ]}
        selectedKey="k1"
        onSelect={vi.fn()}
      />,
    );

    expect(screen.getByTestId("ranked-path-advisory")).toHaveTextContent("CVE-2026-0002");
    const title = screen.getByText("via Agent → Database → werkzeug");
    expect(title).toHaveAttribute(
      "title",
      "CVE-2026-0002 · via Agent → Database → werkzeug",
    );
  });
});
