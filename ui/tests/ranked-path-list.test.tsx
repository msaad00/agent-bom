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
    hops: 3,
    agents: 2,
  },
  {
    key: "k2::1",
    selectionKey: "k2",
    rank: 2,
    title: "Agent → API → flask",
    cve: null,
    riskScore: 7.1,
    hops: 2,
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
    // The single DAG renders in the command-center panel, not per row here.
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
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
});
