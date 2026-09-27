import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GraphSnapshotReceipt } from "@/components/graph-snapshot-receipt";
import type { GraphSnapshot } from "@/lib/api";
const snapshot: GraphSnapshot = { scan_id: "scan/a&b", snapshot_kind: "scan", created_at: "bad-date", node_count: 40, edge_count: 50, risk_summary: {} };

describe("snapshot receipt", () => {
  it("links exact scan scope and distinguishes graph completeness from assessment", () => {
    render(<GraphSnapshotReceipt snapshot={snapshot} />);
    fireEvent.click(screen.getByText("Snapshot evidence"));
    expect(screen.getByRole("link")).toHaveAttribute("href", "/findings?scan=scan%2Fa%26b");
    expect(screen.getByText("Captured: Unavailable")).toBeInTheDocument();
    expect(screen.getByText(/not assessment coverage/)).toBeInTheDocument();
  });
  it("does not fabricate a source-scan link for correlation snapshots", () => {
    render(<GraphSnapshotReceipt snapshot={{ ...snapshot, snapshot_kind: "correlation" }} />);
    fireEvent.click(screen.getByText("Snapshot evidence"));
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
