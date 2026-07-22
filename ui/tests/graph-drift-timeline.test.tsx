import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { GraphDriftTimeline } from "@/components/graph-drift-timeline";

describe("GraphDriftTimeline", () => {
  it("renders adjacent scan pairs with change pills", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(
      <GraphDriftTimeline
        selected={null}
        onSelect={onSelect}
        snapshots={[
          {
            scan_id: "scan-new-aaaaaaaa",
            created_at: "2026-07-02T00:00:00Z",
            diff_baseline_scan_id: "scan-old-bbbbbbbb",
            diff_summary: {
              nodes_added: 2,
              nodes_removed: 1,
              nodes_changed: 0,
              edges_added: 0,
              edges_removed: 0,
            },
          },
          {
            scan_id: "scan-old-bbbbbbbb",
            created_at: "2026-07-01T00:00:00Z",
          },
        ]}
      />,
    );

    expect(screen.getByTestId("graph-drift-timeline")).toHaveTextContent("Drift timeline");
    expect(screen.getByText(/Critical/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /scan-new/i }));
    expect(onSelect).toHaveBeenCalledWith({
      oldScanId: "scan-old-bbbbbbbb",
      newScanId: "scan-new-aaaaaaaa",
    });
  });
});
