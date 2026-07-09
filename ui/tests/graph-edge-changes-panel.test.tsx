import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GraphEdgeChangesPanel } from "@/components/graph-edge-changes-panel";
import type { GraphEdgeChangesResponse } from "@/lib/api-types";

const sampleChanges: GraphEdgeChangesResponse = {
  scan_id_old: "showcase-baseline",
  scan_id_new: "showcase",
  edges_added: [
    {
      source_id: "user:bob",
      target_id: "role:prod-admin",
      relationship: "trusts",
      direction: "forward",
      weight: 1,
      traversable: true,
      confidence: 1,
      provenance: {},
      evidence: {},
    },
  ],
  edges_removed: [
    {
      source_id: "agent:support-copilot",
      target_id: "server:legacy-chat-server",
      relationship: "uses",
      direction: "forward",
      weight: 1,
      traversable: true,
      confidence: 1,
      provenance: {},
      evidence: {},
    },
  ],
  edges_changed: [],
  edges_unchanged: [],
  summary: { added: 1, removed: 1, changed: 0, unchanged: 0 },
};

describe("GraphEdgeChangesPanel", () => {
  it("renders added and removed edge rows", () => {
    render(
      <GraphEdgeChangesPanel
        changes={sampleChanges}
        loading={false}
        error={null}
        comparedLabel="showcase-base"
      />,
    );
    expect(screen.getByTestId("graph-edge-changes-panel")).toBeInTheDocument();
    expect(screen.getByText(/user:bob → role:prod-admin/)).toBeInTheDocument();
    expect(
      screen.getByText(/agent:support-copilot → server:legacy-chat-server/),
    ).toBeInTheDocument();
  });

  it("shows empty state when no edge lifecycle changes", () => {
    render(
      <GraphEdgeChangesPanel
        changes={{
          ...sampleChanges,
          edges_added: [],
          edges_removed: [],
          summary: { added: 0, removed: 0, changed: 0, unchanged: 10 },
        }}
        loading={false}
        error={null}
      />,
    );
    expect(screen.getByText(/No relationship additions/)).toBeInTheDocument();
  });
});
