import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { GraphScenarioAuthoring } from "@/components/graph-scenario-comparison";
import { ApiConflictError } from "@/lib/api";

const { createGraphScenario, updateGraphScenario } = vi.hoisted(() => ({
  createGraphScenario: vi.fn(),
  updateGraphScenario: vi.fn(),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: { ...actual.api, createGraphScenario, updateGraphScenario },
  };
});

const savedScenario = {
  scenario_id: "scenario-1",
  tenant_id: "tenant-1",
  name: "Private endpoint",
  description: "",
  base_scan_id: "scan-1",
  assumptions: [],
  changes: [],
  revision: 3,
  created_by: "analyst@example.com",
  created_at: "2026-08-25T00:00:00Z",
  updated_at: "2026-08-25T00:00:00Z",
};

describe("GraphScenarioAuthoring", () => {
  beforeEach(() => {
    createGraphScenario.mockReset();
    updateGraphScenario.mockReset();
  });

  it("creates a typed snapshot-pinned scenario without a raw JSON editor", async () => {
    createGraphScenario.mockResolvedValue({ schema: "graph.scenarios.v1", scenario: savedScenario });
    const onSaved = vi.fn();
    render(<GraphScenarioAuthoring scanId="scan-1" scenario={null} session={null} canWrite onSaved={onSaved} />);

    fireEvent.click(screen.getByText("Design a proposed scenario"));
    fireEvent.change(screen.getByLabelText("Scenario name"), { target: { value: "Private endpoint" } });
    fireEvent.change(screen.getByLabelText("Change 1 node id"), { target: { value: "resource:vpce-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Create scenario" }));

    await waitFor(() => expect(createGraphScenario).toHaveBeenCalledOnce());
    expect(createGraphScenario.mock.calls[0]?.[0]).toMatchObject({
      name: "Private endpoint",
      base_scan_id: "scan-1",
      changes: [{
        kind: "add_node",
        key: "resource:vpce-1",
        entity_type: "cloud_resource",
        label: "resource:vpce-1",
        presentation: {},
      }],
    });
    expect(onSaved).toHaveBeenCalledWith(savedScenario);
  });

  it("turns a stale optimistic revision into a safe refresh instruction", async () => {
    updateGraphScenario.mockRejectedValue(
      new ApiConflictError("stale revision details", {
        status: 409,
        statusText: "Conflict",
        url: "/v1/graph/scenarios/scenario-1",
        method: "PUT",
      }),
    );
    render(<GraphScenarioAuthoring scanId="scan-1" scenario={savedScenario} session={null} canWrite onSaved={vi.fn()} />);

    fireEvent.click(screen.getByText("Add a proposed change"));
    fireEvent.change(screen.getByLabelText("Change 1 node id"), { target: { value: "resource:new" } });
    fireEvent.click(screen.getByRole("button", { name: "Save new revision" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "This scenario changed after it was opened. Refresh it before saving again.",
    );
    expect(screen.queryByText("stale revision details")).not.toBeInTheDocument();
  });

  it("round-trips untouched operations while removing and editing selected changes", async () => {
    const editable = {
      ...savedScenario,
      changes: [
        {
          kind: "add_node" as const,
          key: "private-endpoint",
          entity_type: "cloud_resource",
          label: "Private endpoint",
          presentation: { x: 20, y: 40 },
        },
        {
          kind: "remove_edge" as const,
          source: "resource:public-api",
          target: "resource:database",
          relationship: "can_access",
        },
      ],
    };
    updateGraphScenario.mockResolvedValue({ schema: "graph.scenarios.v1", scenario: editable });
    render(<GraphScenarioAuthoring scanId="scan-1" scenario={editable} session={null} canWrite onSaved={vi.fn()} />);

    fireEvent.click(screen.getByText("Add a proposed change"));
    fireEvent.click(screen.getAllByRole("button", { name: "Remove change" })[1]!);
    fireEvent.change(screen.getByLabelText("Change 1 node label"), {
      target: { value: "Private service endpoint" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save new revision" }));

    await waitFor(() => expect(updateGraphScenario).toHaveBeenCalledOnce());
    expect(updateGraphScenario.mock.calls[0]?.[1]).toMatchObject({
      expected_revision: 3,
      changes: [
        {
          kind: "add_node",
          key: "private-endpoint",
          entity_type: "cloud_resource",
          label: "Private service endpoint",
        },
      ],
    });
  });
});
