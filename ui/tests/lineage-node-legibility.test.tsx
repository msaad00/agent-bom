import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render, screen } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { lineageNodeTypes } from "@/components/lineage-nodes";

const source = readFileSync(
  resolve(__dirname, "../components/lineage-nodes.tsx"),
  "utf8",
);

describe("lineage node labels", () => {
  it.each([
    { entityType: "application", nodeType: "container" as const, badge: "Application" },
    { entityType: "container", nodeType: "container" as const, badge: "Container" },
    { entityType: "package", nodeType: "package" as const, badge: "Package" },
    { entityType: undefined, nodeType: "container" as const, badge: "Container" },
  ])("labels $entityType as $badge without changing its renderer", ({ entityType, nodeType, badge }) => {
    const Renderer = nodeType === "package" ? lineageNodeTypes.packageNode : lineageNodeTypes.containerNode;
    render(
      <ReactFlowProvider>
        <Renderer data={{ label: "inventory item", entityType, nodeType }} />
      </ReactFlowProvider>,
    );
    expect(screen.getByText(badge, { exact: true })).toBeVisible();
    if (entityType === "application") {
      expect(screen.queryByText("Container", { exact: true })).not.toBeInTheDocument();
    }
  });

  it("wraps long asset names instead of clipping them to one line", () => {
    // Estate names are long by nature -- GCS_SERVICE_ACCOUNT_JSON,
    // data: customer-pii-prod. Clipped to a single 180px line they render as
    // "GCS_SERVICE_ACC..." and the node stops identifying anything. The grid
    // has vertical slack and no horizontal slack, so the label takes a second
    // line rather than a wider node.
    // Neither the detailed node nor the rolled-up summary node may clip.
    expect(source).not.toMatch(/flex-1 truncate/);
    expect(source.match(/line-clamp-2/g)?.length ?? 0).toBeGreaterThanOrEqual(2);
  });
});
