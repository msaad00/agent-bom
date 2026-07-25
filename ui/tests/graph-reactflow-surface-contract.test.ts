import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const source = (path: string) => readFileSync(join(process.cwd(), path), "utf8");

describe("interactive React Flow surface contract", () => {
  it.each([
    "app/graph/graph-page-client.tsx",
    "app/mesh/page.tsx",
    "app/context/page.tsx",
    "components/scan-mesh.tsx",
    "components/attack-flow.tsx",
    "components/security-graph-investigation.tsx",
    "app/agents/page.tsx",
  ])("keeps evidence topology immutable in %s", (path) => {
    expect(source(path)).toContain("deleteKeyCode={null}");
  });

  it.each([
    "app/context/page.tsx",
    "components/scan-mesh.tsx",
    "components/attack-flow.tsx",
    "app/agents/page.tsx",
  ])("persists personal node positions and viewport in %s", (path) => {
    const content = source(path);
    expect(content).toContain("useGraphPresentation");
    expect(content).toContain("defaultViewport={presentation.viewport}");
    expect(content).toContain("nodesDraggable=");
    expect(content).toContain("presentation.editing");
    expect(content).toContain("onNodesChange={presentation.onNodesChange}");
    expect(content).toContain("onMoveEnd={presentation.onMoveEnd}");
  });

  it("keeps the investigation legend interactive", () => {
    expect(source("components/security-graph-investigation.tsx")).toContain(
      'className="pointer-events-auto absolute left-3 top-3',
    );
  });
});
