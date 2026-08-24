import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const source = (path: string) => readFileSync(join(process.cwd(), path), "utf8");

describe("interactive React Flow surface contract", () => {
  it.each([
    "app/graph/graph-page-client.tsx",
    "components/mesh-lens-view.tsx",
    "components/context-lens-view.tsx",
    "components/scan-mesh.tsx",
    "components/attack-flow.tsx",
    "components/security-graph-investigation.tsx",
    "app/agents/page.tsx",
  ])("keeps evidence topology immutable in %s", (path) => {
    expect(source(path)).toContain("deleteKeyCode={null}");
  });

  it.each([
    "components/context-lens-view.tsx",
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

  it("keeps investigation controls interactive without overlaying evidence nodes", () => {
    const content = source("components/security-graph-investigation.tsx");
    expect(content).toContain('data-testid="security-graph-legend-band"');
    expect(content).toContain('data-testid="security-graph-interaction-band"');
    expect(content).not.toContain('className="pointer-events-auto absolute left-3 top-3');
  });

  it("uses the shared renderer decision for broad full-snapshot investigations", () => {
    const content = source("components/security-graph-investigation.tsx");
    expect(content).toContain("decideGraphRenderer");
    expect(content).toContain("<SigmaGraphOverview");
    expect(content).toContain("selectedAttackPath: focusMode");
  });

  it("hosts every graph lens on the canonical investigation route", () => {
    const content = source("app/security-graph/page.tsx");
    expect(content).toContain("<GraphSurface />");
    expect(content).toContain('lens !== "attack-path"');
  });

  it.each([
    "components/agent-topology.tsx",
    "components/scan-pipeline.tsx",
  ])("normalizes edge labels and accessibility text in %s", (path) => {
    const content = source(path);
    expect(content).toContain("readableGraphEdges");
    expect(content).toContain("graphNodeDisplayLabels");
    expect(content).toContain("preserveVisualStyle: true");
  });

  it.each([
    "app/graph/graph-page-client.tsx",
    "components/mesh-lens-view.tsx",
    "components/context-lens-view.tsx",
    "components/scan-mesh.tsx",
    "components/attack-flow.tsx",
    "app/agents/page.tsx",
  ])("does not treat transient auth loading as logout in %s", (path) => {
    const content = source(path);
    expect(content).toContain("ownerActive: Boolean(session)");
    expect(content).not.toContain("ownerActive: !authLoading");
  });

  it("passes a stable owner signal through the investigation flow", () => {
    const content = source("components/security-graph-investigation.tsx");
    expect(content).toContain("ownerActive={Boolean(session)}");
    expect(content).toContain("ownerActive,");
    expect(content).toContain('localMode={session?.recommended_ui_mode === "no_auth"}');
  });

  it("bounds the agent lifecycle canvas inside the application shell", () => {
    const content = source("app/agents/page.tsx");
    expect(content).toContain('className="h-[calc(100dvh-6rem)] w-full');
    expect(content).not.toContain('className="h-screen w-screen');
  });

  it.each([
    "app/graph/graph-page-client.tsx",
    "components/mesh-lens-view.tsx",
    "components/context-lens-view.tsx",
  ])("enables persistence only for an explicit no-auth local session in %s", (path) => {
    expect(source(path)).toContain('localMode: session?.recommended_ui_mode === "no_auth"');
  });
});
