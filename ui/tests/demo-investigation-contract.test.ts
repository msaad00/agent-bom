import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const page = readFileSync(join(process.cwd(), "app/security-graph/page.tsx"), "utf8");

describe("investigation demo hierarchy", () => {
  it("puts the ranked decision workspace before secondary evidence controls", () => {
    const workspace = page.indexOf("<InvestigationPathWorkspace");
    const evidenceScope = page.indexOf('title="Evidence scope"');
    const deployGate = page.indexOf('title="Should I deploy?"');
    const exposureLens = page.indexOf('title="Exposure paths"');

    expect(workspace).toBeGreaterThan(-1);
    expect(evidenceScope).toBeGreaterThan(workspace);
    expect(deployGate).toBeGreaterThan(workspace);
    expect(exposureLens).toBeGreaterThan(workspace);
  });

  it("describes snapshots as supporting evidence instead of the page identity", () => {
    expect(page).toContain("Evidence scope");
    expect(page).toContain("Current scan evidence");
    expect(page).toContain("Manage snapshots");
    expect(page).not.toContain(">Snapshot</p>");
    expect(page).not.toContain("Large estate ·");
  });

  it("does not make the ranked path queue wait for fix-first enrichment", () => {
    expect(page).not.toContain("const [graph, view] = await Promise.all");
    expect(page).toContain("async function loadAttackPaths");
    expect(page).toContain("async function loadFixFirstEnrichment");
    expect(page).toContain("Ranked paths are ready; fix guidance is still loading");
  });

  it("parses a top-path route and focuses the stable Investigation target", () => {
    expect(page).toContain('const requestedPathMode = searchParams.get("path")');
    expect(page).toContain('const requestedPathScanId = searchParams.get("scan")');
    expect(page).toContain('requestedPathMode !== "top" || requestedPathScanId !== selectedScanId');
    expect(page).toContain("setSelectedAttackPathKey(null)");
    expect(page).toContain("focusCorrelationPathTarget(document)");
  });
});
