import { describe, expect, it } from "vitest";

import { REPO_SCAN_SURFACES, repoScanLanguageSummary } from "@/lib/repo-scan-surfaces";

describe("repo-scan-surfaces", () => {
  it("lists the major auto-detect surfaces for public repo scans", () => {
    const ids = REPO_SCAN_SURFACES.map((surface) => surface.id);
    expect(ids).toContain("agent-frameworks");
    expect(ids).toContain("terraform");
    expect(ids).toContain("iac");
    expect(ids).toContain("dependencies");
    expect(ids).toContain("secrets");
    expect(ids).toContain("jupyter");
    expect(ids).toContain("sast");
    expect(ids).toContain("connectors");
  });

  it("summarizes language coverage for the scan form", () => {
    expect(repoScanLanguageSummary()).toMatch(/languages/);
  });
});
