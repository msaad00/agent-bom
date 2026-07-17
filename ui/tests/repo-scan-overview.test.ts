import { describe, expect, it } from "vitest";

import type { ScanResult } from "@/lib/api-types";
import {
  deriveRepoSurfaceEvidence,
  repoGraphHref,
  resolveProjectInventory,
} from "@/lib/repo-scan-overview";

describe("repo-scan-overview", () => {
  it("resolves nested dependency inventory from API repo scans", () => {
    const result = {
      agents: [],
      blast_radius: [],
      ai_inventory: {
        dependency_inventory: { directories: ["src", "tests"], package_count: 12 },
        secrets: { findings: [{ id: "1" }] },
      },
    } as ScanResult;

    expect(resolveProjectInventory(result)?.package_count).toBe(12);
    const surfaces = deriveRepoSurfaceEvidence(result);
    expect(surfaces.find((s) => s.id === "dependencies")?.state).toBe("found");
    expect(surfaces.find((s) => s.id === "secrets")?.state).toBe("found");
    expect(surfaces.find((s) => s.id === "connectors")).toBeUndefined();
  });

  it("builds a folder-layer graph deep link for the scan", () => {
    expect(repoGraphHref("job-abc")).toContain("scan_id=job-abc");
    expect(repoGraphHref("job-abc")).toContain("directory");
    expect(repoGraphHref("job-abc")).toContain("framework");
  });

  it.each(["findings", "clean", "skipped", "failed"] as const)(
    "preserves the typed SAST %s outcome instead of treating it as no evidence",
    (executionStatus) => {
      const result = {
        agents: [],
        blast_radius: [],
        sast: {
          scanner_driver_id: "sast-semgrep",
          execution_status: executionStatus,
          status_reason: executionStatus === "failed" ? "semgrep_failed" : null,
          status_detail: executionStatus === "failed" ? "SAST execution failed." : null,
          findings: executionStatus === "findings" ? [{ rule_id: "CWE-89" }] : [],
        },
      } as unknown as ScanResult;

      const sast = deriveRepoSurfaceEvidence(result).find((surface) => surface.id === "sast");
      expect(sast?.state).toBe(executionStatus);
      expect(sast?.statusReason).toBe(executionStatus === "failed" ? "semgrep_failed" : undefined);
    },
  );
});
