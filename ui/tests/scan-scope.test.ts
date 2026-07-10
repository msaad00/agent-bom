import { describe, expect, it } from "vitest";

import type { CloudConnectionRecord, ScanRequest } from "@/lib/api";
import {
  adhocScopeChips,
  cloudAccountBoundary,
  cloudConnectionScopeChips,
  cloudRegionScope,
  isScannableConnection,
} from "@/lib/scan-scope";

function awsConnection(overrides: Partial<CloudConnectionRecord> = {}): CloudConnectionRecord {
  return {
    id: "conn-aws-1",
    tenant_id: "default",
    provider: "aws",
    display_name: "Prod AWS",
    role_ref: "arn:aws:iam::123456789012:role/AgentBomReadOnly",
    has_external_id: true,
    regions: ["us-east-1", "us-west-2"],
    status: "active",
    status_detail: "",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    last_scan_at: null,
    last_event_at: null,
    last_scan_id: null,
    scan_interval_minutes: 1440,
    auth_params: {},
    ...overrides,
  };
}

describe("scan-scope", () => {
  it("summarizes cloud account boundary and regions", () => {
    const connection = awsConnection();
    expect(cloudAccountBoundary(connection)).toContain("arn:aws:iam::");
    expect(cloudRegionScope(connection)).toContain("2 regions");
    expect(isScannableConnection(connection)).toBe(true);
  });

  it("builds cloud scope chips with scan type and schedule", () => {
    const chips = cloudConnectionScopeChips(awsConnection());
    expect(chips.find((chip) => chip.label === "Scan type")?.value).toBe("Read-only inventory + CIS");
    expect(chips.find((chip) => chip.label === "Schedule")?.value).toBe("Every 1440 min");
  });

  it("builds ad-hoc scope chips for queued targets and baseline discovery", () => {
    const form: ScanRequest = {
      agent_projects: ["/repo/a"],
      images: ["nginx:1.25"],
      k8s: true,
      k8s_namespace: "prod",
      enrich: true,
    };
    const chips = adhocScopeChips(form, "kubernetes");
    expect(chips.find((chip) => chip.label === "Baseline")?.value).toContain("Local MCP");
    expect(chips.find((chip) => chip.label === "Agent projects")?.value).toBe("1 path");
    expect(chips.find((chip) => chip.label === "Container images")?.value).toBe("1 image");
    expect(chips.find((chip) => chip.label === "Kubernetes")?.value).toBe("Namespace prod");
    expect(chips.find((chip) => chip.label === "Enrichment")?.value).toContain("NVD");
  });

  it("builds repository scope chips for public git URLs", () => {
    const chips = adhocScopeChips(
      { repo_url: "https://github.com/org/repo", enrich: true },
      "repository",
    );
    expect(chips.find((chip) => chip.label === "Repository")?.value).toBe("https://github.com/org/repo");
    expect(chips.find((chip) => chip.label === "Execution")?.value).toContain("Static parse only");
    expect(chips.find((chip) => chip.label === "Auto-detect")?.value).toContain("Terraform");
  });
});
