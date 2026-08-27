import { describe, expect, it } from "vitest";

import type { ComplianceControl, ComplianceResponse } from "@/lib/api";
import {
  complianceFrameworkSummaries,
  compliancePassRate,
  controlMatchesQuery,
} from "@/lib/compliance-frameworks";
import overlayPayload from "./fixtures/compliance-overlay-response.json";

function sampleControl(overrides: Partial<ComplianceControl> = {}): ComplianceControl {
  return {
    code: "LLM01",
    name: "Prompt Injection",
    findings: 0,
    status: "pass",
    severity_breakdown: {},
    affected_packages: [],
    affected_agents: [],
    ...overrides,
  };
}

function sampleCompliance(overrides: Partial<ComplianceResponse> = {}): ComplianceResponse {
  return {
    overall_score: 32,
    overall_status: "fail",
    evaluated_controls: 25,
    total_controls: 931,
    coverage_pct: 2.69,
    scan_count: 1,
    latest_scan: "2026-07-09T22:45:07Z",
    has_mcp_context: true,
    framework_kinds: overlayPayload.framework_kinds as ComplianceResponse["framework_kinds"],
    summary: {
      ...overlayPayload.summary,
      // ATLAS is an applicability overlay (#4709): the API reports which
      // techniques the evidence puts in play, never pass/fail. This fixture
      // asserted the scored form long after the server stopped sending it,
      // which is why a page rendering NaN kept a green suite.
      atlas_applicable: 40,
      atlas_not_applicable: 25,
      nist_pass: 2,
      nist_warn: 0,
      nist_fail: 12,
      eu_ai_act_pass: 0,
      eu_ai_act_warn: 0,
      eu_ai_act_fail: 6,
      nist_csf_pass: 0,
      nist_csf_warn: 0,
      nist_csf_fail: 14,
      iso_27001_pass: 0,
      iso_27001_warn: 0,
      iso_27001_fail: 20,
      soc2_pass: 0,
      soc2_warn: 0,
      soc2_fail: 18,
      cis_pass: 0,
      cis_warn: 0,
      cis_fail: 16,
      cmmc_pass: 0,
      cmmc_warn: 0,
      cmmc_fail: 22,
      nist_800_53_pass: 0,
      nist_800_53_warn: 0,
      nist_800_53_fail: 0,
      fedramp_pass: 0,
      fedramp_warn: 0,
      fedramp_fail: 0,
      pci_dss_pass: 0,
      pci_dss_warn: 0,
      pci_dss_fail: 0,
      aisvs_pass: 0,
      aisvs_fail: 0,
      aisvs_error: 0,
      aisvs_not_applicable: 0,
    },
    owasp_llm_top10: Array.from({ length: 10 }, () => sampleControl()),
    owasp_mcp_top10: Array.from({ length: 10 }, () => sampleControl()),
    mitre_atlas: Array.from({ length: 65 }, (_, index) =>
      sampleControl({ code: `AML.T${index}`, status: index < 25 ? "pass" : "fail" }),
    ),
    nist_ai_rmf: Array.from({ length: 14 }, () => sampleControl()),
    owasp_agentic_top10: Array.from({ length: 10 }, () => sampleControl()),
    eu_ai_act: Array.from({ length: 6 }, () => sampleControl({ status: "fail" })),
    nist_csf: Array.from({ length: 14 }, () => sampleControl({ status: "fail" })),
    iso_27001: [],
    soc2: [],
    cis_controls: [],
    cmmc: [],
    nist_800_53: [],
    fedramp: [],
    pci_dss: [],
    aisvs_benchmark: {
      framework: "aisvs",
      framework_key: "aisvs_benchmark",
      framework_label: "AISVS",
      source: "scan_jobs",
      scan_id: null,
      measured_at: null,
      representation: "benchmark",
      score: 0,
      summary: {
        pass: 0,
        fail: 0,
        error: 0,
        not_applicable: 0,
        total: 0,
        score: 0,
      },
      benchmark: {
        benchmark: "aisvs",
        benchmark_version: "1.0",
        passed: 0,
        failed: 0,
        total: 0,
        pass_rate: 0,
        checks: [],
        metadata: {},
      },
    },
    ...overrides,
  };
}

describe("complianceFrameworkSummaries", () => {
  it("builds framework cards with MCP disabled when context is missing", () => {
    const frameworks = complianceFrameworkSummaries(
      sampleCompliance({ has_mcp_context: false }),
      false,
    );
    const mcp = frameworks.find((framework) => framework.id === "owasp-mcp");
    expect(mcp?.disabled).toBe(true);
    expect(mcp?.disabledReason).toMatch(/MCP/i);
  });

  it("uses the serialized framework kind and never scores OWASP risk catalogs", () => {
    const frameworks = complianceFrameworkSummaries(sampleCompliance(), true);
    const llm = frameworks.find((framework) => framework.id === "owasp-llm");
    expect(llm?.kind).toBe("applicability");
    expect(llm?.pass).toBe(0);
    expect(llm?.fail).toBe(0);
    expect(llm?.applicable).toBe(3);
    expect(compliancePassRate(llm!)).toBe(30);
  });
});

describe("controlMatchesQuery", () => {
  it("matches control code, packages, and agents", () => {
    const control = sampleControl({
      code: "LLM05",
      affected_packages: ["langchain"],
      affected_agents: ["cursor"],
    });
    expect(controlMatchesQuery(control, "llm05")).toBe(true);
    expect(controlMatchesQuery(control, "langchain")).toBe(true);
    expect(controlMatchesQuery(control, "cursor")).toBe(true);
    expect(controlMatchesQuery(control, "missing")).toBe(false);
  });
});
