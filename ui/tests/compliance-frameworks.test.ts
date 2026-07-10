import { describe, expect, it } from "vitest";

import type { ComplianceControl, ComplianceResponse } from "@/lib/api";
import {
  complianceFrameworkSummaries,
  compliancePassRate,
  controlMatchesQuery,
} from "@/lib/compliance-frameworks";

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
    scan_count: 1,
    latest_scan: "2026-07-09T22:45:07Z",
    has_mcp_context: true,
    summary: {
      owasp_pass: 3,
      owasp_warn: 0,
      owasp_fail: 7,
      owasp_mcp_pass: 2,
      owasp_mcp_warn: 0,
      owasp_mcp_fail: 8,
      atlas_pass: 25,
      atlas_warn: 0,
      atlas_fail: 40,
      nist_pass: 2,
      nist_warn: 0,
      nist_fail: 12,
      owasp_agentic_pass: 1,
      owasp_agentic_warn: 0,
      owasp_agentic_fail: 9,
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
    owasp_llm_top10: [],
    owasp_mcp_top10: [],
    mitre_atlas: Array.from({ length: 65 }, (_, index) =>
      sampleControl({ code: `AML.T${index}`, status: index < 25 ? "pass" : "fail" }),
    ),
    nist_ai_rmf: Array.from({ length: 14 }, () => sampleControl()),
    owasp_agentic_top10: [],
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

  it("computes pass rate from pass/total", () => {
    const frameworks = complianceFrameworkSummaries(sampleCompliance(), true);
    const llm = frameworks.find((framework) => framework.id === "owasp-llm");
    expect(llm?.pass).toBe(3);
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
