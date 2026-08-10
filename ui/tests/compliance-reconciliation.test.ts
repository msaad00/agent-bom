/**
 * The compliance page's tiles must reconcile with its own headline.
 *
 * Measured against the demo estate on 2026-08-09, the page showed:
 *
 *   headline   "150 of 195 controls evaluated"
 *   tiles      Passing 6 · Attention 0 · Failing 95   (= 101)
 *   ATLAS row  NaN
 *
 * Three separate causes, one symptom — numbers on one screen that cannot all
 * be true:
 *
 * 1. **ATLAS.** #4709 reclassified MITRE ATLAS as an applicability overlay and
 *    the API stopped emitting `atlas_pass` / `atlas_warn` / `atlas_fail`. The
 *    row still read those three fields, so it rendered `undefined` and poisoned
 *    the tile sums with `NaN`. The UI suite did not catch it because its
 *    fixture hand-writes `atlas_pass: 25`, a payload the server cannot produce.
 *
 * 2. **Frameworks scored but never rendered.** `nist_800_53` (20 evaluated),
 *    `pci_dss` (9) and `fedramp` (0) come back on every response, count toward
 *    `evaluated_controls`, and appeared in no row — 29 evaluated controls the
 *    headline counted and the page did not show. Same for the CIS Foundations
 *    and AISVS benchmark evidence (20 more).
 *
 * 3. **The catalog line.** `nist_800_53_catalog` (16 evaluated: 3 pass, 13
 *    fail) is scored INDEPENDENTLY over the vendored catalog from the SAME
 *    CVE/CIS evidence the framework rows already count. Adding it gives 166,
 *    which is where the "tiles say 166, headline says 150" report came from.
 *    It must stay out of the aggregate — folding it in double-counts evidence
 *    into a leadership-facing score — so the relationship is pinned here
 *    rather than left as a delta someone will eventually "fix".
 */

import { describe, expect, it } from "vitest";

import type { ComplianceResponse } from "@/lib/api";
import {
  complianceFrameworkSummaries,
  complianceScoredTotals,
} from "@/lib/compliance-frameworks";

/** The demo estate's actual /v1/compliance response, reduced to what the tiles read. */
function demoEstateCompliance(): ComplianceResponse {
  const controls = (count: number, status: string) =>
    Array.from({ length: count }, (_unused, index) => ({
      code: `C-${index}`,
      name: `Control ${index}`,
      findings: 0,
      status,
      severity_breakdown: {},
      affected_packages: [],
      affected_agents: [],
    }));
  return {
    overall_score: 13.3,
    overall_status: "fail",
    evaluated_controls: 150,
    total_controls: 195,
    coverage_pct: 76.9,
    scan_count: 1,
    latest_scan: "2026-08-09T00:00:00Z",
    has_mcp_context: true,
    summary: {
      owasp_pass: 0, owasp_warn: 0, owasp_fail: 7,
      owasp_mcp_pass: 0, owasp_mcp_warn: 0, owasp_mcp_fail: 8,
      // No atlas_pass / atlas_warn / atlas_fail: the server stopped sending them.
      atlas_applicable: 40, atlas_not_applicable: 25,
      attack_applicable: 27, attack_not_applicable: 664,
      nist_pass: 0, nist_warn: 0, nist_fail: 12,
      owasp_agentic_pass: 0, owasp_agentic_warn: 0, owasp_agentic_fail: 9,
      eu_ai_act_pass: 0, eu_ai_act_warn: 0, eu_ai_act_fail: 6,
      nist_csf_pass: 3, nist_csf_warn: 0, nist_csf_fail: 11,
      iso_27001_pass: 0, iso_27001_warn: 0, iso_27001_fail: 9,
      soc2_pass: 0, soc2_warn: 0, soc2_fail: 9,
      cis_pass: 3, cis_warn: 0, cis_fail: 7,
      cmmc_pass: 0, cmmc_warn: 0, cmmc_fail: 17,
      nist_800_53_pass: 2, nist_800_53_warn: 0, nist_800_53_fail: 18,
      fedramp_pass: 0, fedramp_warn: 0, fedramp_fail: 0,
      pci_dss_pass: 0, pci_dss_warn: 0, pci_dss_fail: 9,
      cis_foundations_pass: 12, cis_foundations_fail: 8, cis_foundations_error: 0,
      cis_foundations_not_applicable: 0, cis_foundations_evaluated: 20,
      aisvs_pass: 0, aisvs_fail: 0, aisvs_error: 0, aisvs_not_applicable: 0,
      nist_800_53_catalog_pass: 3,
      nist_800_53_catalog_fail: 13,
      nist_800_53_catalog_warning: 0,
      nist_800_53_catalog_error: 0,
      nist_800_53_catalog_evaluated: 16,
      nist_800_53_catalog_not_evaluated: 998,
    },
    owasp_llm_top10: controls(10, "fail"),
    owasp_mcp_top10: controls(10, "fail"),
    mitre_atlas: [...controls(40, "applicable"), ...controls(25, "not_applicable")],
    nist_ai_rmf: controls(14, "fail"),
    owasp_agentic_top10: controls(10, "fail"),
    eu_ai_act: controls(6, "fail"),
    nist_csf: controls(14, "fail"),
    iso_27001: controls(9, "fail"),
    soc2: controls(9, "fail"),
    cis_controls: controls(10, "fail"),
    cmmc: controls(17, "fail"),
    nist_800_53: controls(29, "fail"),
    fedramp: controls(25, "not_evaluated"),
    pci_dss: controls(12, "fail"),
  } as unknown as ComplianceResponse;
}

describe("compliance tiles reconcile with the headline", () => {
  const data = demoEstateCompliance();
  const rows = complianceFrameworkSummaries(data, true);

  it("never renders a framework count the API does not send", () => {
    for (const row of rows) {
      expect(Number.isFinite(row.pass), `${row.id}.pass`).toBe(true);
      expect(Number.isFinite(row.warn), `${row.id}.warn`).toBe(true);
      expect(Number.isFinite(row.fail), `${row.id}.fail`).toBe(true);
    }
  });

  it("models ATLAS as an applicability overlay, not as passing and failing controls", () => {
    const atlas = rows.find((row) => row.id === "atlas");
    expect(atlas).toBeDefined();
    expect(atlas!.kind).toBe("applicability");
    expect(atlas!.applicable).toBe(40);
    // An overlay says which techniques are in play, never that 25 of them passed.
    expect(atlas!.pass).toBe(0);
    expect(atlas!.fail).toBe(0);
  });

  it("renders every framework the headline counted", () => {
    for (const id of ["nist-800-53", "pci-dss", "fedramp", "cis-foundations"]) {
      expect(rows.map((row) => row.id)).toContain(id);
    }
  });

  it("sums to exactly the evaluated_controls the headline reports", () => {
    const totals = complianceScoredTotals(rows);
    expect(totals.pass + totals.warn + totals.fail).toBe(data.evaluated_controls);
  });

  it("leaves the independently scored catalog out of the aggregate", () => {
    // 150 + the catalog's 16 is the 166 the tiles used to imply. The catalog
    // rescores the same CVE and CIS evidence the rows above already counted, so
    // adding it double-counts; it is an alternate VIEW of the estate, not more
    // of it.
    const totals = complianceScoredTotals(rows);
    const catalogEvaluated = data.summary.nist_800_53_catalog_evaluated ?? 0;
    expect(catalogEvaluated).toBeGreaterThan(0);
    expect(totals.pass + totals.warn + totals.fail + catalogEvaluated).toBe(166);
    expect(rows.map((row) => row.id)).not.toContain("nist-800-53-catalog");
  });
});
