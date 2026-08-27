import type { ComplianceControl, ComplianceResponse } from "@/lib/api";

/**
 * How a framework is measured, which decides whether it can be summed.
 *
 * `scored` — controls carry pass / warn / fail, so the row contributes to the
 * page's aggregate and to `evaluated_controls`.
 *
 * `applicability` — the catalog says which adversary techniques are in play,
 * not whether the estate passed them. ATLAS and ATT&CK are technique catalogs;
 * treating a technique as "passing" because nothing matched it is the claim
 * #4709 removed from the backend. Such a row is never summed.
 */
export type ComplianceFrameworkKind = "scored" | "applicability";

export interface ComplianceFrameworkSummary {
  id: string;
  label: string;
  shortLabel: string;
  kind: ComplianceFrameworkKind;
  pass: number;
  warn: number;
  fail: number;
  total: number;
  /** Applicability rows only: techniques the estate's evidence puts in play. */
  applicable?: number;
  notApplicable?: number;
  disabled?: boolean;
  disabledReason?: string;
}

function scored(
  id: string,
  label: string,
  shortLabel: string,
  counts: { pass?: number | undefined; warn?: number | undefined; fail?: number | undefined },
  total: number,
  extra: { disabled?: boolean; disabledReason?: string } = {},
): ComplianceFrameworkSummary {
  return {
    id,
    label,
    shortLabel,
    kind: "scored",
    // Coalesced, not asserted: a field the API stops sending must degrade to a
    // zero the aggregate can carry, never to the NaN that took out every tile
    // on the page when `atlas_pass` disappeared.
    pass: counts.pass ?? 0,
    warn: counts.warn ?? 0,
    fail: counts.fail ?? 0,
    total,
    ...extra,
  };
}

function applicability(
  id: string,
  label: string,
  shortLabel: string,
  counts: { applicable?: number | undefined; notApplicable?: number | undefined },
  total: number,
  extra: { disabled?: boolean; disabledReason?: string } = {},
): ComplianceFrameworkSummary {
  return {
    id,
    label,
    shortLabel,
    kind: "applicability",
    pass: 0,
    warn: 0,
    fail: 0,
    total,
    applicable: counts.applicable ?? 0,
    notApplicable: counts.notApplicable ?? 0,
    ...extra,
  };
}

export function complianceFrameworkSummaries(
  data: ComplianceResponse,
  hasMcp: boolean,
): ComplianceFrameworkSummary[] {
  const s = data.summary;
  const overlay = (outputKey: string): boolean =>
    data.framework_kinds[outputKey] === "applicability";
  return [
    overlay("owasp_llm_top10")
      ? applicability("owasp-llm", "OWASP LLM Top 10", "LLM", { applicable: s.owasp_applicable, notApplicable: s.owasp_not_applicable }, data.owasp_llm_top10.length)
      : scored("owasp-llm", "OWASP LLM Top 10", "LLM", {}, data.owasp_llm_top10.length),
    overlay("owasp_mcp_top10")
      ? applicability("owasp-mcp", "OWASP MCP Top 10", "MCP", { applicable: s.owasp_mcp_applicable, notApplicable: s.owasp_mcp_not_applicable }, data.owasp_mcp_top10.length, {
      disabled: !hasMcp,
      disabledReason: "Requires MCP scan context",
    }) : scored("owasp-mcp", "OWASP MCP Top 10", "MCP", {}, data.owasp_mcp_top10.length),
    overlay("mitre_atlas")
      ? applicability("atlas", "MITRE ATLAS", "ATLAS", { applicable: s.atlas_applicable, notApplicable: s.atlas_not_applicable }, data.mitre_atlas.length)
      : scored("atlas", "MITRE ATLAS", "ATLAS", {}, data.mitre_atlas.length),
    scored("nist-ai-rmf", "NIST AI RMF", "AI RMF", { pass: s.nist_pass, warn: s.nist_warn, fail: s.nist_fail }, data.nist_ai_rmf.length),
    overlay("owasp_agentic_top10")
      ? applicability(
          "owasp-agentic", "OWASP Agentic Top 10", "Agentic",
          { applicable: s.owasp_agentic_applicable, notApplicable: s.owasp_agentic_not_applicable },
          data.owasp_agentic_top10.length,
          { disabled: !hasMcp, disabledReason: "Requires agent + MCP context" },
        )
      : scored("owasp-agentic", "OWASP Agentic Top 10", "Agentic", {}, data.owasp_agentic_top10.length),
    scored("eu-ai-act", "EU AI Act", "EU AI", { pass: s.eu_ai_act_pass, warn: s.eu_ai_act_warn, fail: s.eu_ai_act_fail }, data.eu_ai_act.length),
    scored("nist-csf", "NIST CSF 2.0", "CSF", { pass: s.nist_csf_pass, warn: s.nist_csf_warn, fail: s.nist_csf_fail }, data.nist_csf.length),
    scored("iso27001", "ISO 27001", "ISO", { pass: s.iso_27001_pass, warn: s.iso_27001_warn, fail: s.iso_27001_fail }, data.iso_27001.length),
    scored("soc2", "SOC 2", "SOC 2", { pass: s.soc2_pass, warn: s.soc2_warn, fail: s.soc2_fail }, data.soc2.length),
    scored("cis", "CIS Controls v8", "CIS", { pass: s.cis_pass, warn: s.cis_warn, fail: s.cis_fail }, data.cis_controls.length),
    scored("cmmc", "CMMC 2.0", "CMMC", { pass: s.cmmc_pass, warn: s.cmmc_warn, fail: s.cmmc_fail }, data.cmmc.length),
    // Scored on every response and counted by `evaluated_controls`, but shown
    // in no row until now — so the headline counted 29 controls the page did
    // not display, and its tiles could not add up to it.
    scored("nist-800-53", "NIST SP 800-53", "800-53", { pass: s.nist_800_53_pass, warn: s.nist_800_53_warn, fail: s.nist_800_53_fail }, data.nist_800_53.length),
    scored("pci-dss", "PCI DSS 4.0", "PCI", { pass: s.pci_dss_pass, warn: s.pci_dss_warn, fail: s.pci_dss_fail }, data.pci_dss.length),
    scored("fedramp", "FedRAMP Moderate", "FedRAMP", { pass: s.fedramp_pass, warn: s.fedramp_warn, fail: s.fedramp_fail }, data.fedramp.length),
    // Benchmark evidence. It reaches `evaluated_controls` through the same
    // aggregate as the framework rows, so it belongs in the same table rather
    // than only in a detail panel below it.
    scored(
      "cis-foundations",
      "CIS Foundations Benchmark",
      "CIS Bench",
      { pass: s.cis_foundations_pass, fail: (s.cis_foundations_fail ?? 0) + (s.cis_foundations_error ?? 0) },
      (s.cis_foundations_evaluated ?? 0) + (s.cis_foundations_not_applicable ?? 0),
    ),
    scored(
      "aisvs",
      "OWASP AISVS",
      "AISVS",
      { pass: s.aisvs_pass, fail: (s.aisvs_fail ?? 0) + (s.aisvs_error ?? 0) },
      (s.aisvs_pass ?? 0) + (s.aisvs_fail ?? 0) + (s.aisvs_error ?? 0) + (s.aisvs_not_applicable ?? 0),
    ),
  ];
}

/**
 * The page's aggregate, over scored rows only.
 *
 * Equal to the response's `evaluated_controls` by construction — the invariant
 * `tests/compliance-reconciliation.test.ts` pins. Two things are deliberately
 * absent:
 *
 * * applicability rows, which have nothing to sum; and
 * * `nist_800_53_catalog`, which rescores the SAME CVE and CIS evidence these
 *   rows already count, against the full vendored catalog. It is an alternate
 *   view of the estate rather than more of it, and the backend keeps it out of
 *   `overall_score` for exactly this reason. Adding its 16 evaluated controls
 *   to this total is what made the tiles read 166 against a headline of 150.
 */
export function complianceScoredTotals(
  summaries: ComplianceFrameworkSummary[],
): { pass: number; warn: number; fail: number } {
  return summaries
    .filter((summary) => summary.kind === "scored")
    .reduce(
      (totals, summary) => ({
        pass: totals.pass + summary.pass,
        warn: totals.warn + summary.warn,
        fail: totals.fail + summary.fail,
      }),
      { pass: 0, warn: 0, fail: 0 },
    );
}

export function compliancePassRate(summary: ComplianceFrameworkSummary): number {
  if (summary.total <= 0) return 0;
  if (summary.kind === "applicability") {
    return Math.round(((summary.applicable ?? 0) / summary.total) * 100);
  }
  return Math.round((summary.pass / summary.total) * 100);
}

export function controlMatchesQuery(control: ComplianceControl, query: string): boolean {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return true;
  return [control.code, control.name, ...control.affected_packages, ...control.affected_agents]
    .join(" ")
    .toLowerCase()
    .includes(normalized);
}
