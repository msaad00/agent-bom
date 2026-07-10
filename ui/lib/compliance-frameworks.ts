import type { ComplianceControl, ComplianceResponse } from "@/lib/api";

export interface ComplianceFrameworkSummary {
  id: string;
  label: string;
  shortLabel: string;
  pass: number;
  warn: number;
  fail: number;
  total: number;
  disabled?: boolean;
  disabledReason?: string;
}

export function complianceFrameworkSummaries(
  data: ComplianceResponse,
  hasMcp: boolean,
): ComplianceFrameworkSummary[] {
  const s = data.summary;
  return [
    { id: "owasp-llm", label: "OWASP LLM Top 10", shortLabel: "LLM", pass: s.owasp_pass, warn: s.owasp_warn, fail: s.owasp_fail, total: 10 },
    {
      id: "owasp-mcp",
      label: "OWASP MCP Top 10",
      shortLabel: "MCP",
      pass: s.owasp_mcp_pass,
      warn: s.owasp_mcp_warn,
      fail: s.owasp_mcp_fail,
      total: 10,
      disabled: !hasMcp,
      disabledReason: "Requires MCP scan context",
    },
    { id: "atlas", label: "MITRE ATLAS", shortLabel: "ATLAS", pass: s.atlas_pass, warn: s.atlas_warn, fail: s.atlas_fail, total: data.mitre_atlas.length },
    { id: "nist-ai-rmf", label: "NIST AI RMF", shortLabel: "AI RMF", pass: s.nist_pass, warn: s.nist_warn, fail: s.nist_fail, total: data.nist_ai_rmf.length },
    {
      id: "owasp-agentic",
      label: "OWASP Agentic Top 10",
      shortLabel: "Agentic",
      pass: s.owasp_agentic_pass,
      warn: s.owasp_agentic_warn,
      fail: s.owasp_agentic_fail,
      total: 10,
      disabled: !hasMcp,
      disabledReason: "Requires agent + MCP context",
    },
    { id: "eu-ai-act", label: "EU AI Act", shortLabel: "EU AI", pass: s.eu_ai_act_pass, warn: s.eu_ai_act_warn, fail: s.eu_ai_act_fail, total: data.eu_ai_act.length },
    { id: "nist-csf", label: "NIST CSF 2.0", shortLabel: "CSF", pass: s.nist_csf_pass, warn: s.nist_csf_warn, fail: s.nist_csf_fail, total: data.nist_csf.length },
    { id: "iso27001", label: "ISO 27001", shortLabel: "ISO", pass: s.iso_27001_pass, warn: s.iso_27001_warn, fail: s.iso_27001_fail, total: data.iso_27001.length },
    { id: "soc2", label: "SOC 2", shortLabel: "SOC 2", pass: s.soc2_pass, warn: s.soc2_warn, fail: s.soc2_fail, total: data.soc2.length },
    { id: "cis", label: "CIS Controls v8", shortLabel: "CIS", pass: s.cis_pass, warn: s.cis_warn, fail: s.cis_fail, total: data.cis_controls.length },
    { id: "cmmc", label: "CMMC 2.0", shortLabel: "CMMC", pass: s.cmmc_pass, warn: s.cmmc_warn, fail: s.cmmc_fail, total: data.cmmc.length },
  ];
}

export function compliancePassRate(summary: ComplianceFrameworkSummary): number {
  if (summary.total <= 0) return 0;
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
