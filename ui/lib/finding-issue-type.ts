import type { EnrichedVuln } from "@/lib/findings-view";

export type IssueTypeFilter = "all" | "vulnerability" | "misconfiguration" | "secret" | "identity";

export type IssueType = Exclude<IssueTypeFilter, "all">;

const MISCONFIG_PATTERN =
  /\bcis(?:_| fail| fail)?\b|misconfig|cloud_cis|terraform|iac\b|sast\b|policy|compliance|container|sbom|skill_risk|prompt_security|injection|tool_drift|mcp_blocklist|license\b/i;
const SECRET_PATTERN =
  /\bsecret(?:_scan)?\b|credential_exposure|hardcoded|api[_-]?key|private[_-]?key|token leak|pii\b/i;
const IDENTITY_PATTERN =
  /\bidentity\b|\biam\b|nhi\b|service[_-]?account|jit[_-]?grant|non[_-]?human|role[_-]?binding/i;

function signalBlob(vuln: EnrichedVuln): string {
  return [
    vuln.id,
    vuln.impact_category ?? "",
    vuln.finding_type ?? "",
    ...vuln.sources,
    ...vuln.advisory_sources,
    ...(vuln.framework_tags ?? []),
  ]
    .join(" ")
    .toLowerCase();
}

export function classifyFindingIssueType(vuln: EnrichedVuln): IssueType {
  const blob = signalBlob(vuln);

  if (SECRET_PATTERN.test(blob) || vuln.exposed_credentials.length > 0) {
    return "secret";
  }
  if (IDENTITY_PATTERN.test(blob)) {
    return "identity";
  }
  if (MISCONFIG_PATTERN.test(blob)) {
    return "misconfiguration";
  }
  if (/^cve-|^ghsa-|^malicious_package/i.test(vuln.id.trim())) {
    return "vulnerability";
  }
  return "vulnerability";
}

export function matchesIssueTypeFilter(vuln: EnrichedVuln, filter: IssueTypeFilter): boolean {
  if (filter === "all") return true;
  return classifyFindingIssueType(vuln) === filter;
}

export const ISSUE_TYPE_FILTERS: { key: IssueTypeFilter; label: string; hint: string }[] = [
  { key: "all", label: "All types", hint: "Every issue class" },
  { key: "vulnerability", label: "Vulnerabilities", hint: "CVE / package risk" },
  { key: "misconfiguration", label: "Misconfigurations", hint: "Cloud, IaC, policy" },
  { key: "secret", label: "Secrets", hint: "Exposed credentials" },
  { key: "identity", label: "Identity", hint: "IAM / NHI exposure" },
];
