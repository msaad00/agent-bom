import type { EnrichedVuln } from "@/lib/findings-view";

export type IssueTypeFilter = "all" | "vulnerability" | "misconfiguration" | "secret" | "identity";

export type IssueType = Exclude<IssueTypeFilter, "all">;

export type SeverityBand = "critical" | "high" | "medium" | "low";

export type SeverityBucket = Record<SeverityBand, number>;

export type IssueSeverityMatrix = Record<IssueType, SeverityBucket> & {
  totals: SeverityBucket;
  byType: Record<IssueType, number>;
  openTotal: number;
};

const MISCONFIG_PATTERN =
  /\bcis(?:_| fail| fail)?\b|misconfig|cloud_cis|terraform|iac\b|sast\b|policy|compliance|container|sbom|skill_risk|prompt_security|injection|tool_drift|mcp_blocklist|license\b/i;
const SECRET_PATTERN =
  /\bsecret(?:_scan)?\b|credential_exposure|hardcoded|api[_-]?key|private[_-]?key|token leak|pii\b/i;
const IDENTITY_PATTERN =
  /\bidentity\b|\biam\b|nhi\b|service[_-]?account|jit[_-]?grant|non[_-]?human|role[_-]?binding/i;

export type IssueTypeSignals = {
  id: string;
  impact_category?: string | undefined;
  finding_type?: string | undefined;
  sources?: string[] | undefined;
  advisory_sources?: string[] | undefined;
  framework_tags?: string[] | undefined;
  exposed_credentials?: string[] | undefined;
};

function signalBlob(signals: IssueTypeSignals): string {
  return [
    signals.id,
    signals.impact_category ?? "",
    signals.finding_type ?? "",
    ...(signals.sources ?? []),
    ...(signals.advisory_sources ?? []),
    ...(signals.framework_tags ?? []),
  ]
    .join(" ")
    .toLowerCase();
}

/** Classify any finding-like signal into vuln / misconfig / secret / identity. */
export function classifyIssueTypeFromSignals(signals: IssueTypeSignals): IssueType {
  const blob = signalBlob(signals);
  const creds = signals.exposed_credentials ?? [];

  if (SECRET_PATTERN.test(blob) || creds.length > 0) {
    return "secret";
  }
  if (IDENTITY_PATTERN.test(blob)) {
    return "identity";
  }
  if (MISCONFIG_PATTERN.test(blob)) {
    return "misconfiguration";
  }
  if (/^cve-|^ghsa-|^malicious_package/i.test(signals.id.trim())) {
    return "vulnerability";
  }
  return "vulnerability";
}

export function classifyFindingIssueType(vuln: EnrichedVuln): IssueType {
  return classifyIssueTypeFromSignals({
    id: vuln.id,
    impact_category: vuln.impact_category,
    finding_type: vuln.finding_type,
    sources: vuln.sources,
    advisory_sources: vuln.advisory_sources,
    framework_tags: vuln.framework_tags,
    exposed_credentials: vuln.exposed_credentials,
  });
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

export const ISSUE_TYPE_SHORT: Record<IssueType, string> = {
  vulnerability: "CVE",
  misconfiguration: "Misconfig",
  secret: "Secret",
  identity: "Identity",
};

export const SEVERITY_BANDS: SeverityBand[] = ["critical", "high", "medium", "low"];

export function emptySeverityBucket(): SeverityBucket {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

export function emptyIssueSeverityMatrix(): IssueSeverityMatrix {
  return {
    vulnerability: emptySeverityBucket(),
    misconfiguration: emptySeverityBucket(),
    secret: emptySeverityBucket(),
    identity: emptySeverityBucket(),
    totals: emptySeverityBucket(),
    byType: { vulnerability: 0, misconfiguration: 0, secret: 0, identity: 0 },
    openTotal: 0,
  };
}

function normalizeSeverityBand(value: string | null | undefined): SeverityBand | null {
  const s = value?.toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low") return s;
  return null;
}

/** Build severity × issue-type matrix (shared axis for CVEs, misconfigs, secrets). */
export function buildIssueSeverityMatrix(
  items: Array<{
    id: string;
    severity?: string | null | undefined;
    impact_category?: string | undefined;
    finding_type?: string | undefined;
    sources?: string[] | undefined;
    advisory_sources?: string[] | undefined;
    framework_tags?: string[] | undefined;
    exposed_credentials?: string[] | undefined;
  }>,
): IssueSeverityMatrix {
  const matrix = emptyIssueSeverityMatrix();
  for (const item of items) {
    const band = normalizeSeverityBand(item.severity);
    if (!band) continue;
    const issue = classifyIssueTypeFromSignals(item);
    matrix[issue][band] += 1;
    matrix.totals[band] += 1;
    matrix.byType[issue] += 1;
    matrix.openTotal += 1;
  }
  return matrix;
}

export function findingsHref(opts: {
  severity?: SeverityBand | "all";
  issue?: IssueTypeFilter;
  kev?: boolean;
}): string {
  const params = new URLSearchParams();
  if (opts.severity && opts.severity !== "all") params.set("severity", opts.severity);
  if (opts.issue && opts.issue !== "all") params.set("issue", opts.issue);
  if (opts.kev) params.set("kev", "1");
  const qs = params.toString();
  return qs ? `/findings?${qs}` : "/findings";
}
