import type { EnrichedVuln } from "@/lib/findings-view";

export type IssueTypeFilter = "all" | "vulnerability" | "misconfiguration" | "secret" | "pii" | "identity" | "unclassified";

export type IssueType = Exclude<IssueTypeFilter, "all">;

export type SeverityBand = "critical" | "high" | "medium" | "low";

export type SeverityBucket = Record<SeverityBand, number>;

export type IssueSeverityMatrix = Record<IssueType, SeverityBucket> & {
  totals: SeverityBucket;
  byType: Record<IssueType, number>;
  openTotal: number;
};

const VULNERABILITY_TYPES = new Set(["CVE", "MALICIOUS_PACKAGE"]);
const MISCONFIGURATION_TYPES = new Set([
  "CIS_FAIL",
  "CIS_ERROR",
  "CLOUD_BEST_PRACTICE_FAIL",
  "CLOUD_BEST_PRACTICE_ERROR",
]);
const SECRET_TYPES = new Set(["CREDENTIAL_EXPOSURE"]);
// Personal data shares the secret scanner as a source, so it must be decided
// by finding type before the source check below.
const PII_TYPES = new Set(["PII_EXPOSURE"]);
const IDENTITY_TYPES = new Set(["CIEM_OVER_PRIVILEGE"]);

export type IssueTypeSignals = {
  id: string;
  impact_category?: string | undefined;
  finding_type?: string | undefined;
  finding_class?: IssueType | undefined;
  sources?: string[] | undefined;
  advisory_sources?: string[] | undefined;
  framework_tags?: string[] | undefined;
  exposed_credentials?: string[] | undefined;
};

/** Classify any finding-like signal into vuln / misconfig / secret / pii / identity. */
export function classifyIssueTypeFromSignals(signals: IssueTypeSignals): IssueType | null {
  if (signals.finding_class) return signals.finding_class;
  const findingType = (signals.finding_type ?? "").trim().toUpperCase();
  const sources = [...(signals.sources ?? []), ...(signals.advisory_sources ?? [])]
    .map((source) => source.trim().toUpperCase());
  const creds = signals.exposed_credentials ?? [];

  if (PII_TYPES.has(findingType)) {
    return "pii";
  }
  if (SECRET_TYPES.has(findingType) || sources.includes("SECRET_SCAN") || creds.length > 0) {
    return "secret";
  }
  if (IDENTITY_TYPES.has(findingType)) {
    return "identity";
  }
  if (
    MISCONFIGURATION_TYPES.has(findingType) ||
    sources.includes("CLOUD_CIS") ||
    sources.includes("CLOUD_SECURITY")
  ) {
    return "misconfiguration";
  }
  if (VULNERABILITY_TYPES.has(findingType) || /^(cve-|ghsa-)/i.test(signals.id.trim())) {
    return "vulnerability";
  }
  return "unclassified";
}

export function classifyFindingIssueType(vuln: EnrichedVuln): IssueType | null {
  return classifyIssueTypeFromSignals({
    id: vuln.id,
    impact_category: vuln.impact_category,
    finding_type: vuln.finding_type,
    finding_class: vuln.finding_class,
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
  { key: "pii", label: "Personal data", hint: "Personal data in source" },
  { key: "identity", label: "Identity", hint: "IAM / NHI exposure" },
  { key: "unclassified", label: "Unclassified", hint: "Needs taxonomy review" },
];

export const ISSUE_TYPE_SHORT: Record<IssueType, string> = {
  vulnerability: "CVE",
  misconfiguration: "Misconfig",
  secret: "Secret",
  pii: "Personal",
  identity: "Identity",
  unclassified: "Other",
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
    pii: emptySeverityBucket(),
    identity: emptySeverityBucket(),
    unclassified: emptySeverityBucket(),
    totals: emptySeverityBucket(),
    byType: { vulnerability: 0, misconfiguration: 0, secret: 0, pii: 0, identity: 0, unclassified: 0 },
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
    if (!issue) continue;
    matrix[issue][band] += 1;
    matrix.totals[band] += 1;
    matrix.byType[issue] += 1;
    matrix.openTotal += 1;
  }
  return matrix;
}

export function findingsHref(opts: {
  scope?: "latest" | "all";
  severity?: SeverityBand | "all";
  issue?: IssueTypeFilter;
  kev?: boolean;
}): string {
  const params = new URLSearchParams();
  if (opts.scope === "all") params.set("scope", "all");
  if (opts.severity && opts.severity !== "all") params.set("severity", opts.severity);
  if (opts.issue && opts.issue !== "all") params.set("issue", opts.issue);
  if (opts.kev) params.set("kev", "1");
  const qs = params.toString();
  return qs ? `/findings?${qs}` : "/findings";
}
