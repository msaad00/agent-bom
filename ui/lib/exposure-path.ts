export type ExposureSeverity = "critical" | "high" | "medium" | "low" | "none" | string;

export type ExposureEntityRole =
  | "agent"
  | "server"
  | "package"
  | "finding"
  | "credential"
  | "tool"
  | "environment"
  | "cluster"
  | "unknown";

export interface ExposureEntityRef {
  id: string;
  label: string;
  role: ExposureEntityRole;
  severity?: ExposureSeverity | undefined;
  riskScore?: number | undefined;
}

export interface ExposureRelationshipRef {
  id: string;
  source: string;
  target: string;
  relationship: string;
  direction?: "directed" | "bidirectional" | undefined;
  traversable?: boolean | undefined;
  confidence?: string | undefined;
  evidenceCount?: number | undefined;
}

export interface ExposureDependencyContext {
  packageName?: string | undefined;
  packageVersion?: string | undefined;
  ecosystem?: string | undefined;
  serverName?: string | undefined;
}

export interface ExposureFixTarget {
  label: string;
  version?: string | undefined;
  href?: string | undefined;
}

export interface ExposureEvidenceSummary {
  cvssScore?: number | undefined;
  epssScore?: number | undefined;
  isKev?: boolean | undefined;
  impactCategory?: string | undefined;
  attackVectorSummary?: string | undefined;
  source?: string | undefined;
}

export interface ExposurePath {
  id: string;
  rank?: number | undefined;
  label: string;
  summary?: string | undefined;
  riskScore: number;
  severity: ExposureSeverity;
  source: ExposureEntityRef;
  target: ExposureEntityRef;
  hops: ExposureEntityRef[];
  relationships: ExposureRelationshipRef[];
  nodeIds: string[];
  edgeIds: string[];
  findings: string[];
  affectedAgents: string[];
  affectedServers: string[];
  reachableTools: string[];
  exposedCredentials: string[];
  dependencyContext?: ExposureDependencyContext | undefined;
  fix?: ExposureFixTarget | undefined;
  evidence?: ExposureEvidenceSummary | undefined;
  provenance?: {
    source: string;
    scanId?: string | undefined;
  } | undefined;
  timestamps?: {
    firstSeen?: string | undefined;
    lastSeen?: string | undefined;
  } | undefined;
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
};

export function exposureSeverityRank(severity: ExposureSeverity | undefined): number {
  return SEVERITY_RANK[String(severity ?? "none").toLowerCase()] ?? 0;
}

export function normalizeExposureSeverity(severity: ExposureSeverity | undefined): ExposureSeverity {
  const normalized = String(severity ?? "none").toLowerCase();
  return normalized in SEVERITY_RANK ? normalized : severity ?? "none";
}

export function uniqueExposureValues(values: (string | undefined | null)[]): string[] {
  return [...new Set(values.map((value) => value?.trim()).filter((value): value is string => Boolean(value)))];
}

export function exposurePathKey(path: ExposurePath): string {
  return path.id || `${path.source.id}::${path.target.id}::${path.nodeIds.join("->")}`;
}

export function compareExposurePaths(left: ExposurePath, right: ExposurePath): number {
  const riskDiff = right.riskScore - left.riskScore;
  if (riskDiff !== 0) return riskDiff;
  const severityDiff = exposureSeverityRank(right.severity) - exposureSeverityRank(left.severity);
  if (severityDiff !== 0) return severityDiff;
  const kevDiff = Number(Boolean(right.evidence?.isKev)) - Number(Boolean(left.evidence?.isKev));
  if (kevDiff !== 0) return kevDiff;
  const blastDiff = right.affectedAgents.length - left.affectedAgents.length;
  if (blastDiff !== 0) return blastDiff;
  return pathDisplayTitle(left).localeCompare(pathDisplayTitle(right));
}

export function highestExposureSeverity(paths: ExposurePath[]): ExposureSeverity {
  return paths.reduce<ExposureSeverity>(
    (highest, path) => (exposureSeverityRank(path.severity) > exposureSeverityRank(highest) ? path.severity : highest),
    "none",
  );
}

export function pathDisplayTitle(path: ExposurePath): string {
  const finding = path.findings[0] || path.target.label;
  const dependency = path.dependencyContext?.packageName
    ? `${path.dependencyContext.packageName}${path.dependencyContext.packageVersion ? `@${path.dependencyContext.packageVersion}` : ""}`
    : "";
  const agent = path.affectedAgents[0] || path.source.label;
  return [agent, dependency, finding].filter(Boolean).join(" -> ") || path.label;
}

export function pathFixLabel(path: ExposurePath): string | undefined {
  if (path.fix?.version) return path.fix.version;
  if (path.fix?.label) return path.fix.label;
  return undefined;
}

export function pathSequenceLabels(path: ExposurePath): string[] {
  return path.hops.map((hop) => hop.label);
}
