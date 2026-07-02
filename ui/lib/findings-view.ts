import type { Vulnerability } from "@/lib/api";

export interface EnrichedVuln extends Vulnerability {
  packages: string[];
  agents: string[];
  sources: string[];
  affected_servers: string[];
  exposed_credentials: string[];
  reachable_tools: string[];
  references: string[];
  advisory_sources: string[];
  attack_vector_summary?: string | undefined;
  impact_category?: string | undefined;
  risk_score?: number | undefined;
  remediation_items: RemediationSummary[];
  graph_reachable?: boolean | null | undefined;
  graph_min_hop_distance?: number | null | undefined;
}

export interface RemediationSummary {
  package: string;
  ecosystem: string;
  current_version: string;
  fixed_version: string | null;
  action?: string | undefined;
  command?: string | null | undefined;
  verify_command?: string | null | undefined;
  references: string[];
  risk_narrative: string;
}

export type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";
export type SortKey = "severity" | "cvss" | "epss" | "id";
export type GroupKey = "none" | "package" | "agent" | "severity";
export type ScanScope = "latest" | "all";

export function uniqueStrings(items: Array<string | null | undefined>) {
  return [...new Set(items.filter((item): item is string => Boolean(item && item.trim())).map((item) => item.trim()))];
}
