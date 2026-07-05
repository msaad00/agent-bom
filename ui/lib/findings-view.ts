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
  lifecycle_status?: string | undefined;
  first_seen?: string | undefined;
  last_seen?: string | undefined;
  resolved_at?: string | undefined;
  reopened_at?: string | undefined;
  scan_count?: number | undefined;
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
export type SortKey = "severity" | "cvss" | "epss" | "effective_reach" | "id";
export type GroupKey = "none" | "package" | "agent" | "severity";
export type ScanScope = "latest" | "all";

/** Map dashboard sort keys to the server-side ``GET /v1/findings`` contract. */
export function serverFindingsSort(sortKey: SortKey): string {
  if (sortKey === "cvss") return "cvss";
  if (sortKey === "severity") return "severity";
  return "effective_reach";
}

/** Human label for totals that may be cached or lower-bounded. */
export function formatFindingsTotal(total: number, approximate?: boolean): string {
  if (!approximate) return String(total);
  return `~${total}`;
}

export function formatFindingTimestamp(value: string | undefined | null): string {
  if (!value || !value.trim()) return "—";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return value;
  return new Date(parsed).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function findingStatusLabel(status: string | undefined): string {
  const normalized = (status ?? "").trim().toLowerCase();
  if (normalized === "open" || normalized === "resolved" || normalized === "reopened") {
    return normalized;
  }
  return normalized || "—";
}

export function findingStatusClass(status: string | undefined): string {
  const normalized = (status ?? "").trim().toLowerCase();
  if (normalized === "open") {
    return "bg-amber-950 border-amber-800 text-amber-300";
  }
  if (normalized === "resolved") {
    return "bg-emerald-950 border-emerald-800 text-emerald-300";
  }
  if (normalized === "reopened") {
    return "bg-orange-950 border-orange-800 text-orange-300";
  }
  return "bg-zinc-900 border-zinc-700 text-zinc-500";
}

export function hasLifecycleMetadata(rows: EnrichedVuln[]): boolean {
  return rows.some(
    (row) =>
      Boolean(row.lifecycle_status?.trim()) ||
      Boolean(row.first_seen?.trim()) ||
      Boolean(row.last_seen?.trim()) ||
      Boolean(row.resolved_at?.trim()),
  );
}

export function uniqueStrings(items: Array<string | null | undefined>) {
  return [...new Set(items.filter((item): item is string => Boolean(item && item.trim())).map((item) => item.trim()))];
}
