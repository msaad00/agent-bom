import type { Vulnerability } from "@/lib/api";

export interface EnrichedVuln extends Vulnerability {
  /**
   * Unique per-finding identifier (UUID). Distinct from `id`, which carries the
   * vulnerability label (CVE/GHSA) shown to users. The same CVE can affect many
   * assets, so `id` is NOT unique across rows — use `finding_id` for React keys
   * and per-row selection. Absent for legacy scan/graph paths that already
   * merge one row per CVE.
   */
  finding_id?: string | undefined;
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
  effective_reach_score?: number | undefined;
  effective_reach_band?: string | undefined;
  framework_tags?: string[] | undefined;
  finding_type?: string | undefined;
  phantom_tools?: string[] | undefined;
  runtime_evidence?: {
    state?: "static" | "observed" | "blocked" | "replay_only" | string;
    blocked_count?: number;
    observed_count?: number;
  } | undefined;
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
  return "bg-[var(--surface)] border-[var(--border-subtle)] text-[var(--text-tertiary)]";
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

/**
 * Stable, unique React key / selection identity for a findings row. Prefers the
 * per-finding UUID (`finding_id`) so the same CVE across multiple assets renders
 * as distinct rows; falls back to `id` for legacy paths that merge per CVE.
 */
export function vulnRowKey(vuln: EnrichedVuln): string {
  return vuln.finding_id ?? vuln.id;
}

/**
 * Placeholder package name used when a finding has no real package (CIS /
 * misconfiguration rows carry the asset itself). Treated as "empty" so the
 * Packages column can auto-hide when every row is just this stand-in.
 */
const PLACEHOLDER_PACKAGE = "asset";

/**
 * Secondary (grey) line for a findings row. Findings frequently set the summary
 * to the same string as the title (`id`) — for CIS/misconfig rows the title and
 * summary are identical, so the row printed the label twice. Return the summary
 * only when it carries information the title doesn't; if it's the same string or
 * a truncation of the title (or vice versa), return null so the echo is dropped.
 */
export function findingSecondaryText(vuln: EnrichedVuln): string | null {
  const secondary = (vuln.summary ?? vuln.description ?? "").trim();
  if (!secondary) return null;
  const primary = (vuln.id ?? "").trim();
  if (!primary) return secondary;
  const p = primary.toLowerCase();
  const s = secondary.toLowerCase();
  if (p === s) return null;
  // One is a truncated prefix of the other — still the same text, drop it.
  if (p.startsWith(s) || s.startsWith(p)) return null;
  return secondary;
}

export interface FindingColumnVisibility {
  cvss: boolean;
  epss: boolean;
  packages: boolean;
  agents: boolean;
  fix: boolean;
}

/**
 * Auto-hide columns that are entirely empty/N/A across the current (filtered)
 * result set. CIS/misconfiguration findings leave CVSS, EPSS and Fix as "N/A"
 * and only carry the placeholder "asset" package, so those columns are pure
 * noise for posture-only scans. A column stays visible when at least one row
 * carries a real value. Falls back to all-visible for an empty set so headers
 * don't flicker between renders.
 */
export function computeFindingColumns(rows: EnrichedVuln[]): FindingColumnVisibility {
  if (rows.length === 0) {
    return { cvss: true, epss: true, packages: true, agents: true, fix: true };
  }
  const columns: FindingColumnVisibility = {
    cvss: false,
    epss: false,
    packages: false,
    agents: false,
    fix: false,
  };
  for (const row of rows) {
    if (!columns.cvss && typeof row.cvss_score === "number" && Number.isFinite(row.cvss_score)) {
      columns.cvss = true;
    }
    if (!columns.epss && typeof row.epss_score === "number" && Number.isFinite(row.epss_score)) {
      columns.epss = true;
    }
    if (!columns.packages && row.packages.some((p) => p.trim() && p.trim().toLowerCase() !== PLACEHOLDER_PACKAGE)) {
      columns.packages = true;
    }
    if (!columns.agents && row.agents.some((a) => a.trim())) {
      columns.agents = true;
    }
    if (!columns.fix && Boolean(row.fixed_version?.trim())) {
      columns.fix = true;
    }
    if (columns.cvss && columns.epss && columns.packages && columns.agents && columns.fix) {
      break;
    }
  }
  return columns;
}
