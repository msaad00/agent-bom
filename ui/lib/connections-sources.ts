import type {
  CloudConnectionRecord,
  SourceKind,
  SourceRecord,
} from "@/lib/api";

// One display model over two backends: `/v1/cloud/connections`
// (CloudConnectionRecord) and `/v1/sources` (SourceRecord). The Connections hub
// renders both in a single dense table; a cloud account that is registered in
// both places is deduped so it appears once (the richer cloud-connection row
// wins). This module is pure so the merge/dedup/filter rules stay unit-tested
// independent of React.

export type SourceCategory = "cloud" | "code" | "ai" | "data" | "runtime" | "ingest";

export type UnifiedOrigin = "cloud" | "source";

export interface UnifiedSourceRow {
  /** Stable, origin-prefixed key (never collides across the two backends). */
  id: string;
  origin: UnifiedOrigin;
  name: string;
  /** Secondary identifier line (role ref for cloud, kind detail for sources). */
  detail: string;
  /** Human label for the Kind column. */
  kindLabel: string;
  category: SourceCategory;
  /** Normalized status token for the Status column. */
  status: string;
  /** Most recent scan/run timestamp, or null when never run. */
  lastScanAt: string | null;
  /** Number of recurring schedules bound to this row. */
  scheduleCount: number;
  /** Cloud provider id (for the brand mark), cloud rows only. */
  provider?: string;
  /** Back-reference to the underlying cloud connection id, cloud rows only. */
  connectionId?: string;
  /** Back-reference to the underlying source id, source rows only. */
  sourceId?: string;
}

export interface CategoryOption {
  id: SourceCategory | "all";
  label: string;
}

export const SOURCE_CATEGORY_OPTIONS: CategoryOption[] = [
  { id: "all", label: "All" },
  { id: "cloud", label: "Cloud" },
  { id: "code", label: "Code" },
  { id: "ai", label: "AI" },
  { id: "data", label: "Data" },
  { id: "runtime", label: "Runtime" },
  { id: "ingest", label: "Ingest" },
];

const SOURCE_KIND_CATEGORY: Record<SourceKind, SourceCategory> = {
  "scan.repo": "code",
  "scan.image": "code",
  "scan.iac": "code",
  "scan.cloud": "cloud",
  "scan.mcp_config": "ai",
  "connector.cloud_read_only": "cloud",
  "connector.registry": "code",
  "connector.warehouse": "data",
  "ingest.fleet_sync": "ingest",
  "ingest.trace_push": "ingest",
  "ingest.result_push": "ingest",
  "ingest.artifact_import": "ingest",
  "runtime.proxy": "runtime",
  "runtime.gateway": "runtime",
};

const SOURCE_KIND_LABEL: Record<SourceKind, string> = {
  "scan.repo": "Repo / package scan",
  "scan.image": "Container / image scan",
  "scan.iac": "IaC / cluster scan",
  "scan.cloud": "Cloud account scan",
  "scan.mcp_config": "MCP configuration scan",
  "connector.cloud_read_only": "Cloud API connector",
  "connector.registry": "Registry / package connector",
  "connector.warehouse": "Warehouse / lake connector",
  "ingest.fleet_sync": "Fleet sync",
  "ingest.trace_push": "Trace ingest",
  "ingest.result_push": "Result push",
  "ingest.artifact_import": "Artifact import",
  "runtime.proxy": "MCP proxy runtime",
  "runtime.gateway": "MCP gateway runtime",
};

export function sourceKindCategory(kind: SourceKind | string): SourceCategory {
  return SOURCE_KIND_CATEGORY[kind as SourceKind] ?? "ingest";
}

export function sourceKindLabel(kind: SourceKind | string): string {
  return SOURCE_KIND_LABEL[kind as SourceKind] ?? String(kind);
}

function normalizeName(value: string): string {
  return value.trim().toLowerCase();
}

/**
 * Merge cloud connections and registered sources into one display list.
 *
 * Cloud connections lead. A registered source that is a cloud-kind source AND
 * shares a (case-insensitive) display name with a cloud connection is treated
 * as the same underlying account and dropped, so a cloud account that was
 * registered in both surfaces appears exactly once.
 */
export function buildUnifiedRows(
  connections: CloudConnectionRecord[],
  sources: SourceRecord[],
  scheduleCounts?: Map<string, number> | Record<string, number>,
): UnifiedSourceRow[] {
  const scheduleCountFor = (sourceId: string): number => {
    if (!scheduleCounts) return 0;
    if (scheduleCounts instanceof Map) return scheduleCounts.get(sourceId) ?? 0;
    return scheduleCounts[sourceId] ?? 0;
  };

  const cloudRows: UnifiedSourceRow[] = connections.map((connection) => ({
    id: `cloud:${connection.id}`,
    origin: "cloud",
    name: connection.display_name,
    detail: connection.role_ref,
    kindLabel: "Cloud account",
    category: "cloud",
    status: connection.status,
    lastScanAt: connection.last_scan_at,
    scheduleCount: connection.scan_interval_minutes ? 1 : 0,
    provider: connection.provider,
    connectionId: connection.id,
  }));

  const cloudNames = new Set(cloudRows.map((row) => normalizeName(row.name)));

  const sourceRows: UnifiedSourceRow[] = [];
  for (const source of sources) {
    const category = sourceKindCategory(source.kind);
    // Dedup: a cloud-kind source that mirrors an already-listed cloud
    // connection is the same account registered twice — keep the cloud row.
    if (category === "cloud" && cloudNames.has(normalizeName(source.display_name))) {
      continue;
    }
    sourceRows.push({
      id: `source:${source.source_id}`,
      origin: "source",
      name: source.display_name,
      detail: sourceKindLabel(source.kind),
      kindLabel: sourceKindLabel(source.kind),
      category,
      status: source.status,
      lastScanAt: source.last_run_at,
      scheduleCount: scheduleCountFor(source.source_id),
      sourceId: source.source_id,
    });
  }

  return [...cloudRows, ...sourceRows];
}

export interface UnifiedFilter {
  category: SourceCategory | "all";
  status: string | "all";
  query: string;
}

export function filterUnifiedRows(
  rows: UnifiedSourceRow[],
  filter: UnifiedFilter,
): UnifiedSourceRow[] {
  const query = filter.query.trim().toLowerCase();
  return rows.filter((row) => {
    if (filter.category !== "all" && row.category !== filter.category) return false;
    if (filter.status !== "all" && row.status.toLowerCase() !== filter.status.toLowerCase()) {
      return false;
    }
    if (!query) return true;
    const haystack = `${row.name} ${row.detail} ${row.kindLabel}`.toLowerCase();
    return haystack.includes(query);
  });
}

export function categoryCounts(
  rows: UnifiedSourceRow[],
): Record<SourceCategory | "all", number> {
  const counts = {
    all: rows.length,
    cloud: 0,
    code: 0,
    ai: 0,
    data: 0,
    runtime: 0,
    ingest: 0,
  } as Record<SourceCategory | "all", number>;
  for (const row of rows) {
    counts[row.category] += 1;
  }
  return counts;
}

/** Distinct statuses present in the rows, sorted for a stable filter dropdown. */
export function statusOptions(rows: UnifiedSourceRow[]): string[] {
  const set = new Set<string>();
  for (const row of rows) {
    if (row.status) set.add(row.status);
  }
  return Array.from(set).sort((a, b) => a.localeCompare(b));
}
