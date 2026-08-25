import type { AssetRow } from "@/lib/inventory";

/** Deep link into the Findings queue filtered to this asset. */
export function findingsHref(row: AssetRow, scanId?: string): string {
  const params = new URLSearchParams();
  params.set("q", row.label);
  if (scanId) params.set("scan", scanId);
  return `/findings?${params.toString()}`;
}

/**
 * Deep link into the Security Graph focused on this asset. The graph view reads
 * `package` / `agent` params; other kinds open the graph unfocused so the user
 * can pivot from there.
 */
export function securityGraphHref(row: AssetRow, scanId?: string): string {
  const params = new URLSearchParams({ node: row.id });
  if (scanId) params.set("scan", scanId);
  return `/security-graph?${params.toString()}`;
}

/** Deep link into the lineage graph (node-centric correlation). */
export function lineageHref(row: AssetRow, scanId?: string): string {
  const params = new URLSearchParams({ investigate: "1", root: row.id, q: row.label });
  if (scanId) params.set("scan", scanId);
  return `/graph?${params.toString()}`;
}

/** Compliance link when the asset carries framework/control tags. */
export function complianceHref(row: AssetRow): string | null {
  if (row.complianceTags.length === 0) return null;
  return `/compliance?q=${encodeURIComponent(row.complianceTags[0]!)}`;
}
