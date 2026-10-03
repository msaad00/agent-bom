import type { AssetRow } from "@/lib/inventory";

/** Inspect recorded findings for an exact component and retained snapshot. */
export function findingsHref(row: AssetRow, scanId?: string): string {
  const params = new URLSearchParams();
  params.set("asset", row.id);
  if (scanId) params.set("scan", scanId);
  return `/findings?${params.toString()}`;
}

/**
 * Deep link into the Security Graph focused on this asset. The graph view reads
 * `package` / `agent` params; other kinds open the graph unfocused so the user
 * can pivot from there.
 */
export function securityGraphHref(row: AssetRow, scanId?: string): string {
  const params = new URLSearchParams({ lens: "estate", node: row.id });
  if (scanId) params.set("scan", scanId);
  return `/security-graph?${params.toString()}`;
}

/** Deep link into the lineage graph (node-centric correlation). */
export function lineageHref(row: AssetRow, scanId?: string): string {
  const params = new URLSearchParams({ investigate: "1", root: row.id, q: row.label });
  if (scanId) params.set("scan", scanId);
  return `/graph?${params.toString()}`;
}

/** Preserve exact scope even when a component has no control tags. */
export function complianceHref(row: AssetRow, scanId?: string): string {
  const params = new URLSearchParams({ asset: row.id });
  if (scanId) params.set("scan", scanId);
  return `/compliance?${params.toString()}`;
}
