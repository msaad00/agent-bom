import type { AssetRow } from "@/lib/inventory";

/** Deep link into the Findings queue filtered to this asset. */
export function findingsHref(row: AssetRow): string {
  return `/findings?q=${encodeURIComponent(row.label)}`;
}

/**
 * Deep link into the Security Graph focused on this asset. The graph view reads
 * `package` / `agent` params; other kinds open the graph unfocused so the user
 * can pivot from there.
 */
export function securityGraphHref(row: AssetRow): string {
  if (row.kind === "packages") return `/security-graph?package=${encodeURIComponent(row.label)}`;
  if (row.kind === "agents") return `/security-graph?agent=${encodeURIComponent(row.label)}`;
  return "/security-graph";
}

/** Deep link into the lineage graph (node-centric correlation). */
export function lineageHref(row: AssetRow): string {
  return `/graph?focus=${encodeURIComponent(row.id)}`;
}

/** Compliance link when the asset carries framework/control tags. */
export function complianceHref(row: AssetRow): string | null {
  if (row.complianceTags.length === 0) return null;
  return `/compliance?q=${encodeURIComponent(row.complianceTags[0]!)}`;
}
